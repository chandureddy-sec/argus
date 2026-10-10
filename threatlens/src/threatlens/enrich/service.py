"""Enrichment service: one place that decides *whether* to ask a provider,
asks it, stores the answer and turns everything into a verdict (ADR 0005).

For each enricher that handles the observable's type, in this order:

1. a fresh cached answer is used as is (``cached``) unless ``refresh``;
2. an active enricher runs only when the caller asked for active mode;
3. TLP: no third party sees AMBER/RED values; GREEN values only go to
   providers that don't disclose lookups;
4. a missing key, a disabled source, an exhausted bulk budget or provider
   quota each give ``skipped`` with a ``skipped_reason``;
5. otherwise the provider is called under a timeout; failures are reported
   (``error``) and, when an older answer exists, it is returned as ``stale``.

Nothing here raises for a provider problem: a lookup always returns, with
``partial: true`` when anything was skipped or failed.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload

from threatlens.allowlist import Allowlist
from threatlens.connectors.base import clip
from threatlens.enrich.base import REGISTRY, Enricher, EnrichError, Evidence, EvidenceKind, Outcome
from threatlens.enrich.quota import QuotaStore
from threatlens.enrich.verdict import assess
from threatlens.ioc.defang import defang
from threatlens.ioc.types import IOCType, Observable
from threatlens.kb import graph
from threatlens.logs import get_logger
from threatlens.models import TLP_LEVELS, AuditLog, Enrichment, Indicator, Sighting, Source
from threatlens.models import Observable as ObsRow
from threatlens.net.http import FetchError, SafeHttp
from threatlens.settings import Settings

log = get_logger("threatlens.enrich")

ALLOWLIST_TTL_S = 300
THIRD_PARTY_BLOCKED = frozenset({"TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"})


def utcnow() -> datetime:
    return datetime.now(UTC)


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def stricter_tlp(*levels: str | None) -> str:
    known = [lv for lv in levels if lv in TLP_LEVELS]
    return max(known, key=TLP_LEVELS.index) if known else "TLP:CLEAR"


def tlp_blocks(info_third_party: bool, info_discloses: bool, tlp: str) -> str | None:
    """Why TLP keeps this value away from the provider, or None."""
    if not info_third_party:
        return None
    if tlp in THIRD_PARTY_BLOCKED:
        return f"{tlp}: not shared with third parties"
    if tlp == "TLP:GREEN" and info_discloses:
        return "TLP:GREEN: this provider may disclose lookups to others"
    return None


@dataclass
class Budget:
    """Metered provider calls a bulk request may still spend."""

    left: int

    def spend(self, units: int) -> bool:
        if self.left < units:
            return False
        self.left -= units
        return True


def _row_out(row: Enrichment, status: str) -> dict[str, Any]:
    return {
        "status": status,
        "fetched_at": _aware(row.fetched_at),
        "expires_at": _aware(row.expires_at),
        "found": row.status == "ok",
        "summary": row.summary or {},
        "evidence": row.evidence or [],
        "query": row.query,
    }


class EnrichmentService:
    def __init__(
        self,
        sessionmaker: async_sessionmaker[AsyncSession],
        http: SafeHttp,
        quota: QuotaStore,
        settings: Settings,
        *,
        registry: dict[str, type[Enricher]] | None = None,
        now: Callable[[], datetime] = utcnow,
    ) -> None:
        self.sm = sessionmaker
        self.http = http
        self.quota = quota
        self.settings = settings
        self.registry = registry if registry is not None else REGISTRY
        self.now = now
        self._sems = {n: asyncio.Semaphore(c.info.concurrency) for n, c in self.registry.items()}
        self._source_ids: dict[str, int] = {}
        self._enabled: dict[str, bool] = {}
        self._synced = False
        self._sync_lock = asyncio.Lock()  # concurrent first lookups must not race the inserts
        self._allowlist: tuple[float, Allowlist] | None = None

    # ── setup ───────────────────────────────────────────────────────────────

    def key_for(self, name: str) -> str | None:
        attr = self.registry[name].info.key_setting
        secret = getattr(self.settings, attr, None) if attr else None
        return secret.get_secret_value() if secret is not None else None

    async def sync_sources(self) -> None:
        """Every enricher is also a ``sources`` row: its licence terms are
        listed with the feeds, and stored enrichments point at it."""
        async with self.sm() as s, s.begin():
            existing = {x.name: x for x in (await s.scalars(select(Source))).all()}
            for name, cls in self.registry.items():
                i = cls.info
                meta = {
                    "title": i.title,
                    "kind": "enricher",
                    "homepage": i.homepage,
                    "reliability": i.reliability,
                    "reliability_note": i.reliability_note,
                    "license": i.license,
                    "license_url": i.license_url,
                    "commercial_use": i.commercial_use,
                    "redistribution": i.redistribution,
                    "attribution": i.attribution,
                    "upstream": i.upstream,
                    "tlp_default": "TLP:CLEAR",
                    "requires_key": i.key_required,
                    "interval_minutes": 0,  # on demand; never scheduled
                }
                row = existing.get(name)
                if row is None:
                    row = Source(name=name, checkpoint={}, health="unknown", **meta)
                    s.add(row)
                else:
                    for k, v in meta.items():
                        setattr(row, k, v)
                await s.flush()
                self._source_ids[name] = row.id
                self._enabled[name] = row.enabled
        self._synced = True

    async def _ensure_synced(self) -> None:
        if self._synced:
            return
        async with self._sync_lock:
            if not self._synced:
                await self.sync_sources()

    async def allowlist(self) -> Allowlist:
        from threatlens.collect import load_allowlist  # heavy module; only needed here

        now = time.monotonic()
        if self._allowlist is None or now - self._allowlist[0] > ALLOWLIST_TTL_S:
            async with self.sm() as s:
                self._allowlist = (now, await load_allowlist(s))
        return self._allowlist[1]

    def applicable(self, type_: IOCType, only: Iterable[str] | None = None) -> list[str]:
        names = set(only) if only else None
        return [
            n
            for n, c in self.registry.items()
            if type_ in c.info.applies_to and (names is None or n in names)
        ]

    # ── local knowledge ─────────────────────────────────────────────────────

    async def _known(
        self, s: AsyncSession, obs: Observable
    ) -> tuple[dict[str, Any] | None, list[dict[str, Any]], int | None]:
        row = await s.scalar(
            select(ObsRow)
            .where(ObsRow.canonical_key == obs.key)
            .options(
                selectinload(ObsRow.indicator).selectinload(Indicator.sightings).selectinload(Sighting.source)
            )
        )
        if row is None:
            return None, [], None
        ind = row.indicator
        if ind is None:
            return None, [], row.id
        sources = sorted({sg.source.name for sg in ind.sightings})
        known = {
            "indicator_id": ind.id,
            "status": ind.status,
            "confidence": ind.confidence,
            "tlp": ind.tlp,
            "labels": ind.labels or [],
            "sources": sources,
            "first_seen": _aware(row.first_seen),
            "last_seen": _aware(row.last_seen),
            "allowlist_reason": ind.allowlist_reason,
        }
        related: list[dict[str, Any]] = []
        if ind.stix_id:
            items, _ = await graph.neighbors(s, ind.stix_id, limit=50)
            for it in items:
                node, edge = it["node"], it["edge"]
                if node["kind"] in ("entity", "vulnerability"):
                    related.append(
                        {
                            "kind": node["kind"],
                            "type": node["type"],
                            "label": node["label"],
                            "external_id": node.get("external_id"),
                            "ref": node["ref"],
                            "relationship": edge["rel_type"],
                            "via": edge.get("source") or edge.get("origin"),
                        }
                    )
        return known, related, row.id

    @staticmethod
    def _local_evidence(
        known: dict[str, Any] | None,
        related: list[dict[str, Any]],
        allow_effect: str | None,
        allow_reasons: Sequence[str],
    ) -> list[Evidence]:
        ev: list[Evidence] = []
        if known is not None:
            srcs = ", ".join(known["sources"]) or "no source"
            conf = known["confidence"]
            if known["status"] in ("active", "new"):
                kind: EvidenceKind = "malicious" if conf >= 60 else "suspicious"
                ev.append(
                    Evidence(
                        "threatlens", kind, conf, f"Active indicator reported by {srcs} (confidence {conf})"
                    )
                )
            elif known["status"] == "false_positive":
                ev.append(
                    Evidence(
                        "threatlens",
                        "benign",
                        80,
                        f"Marked not malicious: {known['allowlist_reason'] or 'allowlisted'}",
                    )
                )
            else:
                ev.append(Evidence("threatlens", "info", 0, f"Was reported by {srcs}; now {known['status']}"))
        if allow_effect == "suppress":
            ev.append(Evidence("allowlist", "benign", 80, "; ".join(allow_reasons) or "allowlisted"))
        elif allow_effect == "flag":
            ev.append(Evidence("allowlist", "info", 0, "; ".join(allow_reasons)))
        for r in related:
            if r["type"] in ("malware", "tool", "intrusion-set", "campaign"):
                ev.append(
                    Evidence(
                        "threatlens",
                        "info",
                        0,
                        f"Linked to {r['type']} {r['label']} ({r['relationship']}, via {r['via']})",
                    )
                )
        return ev

    # ── one enricher ────────────────────────────────────────────────────────

    async def _cached(self, s: AsyncSession, obs: Observable) -> dict[str, Enrichment]:
        rows = (await s.scalars(select(Enrichment).where(Enrichment.canonical_key == obs.key))).all()
        return {r.enricher: r for r in rows}

    async def _run_one(
        self,
        name: str,
        obs: Observable,
        *,
        cached: Enrichment | None,
        active: bool,
        refresh: bool,
        tlp: str,
        budget: Budget | None,
        observable_id: int | None,
        actor: str,
    ) -> dict[str, Any]:
        cls = self.registry[name]
        info = cls.info
        base: dict[str, Any] = {"enricher": name, "title": info.title, "mode": info.mode}
        now = self.now()
        fresh = cached is not None and _aware(cached.expires_at) > now

        def skipped(reason: str, **extra: Any) -> dict[str, Any]:
            out = {**base, "status": "skipped", "skipped_reason": reason, **extra}
            if cached is not None:  # an older answer is better than none
                out |= _row_out(cached, "stale") | {"skipped_reason": reason}
            return out

        if fresh and not refresh and cached is not None:
            return {**base, **_row_out(cached, "cached")}
        if not self._enabled.get(name, True):
            return skipped("disabled")
        if info.mode == "active" and not active:
            return skipped("active_not_requested")
        why = tlp_blocks(info.third_party, info.discloses, tlp)
        if why:
            return skipped("tlp", detail=why)
        key = self.key_for(name)
        if info.key_required and not key:
            return skipped("no_api_key", detail=f"set TL_{(info.key_setting or '').upper()}")
        units = 1
        if info.metered:
            if budget is not None and not budget.spend(units):
                return skipped("budget_exhausted")
            wait = await self.quota.take(name, info.quotas_for(bool(key)), units)
            if wait > 0:
                if budget is not None:
                    budget.left += units
                return skipped("quota_exhausted", resets_in_s=int(wait) + 1)
        timeout = info.timeout_s or self.settings.enrich_timeout_s
        try:
            async with self._sems[name]:
                outcome = await asyncio.wait_for(cls(key).query(self.http, obs.type, obs.value), timeout)
        except TimeoutError:
            return self._failed(base, cached, f"timed out after {timeout:g} s")
        except FetchError as e:
            if e.status == 429:
                await self.quota.block(name, e.retry_after or 60)
                return skipped(
                    "quota_exhausted", detail="provider answered 429", resets_in_s=int(e.retry_after or 60)
                )
            if e.status in (401, 403):
                return self._failed(base, cached, f"provider refused the API key (HTTP {e.status})")
            return self._failed(base, cached, clip(str(e), 300))
        except (EnrichError, ValueError, KeyError, TypeError) as e:
            log.warning("enrich.unreadable", enricher=name, error=str(e))
            return self._failed(base, cached, clip(f"unreadable answer: {e}", 300))
        await self._after_rate(name, outcome)
        row = await self._store(name, obs, outcome, observable_id=observable_id, actor=actor, mode=info.mode)
        if info.mode == "active":
            async with self.sm() as s, s.begin():
                s.add(
                    AuditLog(
                        actor=actor,
                        action="enrich.active",
                        target=f"{name}:{obs.key}"[:2000],
                        details={"tlp": tlp, "query": outcome.query[:500]},
                    )
                )
        return {**base, **_row_out(row, "ok"), "cost": outcome.calls if info.metered else 0}

    @staticmethod
    def _failed(base: dict[str, Any], cached: Enrichment | None, error: str) -> dict[str, Any]:
        out = {**base, "status": "error", "error": error}
        if cached is not None:
            out |= _row_out(cached, "stale") | {"error": error}
        return out

    async def _after_rate(self, name: str, outcome: Outcome) -> None:
        r = outcome.rate
        if r is not None and r.remaining is not None and r.remaining <= 0:
            secs = (r.reset_at - self.now()).total_seconds() if r.reset_at else 3600.0
            await self.quota.block(name, max(1.0, secs))

    async def _store(
        self,
        name: str,
        obs: Observable,
        outcome: Outcome,
        *,
        observable_id: int | None,
        actor: str,
        mode: str,
    ) -> Enrichment:
        info = self.registry[name].info
        now = self.now()
        ttl: timedelta = info.ttl if outcome.status == "ok" else info.negative_ttl
        values = {
            "source_id": self._source_ids.get(name),
            "observable_id": observable_id,
            "type": obs.type.value,
            "value": obs.value,
            "status": outcome.status,
            "mode": mode,
            "summary": outcome.summary,
            "evidence": [e.as_dict() for e in outcome.evidence],
            "raw": outcome.raw,
            "query": outcome.query[:2000],
            "http_status": outcome.http_status,
            "cost": outcome.calls if info.metered else 0,
            "requested_by": actor[:100],
            "fetched_at": now,
            "expires_at": now + ttl,
        }
        for attempt in range(2):
            try:
                async with self.sm() as s, s.begin():
                    row = await s.scalar(
                        select(Enrichment).where(
                            Enrichment.enricher == name, Enrichment.canonical_key == obs.key
                        )
                    )
                    if row is None:
                        row = Enrichment(enricher=name, canonical_key=obs.key, times_fetched=1, **values)
                        s.add(row)
                    else:
                        for k, v in values.items():
                            setattr(row, k, v)
                        row.times_fetched = (row.times_fetched or 0) + 1
                    await s.flush()
                    s.expunge(row)
                return row
            except IntegrityError:
                if attempt:
                    raise
        raise RuntimeError("unreachable")

    # ── lookups ─────────────────────────────────────────────────────────────

    async def lookup(
        self,
        obs: Observable,
        *,
        actor: str,
        active: bool = False,
        refresh: bool = False,
        tlp: str | None = None,
        only: Iterable[str] | None = None,
        budget: Budget | None = None,
    ) -> dict[str, Any]:
        started = time.perf_counter()
        await self._ensure_synced()
        async with self.sm() as s:
            known, related, observable_id = await self._known(s, obs)
            cached = await self._cached(s, obs)
        verdict_al = (await self.allowlist()).check(obs)
        eff_tlp = stricter_tlp(tlp, known["tlp"] if known else None)
        names = self.applicable(obs.type, only)
        results = await asyncio.gather(
            *(
                self._run_one(
                    n, obs, cached=cached.get(n), active=active, refresh=refresh, tlp=eff_tlp,
                    budget=budget, observable_id=observable_id, actor=actor,
                )
                for n in names
            )
        )  # fmt: skip
        evidence = self._local_evidence(known, related, verdict_al.effect, verdict_al.reasons)
        for r in results:
            for e in r.get("evidence") or []:
                evidence.append(Evidence(e["source"], e["kind"], int(e["weight"]), e["text"], e.get("ref")))
        suppressed = None
        if verdict_al.suppressed:
            suppressed = "; ".join(verdict_al.reasons) or "allowlisted"
        elif known is not None and known["status"] == "false_positive":
            suppressed = known["allowlist_reason"] or "marked not malicious"
        a = assess(evidence, suppressed_by=suppressed)
        partial = any(
            r["status"] in ("error", "stale")
            or (r["status"] == "skipped" and r["skipped_reason"] != "active_not_requested")
            for r in results
        )
        return {
            "query": {
                "type": obs.type.value,
                "value": obs.value,
                "defanged": defang(obs.value, obs.type),
                "canonical_key": obs.key,
            },
            "verdict": a.verdict,
            "score": a.score,
            "score_model": a.model,
            "score_breakdown": a.breakdown,
            "recommended_action": a.action,
            "recommended_action_text": a.action_text,
            "tlp": eff_tlp,
            "known": known,
            "allowlist": {
                "effect": verdict_al.effect,
                "reasons": list(verdict_al.reasons),
                "labels": list(verdict_al.labels),
            },
            "evidence": [e.as_dict() for e in sorted(evidence, key=lambda e: (e.kind == "info", -e.weight))],
            "related": related,
            "enrichments": sorted(results, key=lambda r: r["enricher"]),
            "partial": partial,
            "took_ms": round((time.perf_counter() - started) * 1000, 1),
        }

    async def lookup_many(
        self,
        observables: Sequence[Observable],
        *,
        actor: str,
        active: bool = False,
        refresh: bool = False,
        tlp: str | None = None,
        budget: int | None = None,
        concurrency: int = 4,
    ) -> tuple[list[dict[str, Any]], int]:
        """Look up several observables (deduplicated, order kept) sharing one
        metered-call budget; returns (results, units spent)."""
        uniq = list({o.key: o for o in observables}.values())
        b = Budget(self.settings.enrich_budget if budget is None else budget)
        start = b.left
        sem = asyncio.Semaphore(concurrency)

        async def one(o: Observable) -> dict[str, Any]:
            async with sem:
                return await self.lookup(o, actor=actor, active=active, refresh=refresh, tlp=tlp, budget=b)

        results = await asyncio.gather(*(one(o) for o in uniq))
        return list(results), start - b.left

    # ── background ──────────────────────────────────────────────────────────

    async def enrich_backlog(self, limit: int) -> dict[str, int]:
        """Enrich recently seen active IP indicators with the free, passive,
        unmetered enrichers (``auto``), newest first, skipping fresh ones."""
        names = [n for n, c in self.registry.items() if c.info.auto]
        if limit <= 0 or not names:
            return {"candidates": 0, "enriched": 0}
        await self._ensure_synced()
        now = self.now()
        async with self.sm() as s:
            fresh = select(Enrichment.canonical_key).where(
                Enrichment.enricher.in_(names), Enrichment.expires_at > now
            )
            rows = (
                await s.execute(
                    select(ObsRow.type, ObsRow.value, Indicator.tlp)
                    .join(Indicator, Indicator.observable_id == ObsRow.id)
                    .where(
                        ObsRow.type.in_([IOCType.IPV4.value, IOCType.IPV6.value]),
                        Indicator.status == "active",
                        ObsRow.canonical_key.not_in(fresh),
                    )
                    .order_by(ObsRow.last_seen.desc())
                    .limit(limit)
                )
            ).all()
        done = 0
        for t, v, tlp in rows:
            res = await self.lookup(Observable(IOCType(t), v), actor="worker", tlp=tlp, only=names)
            done += sum(1 for r in res["enrichments"] if r["status"] == "ok")
        log.info("enrich.backlog", candidates=len(rows), enriched=done)
        return {"candidates": len(rows), "enriched": done}

    async def status(self) -> list[dict[str, Any]]:
        """Each enricher: configuration, policy and quota use right now."""
        await self._ensure_synced()
        out = []
        for name, cls in sorted(self.registry.items()):
            i = cls.info
            keyed = bool(self.key_for(name))
            quotas = i.quotas_for(keyed)
            out.append(
                {
                    "name": name,
                    "title": i.title,
                    "applies_to": sorted(t.value for t in i.applies_to),
                    "mode": i.mode,
                    "third_party": i.third_party,
                    "discloses": i.discloses,
                    "requires_key": i.key_required,
                    "key_configured": keyed,
                    "enabled": self._enabled.get(name, True),
                    "metered": i.metered,
                    "quotas": [q.label for q in quotas],
                    "used": await self.quota.usage(name, quotas),
                    "ttl_hours": round(i.ttl.total_seconds() / 3600, 1),
                    "auto": i.auto,
                    "reliability": i.reliability,
                    "license": i.license,
                    "commercial_use": i.commercial_use,
                    "redistribution": i.redistribution,
                    "verified": i.verified,
                }
            )
        return out


def enrichment_http(settings: Settings) -> SafeHttp:
    """Lookups are interactive: one quick retry, never a long Retry-After wait
    (a provider asking for a pause is treated as quota exhaustion instead)."""
    return SafeHttp(
        timeout=settings.enrich_timeout_s,
        retries=1,
        backoff_base=0.5,
        max_retry_after=5.0,
        max_bytes=20 * 1024 * 1024,
    )
