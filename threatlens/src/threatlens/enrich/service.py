"""Enrichment service: one place that decides *whether* to ask a provider,
asks it, stores the answer and turns everything into a verdict (ADR 0005).

For each enricher that handles the observable's type, in this order:

1. a fresh cached answer is used as is (``cached``) unless ``refresh``;
2. an active enricher runs only when the caller asked for active mode;
3. TLP (``threatlens.tlp`` sinks): no third party sees AMBER/RED values;
   GREEN values only go to providers that don't disclose lookups;
4. a missing key, a disabled source, an exhausted bulk budget or provider
   quota each give ``skipped`` with a ``skipped_reason``;
5. otherwise the provider is called under a timeout; failures are reported
   (``error``) and, when an older answer exists, it is returned as ``stale``.

Nothing here raises for a provider problem: a lookup always returns, with
``partial: true`` when anything was skipped or failed.

The verdict comes from the scoring model (``threatlens.scoring``, ADR 0008):
the same function that scores stored indicators, applied to the feeds'
sightings plus the providers' findings of this lookup. Everything the caller
may not read (an indicator above their TLP clearance) is left out of the
answer and of the score; it still keeps the value away from third parties.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload

from threatlens import tlp as tlp_rules
from threatlens.allowlist import Allowlist
from threatlens.assets import asset_for
from threatlens.connectors.base import clip
from threatlens.enrich.base import REGISTRY, Enricher, EnrichError, Evidence, Outcome
from threatlens.enrich.quota import QuotaStore
from threatlens.ioc.defang import defang
from threatlens.ioc.types import IOCType, Observable
from threatlens.kb import graph
from threatlens.logs import get_logger
from threatlens.models import AuditLog, Enrichment, Indicator, Sighting, Source
from threatlens.models import Observable as ObsRow
from threatlens.net.http import FetchError, SafeHttp
from threatlens.scoring.model import Score
from threatlens.scoring.model import score as score_signals
from threatlens.scoring.store import (
    Context,
    analyst_signal,
    evidence_signals,
    load_context,
    penalty_hits,
    relevance_hits,
    sighting_signal,
)
from threatlens.settings import Settings

log = get_logger("threatlens.enrich")

ALLOWLIST_TTL_S = 300
CONTEXT_TTL_S = 300
ENABLED_TTL_S = 30


def utcnow() -> datetime:
    return datetime.now(UTC)


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def stricter_tlp(*levels: str | None) -> str:
    """The most restricted marking given; unknown markings count as RED."""
    return tlp_rules.stricter(*levels)


def sink_for(info_third_party: bool, info_discloses: bool) -> str | None:
    """The TLP sink a provider is (None: the value doesn't leave the platform)."""
    if not info_third_party:
        return None
    return "enricher:disclosing" if info_discloses else "enricher:third_party"


def tlp_blocks(info_third_party: bool, info_discloses: bool, tlp: str) -> str | None:
    """Why TLP keeps this value away from the provider, or None."""
    sink = sink_for(info_third_party, info_discloses)
    if sink is None or tlp_rules.sink_allows(sink, tlp):
        return None
    if sink == "enricher:disclosing" and tlp_rules.rank(tlp) == 1:
        return f"{tlp}: this provider may disclose lookups to others"
    return f"{tlp}: not shared with third parties"


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
        self._enabled_at = 0.0
        self._sync_lock = asyncio.Lock()  # concurrent first lookups must not race the inserts
        self._allowlist: tuple[float, Allowlist] | None = None
        self._context: tuple[float, Context] | None = None

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
                    "credibility": i.credibility,
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
        self._enabled_at = time.monotonic()

    async def _ensure_synced(self) -> None:
        if self._synced:
            if time.monotonic() - self._enabled_at > ENABLED_TTL_S:
                await self._refresh_enabled()
            return
        async with self._sync_lock:
            if not self._synced:
                await self.sync_sources()

    async def ensure_sources(self) -> None:
        """Create the providers' source rows if no lookup has yet."""
        await self._ensure_synced()

    def forget_enabled(self) -> None:
        """Re-read the on/off switches on the next lookup (after a toggle here)."""
        self._enabled_at = 0.0

    async def _refresh_enabled(self) -> None:
        """Pick up providers switched on or off in the feed catalog (in this
        process and in the worker) without a restart."""
        self._enabled_at = time.monotonic()
        async with self.sm() as s:
            rows = (
                await s.execute(select(Source.name, Source.enabled).where(Source.kind == "enricher"))
            ).all()
        self._enabled.update({str(n): bool(e) for n, e in rows})

    async def allowlist(self) -> Allowlist:
        from threatlens.collect import load_allowlist  # heavy module; only needed here

        now = time.monotonic()
        if self._allowlist is None or now - self._allowlist[0] > ALLOWLIST_TTL_S:
            async with self.sm() as s:
                self._allowlist = (now, await load_allowlist(s))
        return self._allowlist[1]

    async def scoring_context(self) -> Context:
        now = time.monotonic()
        if self._context is None or now - self._context[0] > CONTEXT_TTL_S:
            async with self.sm() as s:
                self._context = (now, await load_context(s, self.settings))
        return self._context[1]

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
    ) -> tuple[dict[str, Any] | None, list[dict[str, Any]], int | None, list[Sighting]]:
        row = await s.scalar(
            select(ObsRow)
            .where(ObsRow.canonical_key == obs.key)
            .options(
                selectinload(ObsRow.indicator).selectinload(Indicator.sightings).selectinload(Sighting.source)
            )
        )
        if row is None:
            return None, [], None, []
        ind = row.indicator
        if ind is None:
            return None, [], row.id, []
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
            "analyst_verdict": ind.analyst_verdict,
            "analyst_verdict_by": ind.analyst_verdict_by,
            "analyst_verdict_at": _aware(ind.analyst_verdict_at) if ind.analyst_verdict_at else None,
            "priority_score": ind.priority_score,
        }
        related: list[dict[str, Any]] = []
        if ind.stix_id:
            items, _ = await graph.neighbors(s, ind.stix_id, limit=50, clearance=tlp_rules.RED)
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
        return known, related, row.id, list(ind.sightings)

    @staticmethod
    def _local_evidence(
        known: dict[str, Any] | None,
        related: list[dict[str, Any]],
        allow_effect: str | None,
        allow_reasons: Sequence[str],
        signals: Sequence[dict[str, Any]] = (),
    ) -> list[Evidence]:
        ev: list[Evidence] = []
        if known is not None:
            srcs = ", ".join(known["sources"]) or "no source"
            if known["status"] in ("active", "new", "expired"):
                for sig in signals:
                    ev.append(
                        Evidence(
                            "threatlens",
                            sig["kind"],
                            round(sig["value"]),
                            f"{sig['text']} (confidence {sig['confidence']}, "
                            f"{sig['age_days']:g} days ago, weight {sig['weight']:g})",
                        )
                    )
                if known["status"] == "expired":
                    ev.append(Evidence("threatlens", "info", 0, f"Expired: reported by {srcs} too long ago"))
            elif known["status"] == "false_positive":
                reason = (
                    f"marked false positive by {known['analyst_verdict_by'] or 'an analyst'}"
                    if known.get("analyst_verdict") == "fp"
                    else known["allowlist_reason"] or "allowlisted"
                )
                ev.append(Evidence("threatlens", "benign", 80, f"Marked not malicious: {reason}"))
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
        offline: bool = False,
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
        if offline:
            return skipped("not_requested")  # local knowledge only (bulk lookups)
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
        clearance: str,
        providers: bool = True,
    ) -> dict[str, Any]:
        """``clearance``: the caller's TLP clearance (``tlp.RED`` for the
        platform itself). Local knowledge above it is not used or returned.
        ``providers=False`` asks no provider: cached answers and local
        knowledge only."""
        final: dict[str, Any] | None = None
        async for kind, data in self.lookup_stream(
            obs, actor=actor, active=active, refresh=refresh, tlp=tlp, only=only, budget=budget,
            clearance=clearance, providers=providers,
        ):  # fmt: skip
            if kind == "done":
                final = data
        assert final is not None  # the stream always ends with "done"
        return final

    async def lookup_stream(
        self,
        obs: Observable,
        *,
        actor: str,
        active: bool = False,
        refresh: bool = False,
        tlp: str | None = None,
        only: Iterable[str] | None = None,
        budget: Budget | None = None,
        clearance: str,
        providers: bool = True,
    ) -> AsyncIterator[tuple[str, dict[str, Any]]]:
        """The same lookup, as it happens: ``("start", local knowledge and the
        providers about to be asked)``, then ``("enricher", result)`` as each
        provider answers, then ``("done", the full lookup)``. Closing the
        stream early cancels the providers still running."""
        started = time.perf_counter()
        await self._ensure_synced()
        async with self.sm() as s:
            known, related, observable_id, sightings = await self._known(s, obs)
            cached = await self._cached(s, obs)
            own = await asset_for(s, obs.key)
        verdict_al = (await self.allowlist()).check(obs)
        # Sinks see the strictest marking we hold, whoever is asking.
        eff_tlp = stricter_tlp(tlp, known["tlp"] if known else None)
        if known is not None and not tlp_rules.may_read(clearance, known["tlp"]):
            known, related, sightings = None, [], []
        reply_tlp = stricter_tlp(tlp, known["tlp"] if known else None)
        names = self.applicable(obs.type, only)
        query = {
            "type": obs.type.value,
            "value": obs.value,
            "defanged": defang(obs.value, obs.type),
            "canonical_key": obs.key,
        }
        allow_out = {
            "effect": verdict_al.effect,
            "reasons": list(verdict_al.reasons),
            "labels": list(verdict_al.labels),
        }
        pending = [{"enricher": n, "title": self.registry[n].info.title} for n in names]
        yield "start", {
            "query": query, "known": known, "related": related, "asset": own, "allowlist": allow_out,
            "tlp": reply_tlp, "pending": pending,
        }  # fmt: skip
        tasks = [
            asyncio.ensure_future(
                self._run_one(
                    n, obs, cached=cached.get(n), active=active, refresh=refresh, tlp=eff_tlp,
                    budget=budget, observable_id=observable_id, actor=actor, offline=not providers,
                )
            )
            for n in names
        ]  # fmt: skip
        results: list[dict[str, Any]] = []
        try:
            for fut in asyncio.as_completed(tasks):
                r = await fut
                results.append(r)
                yield "enricher", r
        finally:  # the reader went away: stop asking providers
            for task in tasks:
                if not task.done():
                    task.cancel()
        sc = await self._score(obs, known, related, sightings, results, verdict_al)
        local = {sg.source.name for sg in sightings} | {"analyst"}
        mine = [r for r in sc.signals if r["source"] in local]
        evidence = self._local_evidence(known, related, verdict_al.effect, verdict_al.reasons, mine)
        for r in results:
            for e in r.get("evidence") or []:
                evidence.append(Evidence(e["source"], e["kind"], int(e["weight"]), e["text"], e.get("ref")))
        if own is not None:
            evidence.append(
                Evidence(
                    "assets",
                    "info",
                    0,
                    f"Own asset: {own['kind']} of {own['target']} (imported from {own['origin']}, "
                    f"last seen {own['last_seen'].date()})",
                )
            )
        action, action_text = sc.action, sc.action_text
        if own is not None and action == "block":
            # Blocking our own host or IP cuts off our own service; a feed
            # listing it means compromise, abuse or a shared address (ADR 0006).
            action = "investigate"
            action_text = (
                "This is one of your own assets: check it for compromise or abuse "
                "(or a shared IP) instead of blocking it."
            )
            sc.breakdown["own_asset"] = "block becomes investigate"
        partial = any(
            r["status"] in ("error", "stale")
            or (
                r["status"] == "skipped"
                and r["skipped_reason"] not in ("active_not_requested", "not_requested")
            )
            for r in results
        )
        yield (
            "done",
            {
                "query": query,
                "verdict": sc.verdict,
                "score": round(sc.priority),
                "priority": sc.priority,
                "score_model": sc.breakdown["model"],
                "score_breakdown": sc.breakdown,
                "recommended_action": action,
                "recommended_action_text": action_text,
                "tlp": reply_tlp,
                "known": known,
                "asset": own,
                "allowlist": allow_out,
                "evidence": [
                    e.as_dict() for e in sorted(evidence, key=lambda e: (e.kind == "info", -e.weight))
                ],
                "related": related,
                "enrichments": sorted(results, key=lambda r: r["enricher"]),
                "partial": partial,
                "took_ms": round((time.perf_counter() - started) * 1000, 1),
            },
        )

    async def _score(
        self,
        obs: Observable,
        known: dict[str, Any] | None,
        related: list[dict[str, Any]],
        sightings: Sequence[Sighting],
        results: Sequence[dict[str, Any]],
        verdict_al: Any,
    ) -> Score:
        ctx = await self.scoring_context()
        signals = []
        for sg in sightings:
            meta = ctx.sources.get(sg.source_id)
            if meta is not None:
                signals.append(sighting_signal(meta, sg.confidence, sg.last_seen, sg.context))
        dead = False
        for r in results:
            if r.get("evidence") and r.get("fetched_at"):
                signals += evidence_signals(r["evidence"], r["fetched_at"], ctx.by_name)
            if r["enricher"] == "rdap" and obs.type == IOCType.DOMAIN and r.get("found") is False:
                dead = True
        if known is not None and known.get("analyst_verdict") == "tp":
            signals.append(analyst_signal(ctx.cfg, known["analyst_verdict_by"], known["analyst_verdict_at"]))
        labels = list(dict.fromkeys([*(known["labels"] if known else []), *verdict_al.labels]))
        suppressed = None
        if verdict_al.suppressed:
            suppressed = "; ".join(verdict_al.reasons) or "allowlisted"
        elif known is not None and known["status"] == "false_positive":
            suppressed = (
                f"marked false positive by {known['analyst_verdict_by'] or 'an analyst'}"
                if known.get("analyst_verdict") == "fp"
                else known["allowlist_reason"] or "marked not malicious"
            )
        return score_signals(
            signals,
            obs_type=obs.type.value,
            now=self.now(),
            cfg=ctx.cfg,
            relevance=relevance_hits(
                ctx, obs.type.value, obs.value, obs.key, [sg.context or {} for sg in sightings],
                [r["ref"] for r in related], labels,
            ),
            penalties=penalty_hits(ctx, labels, dead),
            suppressed=suppressed,
        )  # fmt: skip

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
        clearance: str,
        providers: bool = True,
    ) -> tuple[list[dict[str, Any]], int]:
        """Look up several observables (deduplicated, order kept) sharing one
        metered-call budget; returns (results, units spent)."""
        uniq = list({o.key: o for o in observables}.values())
        b = Budget(self.settings.enrich_budget if budget is None else budget)
        start = b.left
        sem = asyncio.Semaphore(concurrency)

        async def one(o: Observable) -> dict[str, Any]:
            async with sem:
                return await self.lookup(
                    o, actor=actor, active=active, refresh=refresh, tlp=tlp, budget=b, clearance=clearance,
                    providers=providers,
                )  # fmt: skip

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
            res = await self.lookup(
                Observable(IOCType(t), v), actor="worker", tlp=tlp, only=names, clearance=tlp_rules.RED
            )
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
