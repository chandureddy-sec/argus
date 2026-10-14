"""Collection pipeline: one run of one connector.

    fetch (hardened client, conditional) → archive raw document (content-addressed)
    → parse (connector) → normalize (reject bogons, bad values) → merge duplicates
    → allowlist verdict → upsert observables / indicators / sightings in batches
    → run metrics, source health, checkpoint, next run time

Idempotency: observables are unique by canonical key, indicators by
observable, sightings by (indicator, source). Inserts use ON CONFLICT DO
NOTHING followed by a read, so concurrent runs of different sources that see
the same IOC never fail or duplicate; re-running a source updates timestamps
and counters only.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from secrets import SystemRandom
from typing import Any

import httpx
from sqlalchemy import delete, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from threatlens import catalog
from threatlens import tlp as tlp_rules
from threatlens.allowlist import Allowlist, Entry, Verdict
from threatlens.connectors import REGISTRY
from threatlens.connectors.base import Connector, Item, MissingKeyError, SchemaDriftError
from threatlens.db import upsert_insert
from threatlens.ioc.defang import defang
from threatlens.ioc.normalize import guess, normalize
from threatlens.ioc.types import IOCType, Observable
from threatlens.kb import KB_REGISTRY
from threatlens.kb.base import KbContext, KnowledgeSource
from threatlens.kb.link import link_source
from threatlens.kb.vulns import apply_kev
from threatlens.logs import get_logger
from threatlens.models import (
    AllowlistEntry,
    ConnectorRun,
    Indicator,
    RawDocument,
    Sighting,
    Source,
)
from threatlens.models import Observable as ObservableRow
from threatlens.net.guard import BlockedAddressError
from threatlens.net.http import FetchError, SafeHttp
from threatlens.rawstore import RawStore
from threatlens.scoring.store import rescore, rescore_vulns
from threatlens.settings import Settings

log = get_logger("threatlens.collect")
BATCH = 500
_rng = SystemRandom()

ALLOWLIST_LABELS = {
    "popular-domain",
    "popular-domain-host",
    "shared-cdn",
    "own-asset",
    "allowlisted",
    "contains-own-assets",
}


def utcnow() -> datetime:
    return datetime.now(UTC)


def aware(dt: datetime | None) -> datetime | None:
    """SQLite returns naive datetimes even for timezone-aware columns."""
    return dt.replace(tzinfo=UTC) if dt is not None and dt.tzinfo is None else dt


def stricter_tlp(a: str, b: str) -> str:
    """The more restricted marking; unknown markings count as RED (tlp.py)."""
    return tlp_rules.stricter(a, b)


def stix_pattern(obs: Observable) -> str | None:
    """STIX 2.1 indicator pattern; None for types that aren't patterns (CVE)."""
    v = obs.value.replace("\\", "\\\\").replace("'", "\\'")
    path = {
        IOCType.IPV4: "ipv4-addr:value",
        IOCType.IPV4_NET: "ipv4-addr:value",
        IOCType.IPV6: "ipv6-addr:value",
        IOCType.IPV6_NET: "ipv6-addr:value",
        IOCType.DOMAIN: "domain-name:value",
        IOCType.URL: "url:value",
        IOCType.EMAIL: "email-addr:value",
        IOCType.MD5: "file:hashes.MD5",
        IOCType.SHA1: "file:hashes.'SHA-1'",
        IOCType.SHA256: "file:hashes.'SHA-256'",
        IOCType.FILENAME: "file:name",
        IOCType.REGKEY: "windows-registry-key:key",
    }.get(obs.type)
    return f"[{path} = '{v}']" if path else None


@dataclass
class Merged:
    """All of one document's reports of one observable, combined."""

    obs: Observable
    seen_at: datetime | None
    confidence: int
    labels: list[str]
    context: dict[str, Any]
    tlp: str
    verdict: Verdict = field(default_factory=Verdict)


@dataclass
class RunSummary:
    source: str
    status: str  # success | partial | not_modified | unchanged | skipped | too_soon | failed | disabled
    http_status: int | None = None
    items_total: int = 0
    items_new: int = 0
    items_updated: int = 0
    items_rejected: int = 0
    items_allowlisted: int = 0
    error: str | None = None
    duration_s: float = 0.0
    rejected_reasons: dict[str, int] = field(default_factory=dict)
    note: str | None = None


def _key_for(settings: Settings, connector_cls: type[Connector] | type[KnowledgeSource]) -> str | None:
    attr = connector_cls.info.key_setting
    secret = getattr(settings, attr, None) if attr else None
    return secret.get_secret_value() if secret is not None else None


class Collector:
    def __init__(
        self,
        sessionmaker: async_sessionmaker[AsyncSession],
        http: SafeHttp,
        store: RawStore,
        settings: Settings,
        *,
        now: Callable[[], datetime] = utcnow,
        registry: dict[str, type[Connector]] | None = None,
        kb_registry: dict[str, type[KnowledgeSource]] | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.sm = sessionmaker
        self.http = http
        self.store = store
        self.settings = settings
        self.now = now
        self.registry = registry if registry is not None else REGISTRY
        self.kb_registry = kb_registry if kb_registry is not None else KB_REGISTRY
        self.sleep = sleep

    @property
    def sources(self) -> dict[str, type[Connector] | type[KnowledgeSource]]:
        """Indicator feeds and knowledge sources, by name."""
        return {**self.registry, **self.kb_registry}

    # ── sources ─────────────────────────────────────────────────────────────

    async def sync_sources(self) -> None:
        """Create or refresh source rows from connector metadata, keeping
        runtime state (health, checkpoint, enabled)."""
        async with self.sm() as s, s.begin():
            existing = {x.name: x for x in (await s.scalars(select(Source))).all()}
            for name, cls in self.sources.items():
                i = cls.info
                meta = {
                    "title": i.title,
                    "kind": i.kind,
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
                    "tlp_default": i.tlp,
                    "requires_key": i.key_required,
                    "interval_minutes": int(i.interval.total_seconds() // 60),
                }
                row = existing.get(name)
                if row is None:
                    s.add(Source(name=name, checkpoint={}, **meta))
                else:
                    for k, v in meta.items():
                        setattr(row, k, v)

    async def due(self) -> list[str]:
        now = self.now()
        async with self.sm() as s:
            rows = (await s.scalars(select(Source).where(Source.enabled.is_(True)))).all()
            custom = await catalog.custom_names(s)
        due = []
        for r in rows:
            next_run = aware(r.next_run_at)
            if (r.name in self.sources or r.name in custom) and (next_run is None or next_run <= now):
                due.append(r.name)
        return due

    # ── allowlist ───────────────────────────────────────────────────────────

    async def load_allowlist(self, s: AsyncSession) -> Allowlist:
        return await load_allowlist(s)

    # ── one run ─────────────────────────────────────────────────────────────

    async def source_row(self, name: str) -> Source:
        async with self.sm() as s:
            src = await s.scalar(select(Source).where(Source.name == name))
        if src is None:
            await self.sync_sources()
            async with self.sm() as s:
                src = await s.scalar(select(Source).where(Source.name == name))
        if src is None:
            raise RuntimeError(f"source {name!r} missing after sync")
        return src

    async def run(self, name: str, *, force: bool = False) -> RunSummary:
        if name in self.kb_registry:
            return await self._run_kb(name, force=force)
        started = time.perf_counter()
        cls = self.registry.get(name)
        if cls is None:  # a feed an admin added in the UI (catalog)
            async with self.sm() as s:
                cls = await catalog.load_connector(s, name, self.settings)
        if cls is None:
            raise KeyError(f"unknown source {name!r}")
        info = cls.info
        now = self.now()
        src = await self.source_row(name)
        if not src.enabled and not force:
            return RunSummary(name, "disabled")
        last_run = aware(src.last_run_at)
        if not force and last_run and now - last_run < info.min_interval:
            # The source's own fetch limit: never exceed it, even on a manual trigger.
            return RunSummary(
                name, "too_soon", error=f"last run {last_run.isoformat()}; minimum gap {info.min_interval}"
            )

        summary = RunSummary(name, "failed")
        raw_id: int | None = None
        checkpoint = dict(src.checkpoint or {})
        try:
            connector = cls(api_key=_key_for(self.settings, cls))
        except MissingKeyError as e:
            summary.status, summary.error = "skipped", str(e)
            await self._finish(src.id, summary, now, info.interval, health="skipped")
            return summary

        try:
            result = await connector.fetch(self.http, checkpoint)
            summary.http_status = result.status
            new_checkpoint = connector.next_checkpoint(result, checkpoint)
            if result.not_modified:
                summary.status = "not_modified"
                await self._finish(
                    src.id, summary, now, info.interval, health="ok", checkpoint=new_checkpoint
                )
                return summary

            sha, ref = self.store.put(name, result.body)
            async with self.sm() as s, s.begin():
                doc = await s.scalar(
                    select(RawDocument).where(RawDocument.source_id == src.id, RawDocument.sha256 == sha)
                )
                if doc is not None and doc.parse_status == "parsed" and not force:
                    summary.status = "unchanged"
                    raw_id = doc.id
                if doc is None:
                    doc = RawDocument(
                        source_id=src.id,
                        url=result.url,
                        sha256=sha,
                        size=len(result.body),
                        content_type=result.content_type[:200],
                        payload_ref=ref,
                        fetched_at=now,
                    )
                    s.add(doc)
                    await s.flush()
                raw_id = doc.id
            if summary.status == "unchanged":
                await self._finish(
                    src.id, summary, now, info.interval, health="ok", checkpoint=new_checkpoint, raw_id=raw_id
                )
                return summary

            try:
                items = list(connector.parse(result.body))
            except SchemaDriftError as e:
                await self._mark_doc(raw_id, "failed", str(e), 0)
                raise
            summary.items_total = len(items)
            merged = self._merge(items, info.default_confidence, info.tlp, summary)
            async with self.sm() as s, s.begin():
                allow = await self.load_allowlist(s)
                for m in merged:
                    m.verdict = allow.check(m.obs)
                    if m.verdict.suppressed:
                        summary.items_allowlisted += 1
                touched: list[int] = []
                for i in range(0, len(merged), BATCH):
                    new, upd, ids = await self._ingest(s, src.id, raw_id, merged[i : i + BATCH], now)
                    summary.items_new += new
                    summary.items_updated += upd
                    touched += ids
            await self._mark_doc(raw_id, "parsed", None, len(items))
            summary.status = "success"
            await self._finish(
                src.id, summary, now, info.interval, health="ok", checkpoint=new_checkpoint, raw_id=raw_id
            )
            await self._after_run(name, now)
            await self._rescore(name, touched, now)
        except (FetchError, BlockedAddressError, httpx.HTTPError, SchemaDriftError, OSError, ValueError) as e:
            summary.status = "failed"
            summary.error = f"{type(e).__name__}: {e}"[:1000]
            drift = isinstance(e, SchemaDriftError)
            await self._fail(src.id, summary, now, info.interval, info.min_interval, drift, raw_id)
        finally:
            summary.duration_s = round(time.perf_counter() - started, 2)
            log.info(
                "collect.run",
                source=name,
                status=summary.status,
                total=summary.items_total,
                new=summary.items_new,
                updated=summary.items_updated,
                rejected=summary.items_rejected,
                allowlisted=summary.items_allowlisted,
                error=summary.error,
                duration_s=summary.duration_s,
            )
        return summary

    def _merge(
        self, items: Iterable[Item], default_conf: int, default_tlp: str, summary: RunSummary
    ) -> list[Merged]:
        out: dict[str, Merged] = {}
        for it in items:
            r = normalize(it.type, it.value) if it.type else guess(it.value)
            if not isinstance(r, Observable):
                summary.items_rejected += 1
                summary.rejected_reasons[r.reason] = summary.rejected_reasons.get(r.reason, 0) + 1
                continue
            conf = it.confidence if it.confidence is not None else default_conf
            conf = max(0, min(100, conf))
            tlp = tlp_rules.normalize(it.tlp or default_tlp)
            m = out.get(r.key)
            if m is None:
                out[r.key] = Merged(
                    r, it.seen_at, conf, list(dict.fromkeys(it.labels)), dict(it.context), tlp
                )
                continue
            m.confidence = max(m.confidence, conf)
            if it.seen_at and (m.seen_at is None or it.seen_at < m.seen_at):
                m.seen_at = it.seen_at
            m.labels = list(dict.fromkeys([*m.labels, *it.labels]))
            m.context.update({k: v for k, v in it.context.items() if v is not None})
            m.tlp = stricter_tlp(m.tlp, tlp)
        return list(out.values())

    async def _ingest(
        self, s: AsyncSession, source_id: int, raw_id: int | None, batch: Sequence[Merged], now: datetime
    ) -> tuple[int, int, list[int]]:
        keys = [m.obs.key for m in batch]
        pre = set(
            (
                await s.scalars(
                    select(ObservableRow.canonical_key).where(ObservableRow.canonical_key.in_(keys))
                )
            ).all()
        )
        rows = [
            {
                "type": m.obs.type.value,
                "value": m.obs.value,
                "canonical_key": m.obs.key,
                "defanged": defang(m.obs.value, m.obs.type),
                "first_seen": m.seen_at or now,
                "last_seen": now,
                "sightings_count": 0,
            }
            for m in batch
            if m.obs.key not in pre
        ]
        if rows:
            await s.execute(
                upsert_insert(s, ObservableRow)
                .values(rows)
                .on_conflict_do_nothing(index_elements=["canonical_key"])
            )
        obs_rows = {
            o.canonical_key: o
            for o in (
                await s.scalars(select(ObservableRow).where(ObservableRow.canonical_key.in_(keys)))
            ).all()
        }
        new = sum(1 for k in keys if k not in pre)

        # Indicators: one per observable.
        obs_ids = [o.id for o in obs_rows.values()]
        existing_ind = {
            i.observable_id: i
            for i in (await s.scalars(select(Indicator).where(Indicator.observable_id.in_(obs_ids)))).all()
        }
        ind_rows = []
        for m in batch:
            o = obs_rows[m.obs.key]
            if o.id in existing_ind:
                continue
            ind_rows.append(
                {
                    "observable_id": o.id,
                    "pattern": stix_pattern(m.obs),
                    "valid_from": m.seen_at or now,
                    "confidence": m.confidence,
                    "tlp": m.tlp,
                    "status": "false_positive" if m.verdict.suppressed else "active",
                    "labels": list(dict.fromkeys([*m.labels, *m.verdict.labels])),
                    "allowlist_reason": "; ".join(m.verdict.reasons) if m.verdict.suppressed else None,
                    "created_at": now,
                    "updated_at": now,
                }
            )
        if ind_rows:
            await s.execute(
                upsert_insert(s, Indicator)
                .values(ind_rows)
                .on_conflict_do_nothing(index_elements=["observable_id"])
            )
        inds = {
            i.observable_id: i
            for i in (await s.scalars(select(Indicator).where(Indicator.observable_id.in_(obs_ids)))).all()
        }

        for m in batch:
            o = obs_rows[m.obs.key]
            ind = inds[o.id]
            if o.id not in existing_ind:
                continue  # just created with this batch's values
            ind.confidence = max(ind.confidence, m.confidence)
            ind.tlp = stricter_tlp(ind.tlp, m.tlp)
            ind.labels = list(dict.fromkeys([*(ind.labels or []), *m.labels]))
            self._apply_verdict(ind, m.verdict)
            ind.updated_at = now
            o.last_seen = now

        # Sightings: one per (indicator, source).
        ind_ids = [i.id for i in inds.values()]
        seen = {
            sg.indicator_id: sg
            for sg in (
                await s.scalars(
                    select(Sighting).where(
                        Sighting.source_id == source_id, Sighting.indicator_id.in_(ind_ids)
                    )
                )
            ).all()
        }
        sg_rows = []
        for m in batch:
            o = obs_rows[m.obs.key]
            ind = inds[o.id]
            sg = seen.get(ind.id)
            if sg is None:
                sg_rows.append(
                    {
                        "indicator_id": ind.id,
                        "source_id": source_id,
                        "raw_document_id": raw_id,
                        "first_seen": m.seen_at or now,
                        "last_seen": now,
                        "times_reported": 1,
                        "confidence": m.confidence,
                        "labels": m.labels,
                        "context": m.context,
                        "updated_at": now,
                    }
                )
                o.sightings_count = (o.sightings_count or 0) + 1
            else:
                sg.last_seen = now
                sg.times_reported += 1
                sg.confidence = m.confidence
                sg.labels = m.labels
                sg.context = m.context
                sg.raw_document_id = raw_id
                sg.updated_at = now
        if sg_rows:
            await s.execute(
                upsert_insert(s, Sighting)
                .values(sg_rows)
                .on_conflict_do_nothing(index_elements=["indicator_id", "source_id"])
            )
        return new, len(batch) - new, [i.id for i in inds.values()]

    @staticmethod
    def _apply_verdict(ind: Indicator, verdict: Verdict) -> bool:
        """Apply an allowlist verdict to an indicator. Only statuses the
        allowlist itself set (allowlist_reason not null) are reversed, and an
        analyst's TP/FP verdict is never overridden (only the labels follow
        the allowlist). Returns True if changed."""
        before = (ind.status, ind.allowlist_reason, tuple(ind.labels or []))
        labels = [x for x in (ind.labels or []) if x not in ALLOWLIST_LABELS]
        ind.labels = list(dict.fromkeys([*labels, *verdict.labels]))
        if ind.analyst_verdict is not None:
            pass
        elif verdict.suppressed and ind.status in ("active", "new", "expired"):
            ind.status, ind.allowlist_reason = "false_positive", "; ".join(verdict.reasons)
        elif verdict.suppressed and ind.allowlist_reason is not None:
            ind.allowlist_reason = "; ".join(verdict.reasons)
        elif not verdict.suppressed and ind.status == "false_positive" and ind.allowlist_reason is not None:
            ind.status, ind.allowlist_reason = "active", None
        return before != (ind.status, ind.allowlist_reason, tuple(ind.labels))

    async def _rescore(self, name: str, ids: Sequence[int], now: datetime) -> None:
        """Score what this run touched. A failure is logged, never a failed run."""
        if not ids:
            return
        try:
            await rescore(self.sm, self.settings, ids=ids, now=now)
        except (SQLAlchemyError, ValueError, OSError) as e:
            log.warning("collect.rescore_failed", source=name, error=f"{type(e).__name__}: {e}"[:300])

    async def _rescore_vulns(self, name: str) -> None:
        """New NVD/EPSS/OSV facts change patch priorities. Failures are logged only."""
        try:
            await rescore_vulns(self.sm, self.settings)
        except (SQLAlchemyError, ValueError, OSError) as e:
            log.warning("collect.patch_priority_failed", source=name, error=f"{type(e).__name__}: {e}"[:300])

    async def _mark_doc(self, raw_id: int | None, status: str, error: str | None, items: int) -> None:
        if raw_id is None:
            return
        async with self.sm() as s, s.begin():
            await s.execute(
                update(RawDocument)
                .where(RawDocument.id == raw_id)
                .values(parse_status=status, parse_error=error, items=items)
            )

    async def _finish(
        self,
        source_id: int,
        summary: RunSummary,
        now: datetime,
        interval: timedelta,
        *,
        health: str,
        checkpoint: dict[str, Any] | None = None,
        raw_id: int | None = None,
    ) -> None:
        jitter = timedelta(seconds=_rng.uniform(0, interval.total_seconds() * 0.05))
        values: dict[str, Any] = {
            "health": health,
            "last_run_at": now,
            "next_run_at": now + interval + jitter,
            "last_error": summary.error,
        }
        if health == "ok":
            values.update(last_success_at=now, consecutive_failures=0)
        if checkpoint is not None:
            values["checkpoint"] = checkpoint
        async with self.sm() as s, s.begin():
            await s.execute(update(Source).where(Source.id == source_id).values(**values))
            s.add(self._run_row(source_id, summary, now, raw_id))

    async def _fail(
        self,
        source_id: int,
        summary: RunSummary,
        now: datetime,
        interval: timedelta,
        min_interval: timedelta,
        drift: bool,
        raw_id: int | None,
    ) -> None:
        async with self.sm() as s, s.begin():
            src = await s.get(Source, source_id)
            if src is None:
                raise RuntimeError(f"source id {source_id} disappeared during a run")
            failures = (src.consecutive_failures or 0) + 1
            last_ok = aware(src.last_success_at)
            recent = last_ok is not None and now - last_ok < 2 * interval
            src.health = "failing" if drift or not recent else "degraded"
            src.consecutive_failures = failures
            src.last_run_at = now
            src.last_error = summary.error
            # Back off on repeated failures, never past the normal interval
            # and never faster than the source allows.
            backoff = min(interval, timedelta(minutes=5) * 2 ** (failures - 1))
            src.next_run_at = now + max(backoff, min_interval)
            s.add(self._run_row(source_id, summary, now, raw_id))

    def _run_row(
        self, source_id: int, summary: RunSummary, now: datetime, raw_id: int | None
    ) -> ConnectorRun:
        return ConnectorRun(
            source_id=source_id,
            started_at=now,
            finished_at=self.now(),
            status=summary.status,
            http_status=summary.http_status,
            raw_document_id=raw_id,
            items_total=summary.items_total,
            items_new=summary.items_new,
            items_updated=summary.items_updated,
            items_rejected=summary.items_rejected,
            items_allowlisted=summary.items_allowlisted,
            error=summary.error,
            note=summary.note,
        )

    async def _after_run(self, name: str, since: datetime) -> None:
        """Feed the knowledge graph from what this run collected. A failure
        here is logged, never turned into a failed collection run."""
        try:
            if name == "cisa_kev":
                await apply_kev(self.sm)
                await rescore_vulns(self.sm, self.settings)
            await link_source(self.sm, name, since)
        except (SQLAlchemyError, ValueError, KeyError) as e:
            log.warning("collect.link_failed", source=name, error=f"{type(e).__name__}: {e}"[:300])

    async def _run_kb(self, name: str, *, force: bool) -> RunSummary:
        started = time.perf_counter()
        cls = self.kb_registry[name]
        info = cls.info
        now = self.now()
        src = await self.source_row(name)
        if not src.enabled and not force:
            return RunSummary(name, "disabled")
        last_run = aware(src.last_run_at)
        if not force and last_run and now - last_run < info.min_interval:
            return RunSummary(
                name, "too_soon", error=f"last run {last_run.isoformat()}; minimum gap {info.min_interval}"
            )
        summary = RunSummary(name, "failed")
        try:
            source = cls(api_key=_key_for(self.settings, cls))
        except MissingKeyError as e:
            summary.status, summary.error = "skipped", str(e)
            await self._finish(src.id, summary, now, info.interval, health="skipped")
            return summary
        ctx = KbContext(
            self.sm,
            self.http,
            self.store,
            self.settings,
            now,
            src.id,
            name,
            dict(src.checkpoint or {}),
            self.sleep,
        )
        try:
            res = await source.sync(ctx)
            summary.status = res.status
            summary.http_status = res.http_status
            summary.items_total = res.items_total
            summary.items_new = res.items_new
            summary.items_updated = res.items_updated
            summary.note = res.note
            await self._finish(
                src.id, summary, now, info.interval, health="ok", checkpoint=res.checkpoint, raw_id=res.raw_id
            )
            if res.items_new or res.items_updated:
                await self._rescore_vulns(name)
        except (FetchError, BlockedAddressError, httpx.HTTPError, SchemaDriftError, OSError, ValueError) as e:
            summary.status = "failed"
            summary.error = f"{type(e).__name__}: {e}"[:1000]
            await self._fail(
                src.id, summary, now, info.interval, info.min_interval, isinstance(e, SchemaDriftError), None
            )
        finally:
            summary.duration_s = round(time.perf_counter() - started, 2)
            log.info(
                "collect.run",
                source=name,
                status=summary.status,
                total=summary.items_total,
                new=summary.items_new,
                updated=summary.items_updated,
                note=summary.note,
                error=summary.error,
                duration_s=summary.duration_s,
            )
        return summary

    # ── allowlist maintenance ───────────────────────────────────────────────

    async def replace_allowlist(self, origin: str, entries: Sequence[Entry]) -> int:
        """Replace every entry of one origin atomically."""
        async with self.sm() as s, s.begin():
            await s.execute(delete(AllowlistEntry).where(AllowlistEntry.origin == origin))
            for i in range(0, len(entries), 1000):
                s.add_all(
                    AllowlistEntry(
                        kind=e.kind, value=e.value, effect=e.effect, reason=e.reason, origin=e.origin
                    )
                    for e in entries[i : i + 1000]
                )
        return len(entries)

    async def reapply_allowlist(self) -> int:
        return await reapply_allowlist(self.sm, self.settings)


async def load_allowlist(s: AsyncSession) -> Allowlist:
    rows = (await s.scalars(select(AllowlistEntry))).all()
    return Allowlist(Entry(r.kind, r.value, r.effect, r.reason, r.origin) for r in rows)  # type: ignore[arg-type]


async def reapply_allowlist(sm: async_sessionmaker[AsyncSession], settings: Settings | None = None) -> int:
    """Re-evaluate every indicator against the current allowlist; returns how
    many changed status or labels. Runs after any allowlist change; with
    settings, the changed indicators are re-scored too."""
    changed = 0
    ids: list[int] = []
    last_id = 0
    async with sm() as s, s.begin():
        allow = await load_allowlist(s)
        while True:
            rows = (
                await s.execute(
                    select(Indicator, ObservableRow)
                    .join(ObservableRow, Indicator.observable_id == ObservableRow.id)
                    .where(Indicator.id > last_id)
                    .order_by(Indicator.id)
                    .limit(BATCH)
                )
            ).all()
            if not rows:
                break
            for ind, obs in rows:
                verdict = allow.check(Observable(IOCType(obs.type), obs.value))
                if Collector._apply_verdict(ind, verdict):
                    changed += 1
                    ids.append(ind.id)
            last_id = rows[-1][0].id
    if settings is not None and ids:
        await rescore(sm, settings, ids=ids)
    return changed
