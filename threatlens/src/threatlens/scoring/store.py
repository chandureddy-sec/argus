"""Scoring against the database: gather each indicator's signals, relevance
and penalties, score it (``scoring.model``), store the score with its
breakdown, and move indicators between ``active`` and ``expired``.

* **Signals**: one per feed sighting (``seen_at`` is when the feed last listed
  it, or when the feed says it was last online if it reports it offline), one
  per malicious/suspicious/benign finding of a stored enrichment, and one for
  an analyst's "true positive". Each carries its source's Admiralty grade,
  credibility, upstream and feedback weight factor.
* **Relevance** (PIRs and own assets): the value is an imported asset; a
  domain/URL/email contains our brand or domain name (impersonation); the
  indicator is linked to malware/tools that use a technique a PIR watches, or
  its report names one; its report names a watched sector or country.
* **Penalties**: allowlist "flag" labels (shared CDN edge, popular domain),
  and RDAP saying a domain is no longer registered.
* **Expiry**: an ``active``/``new`` indicator whose priority falls below
  ``expiry.below`` becomes ``expired``; an expired one that scores above it
  again (a feed listed it again) becomes ``active``. ``false_positive`` and
  ``revoked`` are analyst/allowlist decisions and are never changed here.
* CVE indicators (from KEV) take their priority from the patch-priority model
  and never expire: KEV is a non-decaying floor.
"""

from __future__ import annotations

import re
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from threatlens.enrich.base import parse_dt
from threatlens.ioc.normalize import registrable_domain
from threatlens.logs import get_logger
from threatlens.models import (
    Asset,
    Enrichment,
    Entity,
    Indicator,
    Relationship,
    Sighting,
    Source,
    Vulnerability,
    VulnerabilityProduct,
)
from threatlens.models import Observable as ObsRow
from threatlens.profile import ProfileError, load_pirs, load_profile
from threatlens.scoring.config import ScoringConfig, get_config
from threatlens.scoring.model import Hit, Score, Signal, SignalKind, score
from threatlens.scoring.vulns import VulnFacts, patch_priority
from threatlens.settings import Settings

log = get_logger("threatlens.scoring")

BATCH = 500
# Being listed is context, not maliciousness (a Tor exit; a custom feed an admin marked "suspicious").
SUSPICIOUS_FEED_KINDS = frozenset({"anonymizer", "custom-suspicious"})
LABEL_PENALTIES = {
    "shared-cdn": ("shared_cdn", "on a shared CDN edge range: blocking it affects many sites"),
    "popular-domain": ("popular_domain", "on a popular (Tranco top) domain"),
    "popular-domain-host": ("popular_domain", "on a popular (Tranco top) domain"),
}
ACTIVE = ("active", "new")


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _compact(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


@dataclass(frozen=True)
class SourceMeta:
    name: str
    kind: str
    grade: str
    credibility: int
    upstream: str
    factor: float


@dataclass
class Context:
    """Everything scoring needs besides the indicator itself, loaded once."""

    cfg: ScoringConfig
    sources: dict[int, SourceMeta] = field(default_factory=dict)
    by_name: dict[str, SourceMeta] = field(default_factory=dict)
    assets: set[str] = field(default_factory=set)
    brand_tokens: list[str] = field(default_factory=list)
    org_domains: set[str] = field(default_factory=set)
    techniques: dict[str, list[str]] = field(default_factory=dict)  # T-id -> PIR ids
    sectors: dict[str, list[str]] = field(default_factory=dict)  # slug -> PIR ids
    geography: dict[str, list[str]] = field(default_factory=dict)  # ISO2 -> PIR ids
    entity_techniques: dict[str, tuple[str, list[str]]] = field(default_factory=dict)  # ref -> (name, T-ids)

    def watched(self, technique: str) -> list[str]:
        t = technique.upper()
        return self.techniques.get(t) or self.techniques.get(t.split(".")[0], [])


async def load_context(s: AsyncSession, settings: Settings, cfg: ScoringConfig | None = None) -> Context:
    ctx = Context(cfg or get_config(settings.scoring_path))
    for src in (await s.scalars(select(Source))).all():
        meta = SourceMeta(
            src.name, src.kind, src.reliability, src.credibility or 6, src.upstream, src.weight_factor or 1.0
        )
        ctx.sources[src.id] = meta
        ctx.by_name[src.name] = meta
    ctx.assets = set((await s.scalars(select(Asset.canonical_key))).all())
    try:
        profile = load_profile(settings.profile_path)
        pirs = load_pirs(settings.pirs_path, profile)
    except (ProfileError, OSError) as e:
        log.warning("scoring.no_profile", error=str(e)[:200])
        return ctx
    org = profile.org
    ctx.org_domains = {registrable_domain(d) for d in org.domains}
    tokens = [_compact(b) for b in org.brands] + [_compact(d.split(".")[0]) for d in ctx.org_domains]
    ctx.brand_tokens = sorted({t for t in tokens if len(t) >= 4})
    for p in pirs.pirs:
        for t in p.watch.techniques:
            ctx.techniques.setdefault(t.upper(), []).append(p.id)
        for sec in p.watch.sectors:
            ctx.sectors.setdefault(sec, []).append(p.id)
        for g in p.watch.geography:
            ctx.geography.setdefault(g, []).append(p.id)
    if ctx.techniques:
        rows = (
            await s.execute(
                select(Relationship.src_ref, Entity.external_id)
                .join(Entity, Entity.stix_id == Relationship.dst_ref)
                .where(
                    Relationship.rel_type == "uses",
                    Relationship.revoked.is_(False),
                    Entity.type == "attack-pattern",
                    or_(
                        *(Entity.external_id == t for t in ctx.techniques),
                        *(Entity.external_id.like(f"{t}.%") for t in ctx.techniques),
                    ),
                )
            )
        ).all()
        users: dict[str, list[str]] = {}
        for ref, ext in rows:
            if ext:
                users.setdefault(ref, []).append(ext)
        if users:
            names = dict(
                (await s.execute(select(Entity.stix_id, Entity.name).where(Entity.stix_id.in_(users)))).all()
            )
            ctx.entity_techniques = {r: (names.get(r, r), sorted(set(t))) for r, t in users.items()}
    return ctx


# ── signals ──────────────────────────────────────────────────────────────────


def _offline_since(context: dict[str, Any] | None) -> datetime | None:
    c = context or {}
    if str(c.get("url_status") or c.get("status") or "").lower() != "offline":
        return None
    return parse_dt(c.get("last_online"))


def sighting_signal(
    meta: SourceMeta, confidence: int, last_seen: datetime, context: dict[str, Any] | None
) -> Signal:
    seen = _aware(last_seen)
    text = f"listed by {meta.name}"
    off = _offline_since(context)
    if off is not None and off < seen:
        seen, text = off, f"listed by {meta.name}; offline since {off.date()}"
    kind: SignalKind = "suspicious" if meta.kind in SUSPICIOUS_FEED_KINDS else "malicious"
    return Signal(
        meta.name, meta.upstream, meta.grade, kind, confidence, seen, meta.credibility, meta.factor, text
    )


def evidence_signals(
    evidence: Iterable[dict[str, Any]], seen_at: datetime, by_name: dict[str, SourceMeta]
) -> list[Signal]:
    out = []
    for e in evidence:
        kind = e.get("kind")
        meta = by_name.get(str(e.get("source")))
        if kind not in ("malicious", "suspicious", "benign") or meta is None:
            continue
        out.append(
            Signal(
                meta.name, meta.upstream, meta.grade, kind, int(e.get("weight") or 0), _aware(seen_at),
                meta.credibility, meta.factor, str(e.get("text") or "")[:200],
            )
        )  # fmt: skip
    return out


def analyst_signal(cfg: ScoringConfig, who: str | None, at: datetime | None) -> Signal:
    return Signal(
        "analyst", "analyst", "A", "malicious", cfg.feedback.analyst_confidence,
        _aware(at or datetime.now(UTC)), 1, 1.0, f"confirmed malicious by {who or 'an analyst'}",
    )  # fmt: skip


# ── relevance and penalties ──────────────────────────────────────────────────


def _host(obs_type: str, value: str) -> str | None:
    if obs_type == "domain-name":
        return value
    if obs_type == "url":
        return urlsplit(value).hostname
    if obs_type == "email-addr" and "@" in value:
        return value.rsplit("@", 1)[1]
    return None


def relevance_hits(
    ctx: Context,
    obs_type: str,
    value: str,
    key: str,
    contexts: Iterable[dict[str, Any]] = (),
    linked: Iterable[str] = (),
    labels: Iterable[str] = (),
) -> list[Hit]:
    rc = ctx.cfg.relevance
    hits: list[Hit] = []
    if key in ctx.assets:
        hits.append(Hit("own_asset", rc.own_asset, "one of our assets (imported from ReconX)"))
    host = _host(obs_type, value)
    if host and ctx.brand_tokens and registrable_domain(host) not in ctx.org_domains:
        compact = _compact(host)
        found = [t for t in ctx.brand_tokens if t in compact]
        if found:
            hits.append(
                Hit("impersonation", rc.impersonation, f"contains our name ({found[0]}): PIR-3 style")
            )
    techs: dict[str, str] = {}
    for ref in linked:
        name, ts = ctx.entity_techniques.get(ref, ("", []))
        for t in ts:
            techs.setdefault(t, f"{name} uses {t}")
    ctx_list = list(contexts)
    for c in ctx_list:
        for t in c.get("attack_ids") or []:
            if isinstance(t, str) and ctx.watched(t):
                techs.setdefault(t.upper(), f"report names {t.upper()}")
    watched_t = [(t, why) for t, why in techs.items() if ctx.watched(t)]
    if watched_t:
        t, why = sorted(watched_t)[0]
        hits.append(Hit("technique", rc.technique, f"{why} ({', '.join(ctx.watched(t))})"))
    words = {_slug(str(x)) for c in ctx_list for x in (c.get("industries") or []) if isinstance(x, str)}
    words |= {_slug(x) for x in labels}
    sec = sorted(w for w in words if w in ctx.sectors)
    if sec:
        hits.append(Hit("sector", rc.sector, f"names sector {sec[0]} ({', '.join(ctx.sectors[sec[0]])})"))
    countries = {
        str(x).upper() for c in ctx_list for x in (c.get("targeted_countries") or []) if isinstance(x, str)
    }
    geo = sorted(g for g in countries if g in ctx.geography)
    if geo:
        hits.append(Hit("geography", rc.geography, f"targets {geo[0]} ({', '.join(ctx.geography[geo[0]])})"))
    return hits


def penalty_hits(ctx: Context, labels: Iterable[str], dead_domain: bool = False) -> list[Hit]:
    pc = ctx.cfg.penalties
    out: dict[str, Hit] = {}
    for lb in labels:
        if lb in LABEL_PENALTIES:
            kind, why = LABEL_PENALTIES[lb]
            out.setdefault(kind, Hit(kind, getattr(pc, kind), why))
    if dead_domain:
        out["dead_domain"] = Hit("dead_domain", pc.dead_domain, "RDAP: the domain is no longer registered")
    return list(out.values())


# ── indicators ───────────────────────────────────────────────────────────────


@dataclass
class RescoreResult:
    scored: int = 0
    expired: int = 0
    reactivated: int = 0
    seconds: float = 0.0


def _suppressed(ind: Indicator) -> str | None:
    if ind.status != "false_positive":
        return None
    if ind.analyst_verdict == "fp":
        return f"marked false positive by {ind.analyst_verdict_by or 'an analyst'}"
    return ind.allowlist_reason or "allowlisted"


async def _patch_scores(s: AsyncSession, cves: list[str]) -> dict[str, Vulnerability]:
    if not cves:
        return {}
    rows = (await s.scalars(select(Vulnerability).where(Vulnerability.cve_id.in_(cves)))).all()
    return {v.cve_id: v for v in rows}


async def rescore(
    sm: async_sessionmaker[AsyncSession],
    settings: Settings,
    *,
    ids: Sequence[int] | None = None,
    now: datetime | None = None,
    ctx: Context | None = None,
) -> RescoreResult:
    """Score indicators (all, or ``ids``), store each breakdown, apply expiry."""
    started = time.perf_counter()
    now = now or datetime.now(UTC)
    res = RescoreResult()
    async with sm() as s:
        ctx = ctx or await load_context(s, settings)
    wanted = sorted(set(ids)) if ids is not None else None
    last = 0
    while True:
        async with sm() as s, s.begin():
            stmt = select(Indicator, ObsRow).join(ObsRow, ObsRow.id == Indicator.observable_id)
            if wanted is not None:
                chunk = [i for i in wanted if i > last][:BATCH]
                if not chunk:
                    break
                stmt = stmt.where(Indicator.id.in_(chunk))
            else:
                stmt = stmt.where(Indicator.id > last)
            rows = (await s.execute(stmt.order_by(Indicator.id).limit(BATCH))).all()
            if not rows:
                break
            last = rows[-1][0].id
            await _score_batch(s, ctx, rows, now, res)
    res.seconds = round(time.perf_counter() - started, 2)
    log.info("scoring.rescore", scored=res.scored, expired=res.expired, reactivated=res.reactivated,
             seconds=res.seconds, config=ctx.cfg.tag)  # fmt: skip
    return res


async def _score_batch(
    s: AsyncSession, ctx: Context, rows: Sequence[Any], now: datetime, res: RescoreResult
) -> None:
    ids = [ind.id for ind, _ in rows]
    keys = [obs.canonical_key for _, obs in rows]
    sightings: dict[int, list[Sighting]] = {}
    for sg in (await s.scalars(select(Sighting).where(Sighting.indicator_id.in_(ids)))).all():
        sightings.setdefault(sg.indicator_id, []).append(sg)
    enrich: dict[str, list[Enrichment]] = {}
    for e in (await s.scalars(select(Enrichment).where(Enrichment.canonical_key.in_(keys)))).all():
        enrich.setdefault(e.canonical_key, []).append(e)
    linked: dict[str, list[str]] = {}
    refs = [ind.stix_id for ind, _ in rows if ind.stix_id]
    if ctx.entity_techniques and refs:
        for src_ref, dst_ref in (
            await s.execute(
                select(Relationship.src_ref, Relationship.dst_ref).where(
                    Relationship.src_ref.in_(refs),
                    Relationship.dst_ref.in_(list(ctx.entity_techniques)),
                    Relationship.revoked.is_(False),
                )
            )
        ).all():
            linked.setdefault(src_ref, []).append(dst_ref)
    vulns = await _patch_scores(s, [obs.value.upper() for _, obs in rows if obs.type == "vulnerability"])
    for ind, obs in rows:
        if obs.type == "vulnerability":
            v = vulns.get(obs.value.upper())
            ind.priority_score = min(100.0, v.patch_score) if v and v.patch_score is not None else None
            ind.score_breakdown = {
                "model": "patch-priority",
                "priority": v.patch_priority if v else None,
                "note": "CVE: scored by patch priority; KEV entries never expire",
            }
            ind.valid_until = None
            res.scored += 1
            continue
        sc = indicator_score(ctx, ind, obs, sightings.get(ind.id, []), enrich.get(obs.canonical_key, []),
                             linked.get(ind.stix_id or "", []), now)  # fmt: skip
        ind.priority_score = sc.priority
        ind.score_breakdown = sc.breakdown
        ind.valid_until = sc.valid_until
        res.scored += 1
        if ind.status in ACTIVE and sc.priority < ctx.cfg.expiry.below:
            ind.status = "expired"
            res.expired += 1
        elif ind.status == "expired" and sc.priority >= ctx.cfg.expiry.below:
            ind.status = "active"
            res.reactivated += 1


def indicator_score(
    ctx: Context,
    ind: Indicator,
    obs: ObsRow,
    sightings: Sequence[Sighting],
    enrichments: Sequence[Enrichment],
    linked: Sequence[str],
    now: datetime,
) -> Score:
    signals: list[Signal] = []
    for sg in sightings:
        meta = ctx.sources.get(sg.source_id)
        if meta is not None:
            signals.append(sighting_signal(meta, sg.confidence, sg.last_seen, sg.context))
    dead = False
    for e in enrichments:
        if e.status == "ok":
            signals += evidence_signals(e.evidence or [], e.fetched_at, ctx.by_name)
        elif e.enricher == "rdap" and obs.type == "domain-name":
            dead = True
    if ind.analyst_verdict == "tp":
        signals.append(analyst_signal(ctx.cfg, ind.analyst_verdict_by, ind.analyst_verdict_at))
    labels = ind.labels or []
    return score(
        signals,
        obs_type=obs.type,
        now=now,
        cfg=ctx.cfg,
        relevance=relevance_hits(
            ctx,
            obs.type,
            obs.value,
            obs.canonical_key,
            [sg.context or {} for sg in sightings],
            linked,
            labels,
        ),
        penalties=penalty_hits(ctx, labels, dead),
        suppressed=_suppressed(ind),
    )


# ── vulnerabilities ──────────────────────────────────────────────────────────


async def rescore_vulns(
    sm: async_sessionmaker[AsyncSession], settings: Settings, *, cfg: ScoringConfig | None = None
) -> int:
    """Patch priority for every vulnerability; returns how many were scored."""
    from threatlens.assets import observed_stack, org_stack  # assets imports scoring users; avoid a cycle

    cfg = cfg or get_config(settings.scoring_path)
    async with sm() as s:
        stack = {(v, p) for _, v, p in await org_stack(s, settings)}
        observed = {(v, p) for _, v, p in await observed_stack(s)}
    done, last = 0, 0
    while True:
        async with sm() as s, s.begin():
            vulns = (
                await s.scalars(
                    select(Vulnerability)
                    .where(Vulnerability.id > last)
                    .order_by(Vulnerability.id)
                    .limit(BATCH)
                )
            ).all()
            if not vulns:
                break
            last = vulns[-1].id
            prods: dict[int, set[tuple[str, str]]] = {}
            for vid, vendor, product in (
                await s.execute(
                    select(
                        VulnerabilityProduct.vulnerability_id,
                        VulnerabilityProduct.vendor,
                        VulnerabilityProduct.product,
                    ).where(VulnerabilityProduct.vulnerability_id.in_([v.id for v in vulns]))
                )
            ).all():
                prods.setdefault(vid, set()).add((vendor, product))
            for v in vulns:
                mine = prods.get(v.id, set())
                pp = patch_priority(
                    VulnFacts(
                        v.cve_id, v.kev, v.kev_ransomware, (v.ssvc or {}).get("exploitation"),
                        len(v.exploit_refs or []), v.epss_percentile, v.cvss_score,
                    ),
                    in_stack=[f"{a}:{b}" for a, b in sorted(mine & stack)],
                    exposed=[f"{a}:{b}" for a, b in sorted(mine & observed)],
                    cfg=cfg,
                )  # fmt: skip
                v.patch_priority, v.patch_score, v.patch_breakdown = pp["priority"], pp["score"], pp
                done += 1
    return done
