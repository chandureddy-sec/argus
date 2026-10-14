"""Read-side queries for the analyst UI (dashboard aggregates and page data).

Everything is computed from stored data; nothing is estimated or invented.
Every indicator figure respects the viewer's TLP clearance (ADR 0008).
"""

from __future__ import annotations

import calendar as cal
import math
from collections import Counter, defaultdict
from datetime import UTC, date, datetime, time, timedelta
from typing import Any
from urllib.parse import quote

from sqlalchemy import String, and_, case, cast, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from threatlens import tlp as tlp_rules
from threatlens.models import (
    Case,
    ConnectorRun,
    Enrichment,
    Entity,
    Indicator,
    Observable,
    Relationship,
    Sighting,
    Source,
    Vulnerability,
    VulnerabilityProduct,
)
from threatlens.profile import ProfileError, load_pirs, load_profile
from threatlens.settings import Settings

# Enterprise matrix order (TA0112 "Defense Impairment" and TA0005 "Stealth" are ATT&CK v19 tactics).
TACTIC_ORDER = [
    "TA0043", "TA0042", "TA0001", "TA0002", "TA0003", "TA0004", "TA0005", "TA0112",
    "TA0006", "TA0007", "TA0008", "TA0009", "TA0011", "TA0010", "TA0040",
]  # fmt: skip
TYPE_LABELS = {
    "ipv4-addr": "IPv4",
    "ipv6-addr": "IPv6",
    "ipv4-net": "IPv4 range",
    "ipv6-net": "IPv6 range",
    "domain-name": "Domain",
    "url": "URL",
    "email-addr": "Email",
    "file-md5": "MD5",
    "file-sha1": "SHA-1",
    "file-sha256": "SHA-256",
    "vulnerability": "CVE",
}


def aware(dt: datetime | None) -> datetime | None:
    return dt.replace(tzinfo=UTC) if dt is not None and dt.tzinfo is None else dt


async def _count(s: AsyncSession, stmt: Any) -> int:
    return int(await s.scalar(select(func.count()).select_from(stmt.subquery())) or 0)


async def stack_cve_ids(s: AsyncSession, stack: list[tuple[str, str]]) -> set[int]:
    if not stack:
        return set()
    cond = or_(*(and_(VulnerabilityProduct.vendor == v, VulnerabilityProduct.product == p) for v, p in stack))
    return set((await s.scalars(select(VulnerabilityProduct.vulnerability_id).where(cond))).all())


# ── dashboard ────────────────────────────────────────────────────────────────


def _buckets(
    now: datetime, runs: list[tuple[datetime, int, int]]
) -> tuple[list[tuple[str, float]], list[tuple[str, float]], str]:
    """Collected / new items per bucket: hourly over 48 h while history is
    short, daily over 30 days once there is more than three days of runs."""
    first = min((aware(r[0]) or now for r in runs), default=now)
    hourly = now - first <= timedelta(days=3)
    n, width = (48, timedelta(hours=1)) if hourly else (30, timedelta(days=1))
    start = (
        now.replace(minute=0, second=0, microsecond=0)
        if hourly
        else now.replace(hour=0, minute=0, second=0, microsecond=0)
    ) - width * (n - 1)
    total = [0.0] * n
    new = [0.0] * n
    for started, items, items_new in runs:
        i = int(((aware(started) or now) - start) / width)
        if 0 <= i < n:
            total[i] += items
            new[i] += items_new
    fmt = "%H:%M" if hourly else "%d %b"
    labels = [(start + width * i).strftime(fmt) for i in range(n)]
    return (
        list(zip(labels, total, strict=True)),
        list(zip(labels, new, strict=True)),
        "last 48 hours" if hourly else "last 30 days",
    )


async def overview(
    s: AsyncSession,
    now: datetime,
    stack: list[tuple[str, str]],
    clearance: str,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Dashboard figures. Indicators above the viewer's TLP clearance are left
    out of every count, list and map (ADR 0008)."""
    day_ago = now - timedelta(hours=24)
    vis = Indicator.tlp.in_(tlp_rules.readable(clearance))
    active = (
        await s.scalar(select(func.count()).select_from(Indicator).where(Indicator.status == "active", vis))
        or 0
    )
    new_24h = (
        await s.scalar(
            select(func.count()).select_from(Indicator).where(Indicator.created_at >= day_ago, vis)
        )
        or 0
    )
    kev = (
        await s.scalar(select(func.count()).select_from(Vulnerability).where(Vulnerability.kev.is_(True)))
        or 0
    )
    kev_30d = (
        await s.scalar(
            select(func.count())
            .select_from(Vulnerability)
            .where(Vulnerability.kev_date_added >= (now - timedelta(days=30)).date())
        )
        or 0
    )
    stack_ids = await stack_cve_ids(s, stack)
    stack_kev = (
        await s.scalar(
            select(func.count())
            .select_from(Vulnerability)
            .where(Vulnerability.id.in_(stack_ids), Vulnerability.kev.is_(True))
        )
        if stack_ids
        else 0
    ) or 0

    # Malware families that feed indicators point at, and their techniques.
    fam_rows = (
        await s.execute(
            select(Relationship.dst_ref, func.count(func.distinct(Relationship.src_ref)))
            .join(Indicator, Indicator.stix_id == Relationship.src_ref)
            .where(Relationship.origin == "feed", Relationship.rel_type == "indicates", vis)
            .group_by(Relationship.dst_ref)
        )
    ).all()
    fam_counts = {ref: int(n) for ref, n in fam_rows}
    fam_ents = (
        {
            e.stix_id: e
            for e in (
                await s.scalars(
                    select(Entity).where(
                        Entity.stix_id.in_(list(fam_counts)),
                        Entity.type.in_(("malware", "tool", "intrusion-set")),
                    )
                )
            ).all()
        }
        if fam_counts
        else {}
    )
    families = sorted(
        ((fam_ents[r].name, n, r, fam_ents[r].external_id) for r, n in fam_counts.items() if r in fam_ents),
        key=lambda x: -x[1],
    )
    tech_counts: Counter[str] = Counter()
    if fam_ents:
        for _src, dst in (
            await s.execute(
                select(Relationship.src_ref, Relationship.dst_ref).where(
                    Relationship.src_ref.in_(list(fam_ents)),
                    Relationship.rel_type == "uses",
                    Relationship.dst_ref.like("attack-pattern--%"),
                    Relationship.revoked.is_(False),
                )
            )
        ).all():
            tech_counts[dst] += 1
    tech_ents = (
        {
            e.stix_id: e
            for e in (await s.scalars(select(Entity).where(Entity.stix_id.in_(list(tech_counts))))).all()
        }
        if tech_counts
        else {}
    )
    techniques = [
        (f"{tech_ents[r].external_id} {tech_ents[r].name}", n, tech_ents[r].external_id)
        for r, n in tech_counts.most_common(6)
        if r in tech_ents
    ]

    sources = (await s.scalars(select(Source).order_by(Source.name))).all()
    healthy = sum(1 for x in sources if x.enabled and x.health == "ok")
    enabled = sum(1 for x in sources if x.enabled and x.health != "skipped")

    runs = (
        await s.execute(
            select(ConnectorRun.started_at, ConnectorRun.items_total, ConnectorRun.items_new).where(
                ConnectorRun.started_at >= now - timedelta(days=31)
            )
        )
    ).all()
    collected, new_items, window = _buckets(now, [(r[0], r[1] or 0, r[2] or 0) for r in runs])

    months = []
    first_month = date(now.year - 2, now.month, 1)
    kev_rows = (
        await s.execute(
            select(Vulnerability.kev_date_added).where(
                Vulnerability.kev.is_(True), Vulnerability.kev_date_added >= first_month
            )
        )
    ).all()
    per_month: Counter[str] = Counter(d.strftime("%Y-%m") for (d,) in kev_rows if d)
    y, m = first_month.year, first_month.month
    for _ in range(25):
        key = f"{y:04d}-{m:02d}"
        months.append((date(y, m, 1).strftime("%b %y"), float(per_month.get(key, 0))))
        m += 1
        if m == 13:
            y, m = y + 1, 1

    types = (
        await s.execute(
            select(Observable.type, func.count())
            .join(Indicator, Indicator.observable_id == Observable.id)
            .where(Indicator.status == "active", vis)
            .group_by(Observable.type)
            .order_by(func.count().desc())
        )
    ).all()

    band = case(
        (Indicator.priority_score >= 60, "malicious (60+)"),
        (Indicator.priority_score >= 30, "suspicious (30-59)"),
        else_="low (under 30)",
    )
    prio_map: dict[str, int] = {
        str(b): int(n)
        for b, n in (
            await s.execute(
                select(band, func.count()).where(Indicator.status == "active", vis).group_by(band)
            )
        ).all()
    }
    top = (
        await s.execute(
            select(Indicator.id, Observable.type, Observable.defanged, Indicator.priority_score)
            .join(Observable, Observable.id == Indicator.observable_id)
            .where(Indicator.status == "active", vis, Indicator.priority_score.is_not(None),
                   Observable.type != "vulnerability")
            .order_by(Indicator.priority_score.desc(), Indicator.id.desc())
            .limit(8)
        )
    ).all()  # fmt: skip
    by_source = (
        await s.execute(
            select(Source.name, func.count(func.distinct(Sighting.indicator_id)))
            .join(Sighting, Sighting.source_id == Source.id)
            .join(Indicator, Indicator.id == Sighting.indicator_id)
            .where(vis)
            .group_by(Source.name)
            .order_by(func.count(func.distinct(Sighting.indicator_id)).desc())
            .limit(6)
        )
    ).all()
    status_rows = dict(
        (await s.execute(select(Indicator.status, func.count()).where(vis).group_by(Indicator.status))).all()
    )

    # Location: RIPEstat (GeoLite2) enrichment where an IP has it, else the
    # country a feed reported (Feodo Tracker); each IP counts once.
    feed_country = Sighting.context["country"].as_string()
    located: dict[str, str] = {
        str(k): str(c)
        for k, c in (
            await s.execute(
                select(Observable.canonical_key, feed_country)
                .join(Indicator, Indicator.observable_id == Observable.id)
                .join(Sighting, Sighting.indicator_id == Indicator.id)
                .where(feed_country.is_not(None), vis)
            )
        ).all()
        if c
    }
    enriched_country = Enrichment.summary["country"].as_string()
    for k, c in (
        await s.execute(
            select(Enrichment.canonical_key, enriched_country).where(
                Enrichment.enricher == "ripestat", Enrichment.status == "ok", enriched_country.is_not(None)
            )
        )
    ).all():
        if c:
            located[str(k)] = str(c)
    hidden = set(
        (
            await s.scalars(
                select(Observable.canonical_key)
                .join(Indicator, Indicator.observable_id == Observable.id)
                .where(~vis)
            )
        ).all()
    )
    geo: dict[str, int] = {}
    located = {k: c for k, c in located.items() if k not in hidden}
    for c in located.values():
        geo[c] = geo.get(c, 0) + 1
    ips = (
        await s.scalar(
            select(func.count())
            .select_from(Observable)
            .where(Observable.type.in_(("ipv4-addr", "ipv6-addr")))
        )
        or 0
    )

    kev_latest = (
        await s.scalars(
            select(Vulnerability)
            .where(Vulnerability.kev.is_(True))
            .order_by(Vulnerability.kev_date_added.desc().nulls_last(), Vulnerability.cve_id.desc())
            .limit(8)
        )
    ).all()
    kev_stack = (
        (
            await s.scalars(
                select(Vulnerability)
                .where(Vulnerability.id.in_(stack_ids), Vulnerability.kev.is_(True))
                .order_by(Vulnerability.kev_date_added.desc().nulls_last())
                .limit(8)
            )
        ).all()
        if stack_ids
        else []
    )
    shown = [v.id for v in (*kev_latest, *kev_stack)]
    products: dict[int, str] = {}
    for vid, vendor, product in (
        await s.execute(
            select(
                VulnerabilityProduct.vulnerability_id,
                VulnerabilityProduct.vendor,
                VulnerabilityProduct.product,
            )
            .where(VulnerabilityProduct.vulnerability_id.in_(shown))
            .order_by(VulnerabilityProduct.id)
        )
    ).all():
        products.setdefault(vid, f"{vendor} {product}".replace("_", " "))

    runs_by_name = await last_runs(s)

    # ── Phase 5 panels ──────────────────────────────────────────────────────
    new_high = (
        await s.scalar(
            select(func.count())
            .select_from(Indicator)
            .where(Indicator.created_at >= day_ago, Indicator.priority_score >= 60, vis)
        )
        or 0
    )
    queue = await priority_queue(s, clearance)
    feed_rates = await feed_success(s, now)
    tactic_rows = await _tactic_counts(s, list(tech_ents.values()))
    patch_rows = dict(
        (
            await s.execute(
                select(Vulnerability.patch_priority, func.count()).group_by(Vulnerability.patch_priority)
            )
        ).all()
    )
    p1_stack = (
        await s.scalars(
            select(Vulnerability)
            .where(
                Vulnerability.patch_priority == "P1",
                cast(Vulnerability.patch_breakdown, String).like("%affects our stack%"),
            )
            .order_by(Vulnerability.patch_score.desc(), Vulnerability.kev_date_added.desc().nulls_last())
            .limit(5)
        )
    ).all()
    pirs = await pir_status(s, settings, vis, stack_kev, len(p1_stack))

    return {
        "kpis": [
            {
                "value": active,
                "label": "Active indicators",
                "sub": f"+{new_24h:,} in the last 24 h",
                "tone": "orange",
                "href": "/indicators",
            },
            {
                "value": kev,
                "label": "Known exploited CVEs",
                "sub": f"{kev_30d} added in 30 days",
                "tone": "yellow",
                "href": "/vulnerabilities?kev=true",
            },
            {
                "value": stack_kev,
                "label": "Exploited in our stack",
                "sub": f"of {len(stack_ids):,} CVEs matching the tech stack",
                "tone": "cyan",
                "href": "/vulnerabilities?kev=true&stack=true",
            },
            {
                "value": len(families),
                "label": "Malware families seen",
                "sub": "named by feed indicators",
                "tone": "pink",
                "href": "/attack",
            },
            {
                "value": healthy,
                "label": "Healthy sources",
                "sub": f"of {enabled} collecting",
                "tone": "purple",
                "href": "/feeds",
            },
        ],
        "collected": collected,
        "new_items": new_items,
        "window": window,
        "kev_months": months,
        "types": [(TYPE_LABELS.get(t, t), int(n), f"/indicators?type={t}") for t, n in types],
        "priority": [
            (b, int(prio_map.get(b, 0))) for b in ("malicious (60+)", "suspicious (30-59)", "low (under 30)")
        ],
        "top": [(i, TYPE_LABELS.get(t, t), v, p) for i, t, v, p in top],
        "by_source": [(n, int(c)) for n, c in by_source],
        "status": {k: int(v) for k, v in status_rows.items()},
        "families": [(name, n, f"/entities/{ext or ref}") for name, n, ref, ext in families[:6]],
        "techniques": [(label, n, f"/entities/{ext}") for label, n, ext in techniques],
        "geo": geo,
        "geo_located": sum(geo.values()),
        "ips": int(ips),
        "kev_latest": kev_latest,
        "kev_stack": kev_stack,
        "products": products,
        "stack_ids": stack_ids,
        "sources": sources,
        "last_runs": {x.id: runs_by_name[x.name] for x in sources if x.name in runs_by_name},
        "stack": stack,
        "active": int(active),
        "new_24h": int(new_24h),
        "new_high": int(new_high),
        "queue": queue,
        "feed_rates": feed_rates,
        "tactics": tactic_rows,
        "patch": [(t, int(patch_rows.get(t, 0) or 0)) for t in ("P1", "P2", "P3", "P4")],
        "p1_stack": p1_stack,
        "pirs": pirs,
        "stack_kev": int(stack_kev),
        "families_all": [(name, n) for name, n, _, _ in families],
        "healthy": healthy,
        "collecting": enabled,
        "unhealthy": [x for x in sources if x.enabled and x.health not in ("ok",) and x.kind != "enricher"],
    }


async def last_runs(s: AsyncSession) -> dict[str, ConnectorRun]:
    """The most recent run of each source, by source name."""
    latest = (
        select(ConnectorRun.source_id, func.max(ConnectorRun.id).label("id"))
        .group_by(ConnectorRun.source_id)
        .subquery()
    )
    rows = (
        await s.execute(
            select(Source.name, ConnectorRun)
            .join(latest, latest.c.source_id == Source.id)
            .join(ConnectorRun, ConnectorRun.id == latest.c.id)
        )
    ).all()
    return {str(name): run for name, run in rows}


# ── ATT&CK matrix ────────────────────────────────────────────────────────────


async def attack_matrix(s: AsyncSession, family_refs: list[str] | None = None) -> dict[str, Any]:
    """Enterprise tactics x techniques, shaded by how many malware families
    seen in feeds use each technique (sub-techniques roll up to parents)."""
    tactics = {
        e.external_id: e
        for e in (
            await s.scalars(select(Entity).where(Entity.type == "x-mitre-tactic", Entity.revoked.is_(False)))
        ).all()
        if e.external_id and "enterprise-attack" in (e.domains or [])
    }
    order = [t for t in TACTIC_ORDER if t in tactics] + sorted(t for t in tactics if t not in TACTIC_ORDER)
    techs = (
        await s.scalars(
            select(Entity).where(
                Entity.type == "attack-pattern",
                Entity.revoked.is_(False),
                Entity.deprecated.is_(False),
                Entity.is_subtechnique.is_(False),
            )
        )
    ).all()
    techs = [t for t in techs if "enterprise-attack" in (t.domains or [])]
    if family_refs is None:
        family_refs = list(
            (
                await s.scalars(
                    select(func.distinct(Relationship.dst_ref)).where(
                        Relationship.origin == "feed", Relationship.rel_type == "indicates"
                    )
                )
            ).all()
        )
    users: defaultdict[str, set[str]] = defaultdict(set)
    if family_refs:
        rows = (
            await s.execute(
                select(Relationship.src_ref, Relationship.dst_ref).where(
                    Relationship.src_ref.in_(family_refs),
                    Relationship.rel_type == "uses",
                    Relationship.dst_ref.like("attack-pattern--%"),
                    Relationship.revoked.is_(False),
                )
            )
        ).all()
        sub_parent = {
            str(src): str(dst)
            for src, dst in (
                await s.execute(
                    select(Relationship.src_ref, Relationship.dst_ref).where(
                        Relationship.rel_type == "subtechnique-of"
                    )
                )
            ).all()
        }
        for fam, tech in rows:
            users[sub_parent.get(tech, tech)].add(fam)
    shortnames = {tid: (tactics[tid].aliases or [""])[0] for tid in order}
    columns: list[dict[str, Any]] = []
    for tid in order:
        short = shortnames[tid]
        cells = sorted(
            ((t, len(users.get(t.stix_id, ()))) for t in techs if short in (t.tactics or [])),
            key=lambda x: (-x[1], x[0].name),
        )
        columns.append({"tactic": tactics[tid], "cells": cells, "hits": sum(1 for _, n in cells if n)})
    peak = max((n for c in columns for _, n in c["cells"]), default=0)
    return {"columns": columns, "peak": peak, "families": len(family_refs)}


# ── Phase 5 dashboard helpers ────────────────────────────────────────────────

ACTIONS = {"malicious": "block", "suspicious": "investigate", "benign": "no_action", "unknown": "monitor"}


def why(breakdown: dict[str, Any] | None) -> str:
    """One line on what drives a score, from its stored breakdown."""
    if not breakdown or breakdown.get("model") != "v1":
        return ""
    if breakdown.get("suppressed"):
        return str(breakdown["suppressed"])
    parts = []
    base = breakdown.get("base") or {}
    sigs = breakdown.get("signals") or []
    top = sigs[0] if sigs else {}
    if base.get("source"):
        parts.append(str(top.get("text") or f"listed by {base['source']}"))
    corr = breakdown.get("corroboration") or {}
    if corr.get("upstreams"):
        parts.append("also " + ", ".join(corr["upstreams"]))
    rel = breakdown.get("relevance") or {}
    if rel.get("applied") and rel.get("hits"):
        parts.append(f"+{rel['value']:g} " + ", ".join(h["kind"].replace("_", " ") for h in rel["hits"]))
    pen = breakdown.get("penalty") or {}
    if pen.get("items"):
        parts.append(f"-{pen['value']:g} " + ", ".join(h["kind"].replace("_", " ") for h in pen["items"]))
    return " · ".join(parts)


async def priority_queue(s: AsyncSession, clearance: str, limit: int = 8) -> list[dict[str, Any]]:
    """The highest-priority active indicators, at most two per (type, source)
    so one bulk feed doesn't fill the whole queue."""
    rows = (
        await s.execute(
            select(Indicator, Observable)
            .join(Observable, Observable.id == Indicator.observable_id)
            .where(
                Indicator.status == "active",
                Indicator.priority_score.is_not(None),
                Observable.type != "vulnerability",
                Indicator.tlp.in_(tlp_rules.readable(clearance)),
            )
            .order_by(Indicator.priority_score.desc(), Observable.last_seen.desc())
            .limit(400)
        )
    ).all()
    seen: Counter[tuple[str, str]] = Counter()
    out: list[dict[str, Any]] = []
    for ind, obs in rows:
        bd = ind.score_breakdown or {}
        src = str((bd.get("base") or {}).get("source") or "")
        if seen[(obs.type, src)] >= 2:
            continue
        seen[(obs.type, src)] += 1
        verdict = str(bd.get("verdict") or "unknown")
        out.append(
            {
                "id": ind.id,
                "type": TYPE_LABELS.get(obs.type, obs.type),
                "value": obs.defanged,
                "score": ind.priority_score or 0.0,
                "verdict": verdict,
                "action": ACTIONS.get(verdict, "monitor"),
                "source": src,
                "why": why(bd),
                "last_seen": aware(obs.last_seen),
            }
        )
        if len(out) >= limit:
            break
    return out


async def feed_success(s: AsyncSession, now: datetime, days: int = 7) -> list[dict[str, Any]]:
    """Per collecting source: share of runs in the last ``days`` that worked."""
    ok = ("success", "not_modified", "unchanged")
    rows = (
        await s.execute(
            select(Source.name, Source.health, Source.kind, ConnectorRun.status, func.count())
            .join(ConnectorRun, ConnectorRun.source_id == Source.id)
            .where(ConnectorRun.started_at >= now - timedelta(days=days), Source.kind != "enricher")
            .group_by(Source.name, Source.health, Source.kind, ConnectorRun.status)
        )
    ).all()
    agg: dict[str, dict[str, Any]] = {}
    for name, health, kind, status, n in rows:
        a = agg.setdefault(name, {"name": name, "health": health, "kind": kind, "ok": 0, "runs": 0})
        a["runs"] += int(n)
        if status in ok:
            a["ok"] += int(n)
    out = []
    for a in sorted(agg.values(), key=lambda x: x["name"]):
        pct = 100 * a["ok"] / a["runs"] if a["runs"] else 0.0
        out.append({**a, "pct": pct, "palette": "lime" if pct >= 90 else "amber" if pct >= 50 else "pink"})
    return out


async def activity(s: AsyncSession, now: datetime, clearance: str, limit: int = 6) -> list[dict[str, Any]]:
    """What happened in the last 7 days, newest first: cases opened and closed
    (within the viewer's clearance), each feed's latest run that brought new
    indicators or failed, and CISA KEV additions."""
    since = now - timedelta(days=7)
    events: list[dict[str, Any]] = []
    for c in (
        await s.scalars(
            select(Case)
            .where(
                Case.tlp.in_(tlp_rules.readable(clearance)),
                or_(Case.created_at >= since, Case.closed_at >= since),
            )
            .order_by(Case.updated_at.desc())
            .limit(limit)
        )
    ).all():
        href, meta = f"/cases/{c.id}", f"{c.severity} · {c.tlp}"
        if (opened := aware(c.created_at)) and opened >= since:
            events.append({"at": opened, "tone": "pink", "kind": "Case opened", "title": c.title,
                           "detail": f"{meta} · by {c.created_by}", "href": href})  # fmt: skip
        if (closed := aware(c.closed_at)) and closed >= since:
            events.append({"at": closed, "tone": "lime", "kind": "Case closed", "title": c.title,
                           "detail": meta, "href": href})  # fmt: skip

    latest: dict[str, tuple[ConnectorRun, str]] = {}
    for run, name in (
        await s.execute(
            select(ConnectorRun, Source.name)
            .join(Source, Source.id == ConnectorRun.source_id)
            .where(
                ConnectorRun.started_at >= since,
                Source.kind != "enricher",
                or_(ConnectorRun.items_new > 0, ConnectorRun.status == "failed"),
            )
            .order_by(ConnectorRun.started_at.desc())
        )
    ).all():
        latest.setdefault(name, (run, name))  # one line per feed: its latest noteworthy run
    for run, name in latest.values():
        at = aware(run.finished_at or run.started_at) or now
        if run.status == "failed":
            why = f"HTTP {run.http_status}" if run.http_status else "see Sources"
            events.append({"at": at, "tone": "red", "kind": "Feed failed", "title": name,
                           "detail": why, "href": "/feeds"})  # fmt: skip
        else:
            events.append({"at": at, "tone": "cyan", "kind": "Collected", "title": name,
                           "detail": f"+{run.items_new:,} new of {run.items_total:,}",
                           "href": f"/indicators?source={quote(name, safe='')}"})  # fmt: skip

    for v in (
        await s.scalars(
            select(Vulnerability)
            .where(Vulnerability.kev.is_(True), Vulnerability.kev_date_added >= since.date())
            .order_by(Vulnerability.kev_date_added.desc(), Vulnerability.cve_id.desc())
            .limit(limit)
        )
    ).all():
        events.append({"at": datetime.combine(v.kev_date_added or since.date(), time(), UTC), "tone": "amber",
                       "kind": "Added to KEV", "title": v.cve_id, "detail": v.kev_name or "",
                       "href": f"/vulnerabilities/{v.cve_id}"})  # fmt: skip

    events.sort(key=lambda e: e["at"], reverse=True)
    # Feeds run hourly; cap routine collections so cases, failures and KEV keep a place.
    collected = [e for e in events if e["kind"] == "Collected"][:3]
    return [e for e in events if e["kind"] != "Collected" or e in collected][:limit]


def parse_month(value: str | None) -> date | None:
    """``YYYY-MM`` to the first of that month; None when absent or invalid."""
    try:
        y, m = (int(x) for x in (value or "").split("-"))
        return date(y, m, 1) if 2000 <= y <= 2100 else None
    except ValueError:
        return None


async def month_calendar(
    s: AsyncSession, now: datetime, clearance: str, month: date | None = None
) -> dict[str, Any]:
    """One month as a Sunday-first grid: indicators first seen each day (within
    the viewer's clearance) and KEV additions. Months after the current one
    are clamped to it."""
    this = now.date().replace(day=1)
    first = min((month or this).replace(day=1), this)
    nxt = (first + timedelta(days=32)).replace(day=1)
    start, end = datetime.combine(first, time(), UTC), datetime.combine(nxt, time(), UTC)
    day = func.date(Indicator.created_at)
    new: dict[str, int] = {
        str(d)[:10]: int(n)
        for d, n in (
            await s.execute(
                select(day, func.count())
                .where(Indicator.created_at >= start, Indicator.created_at < end,
                       Indicator.tlp.in_(tlp_rules.readable(clearance)))
                .group_by(day)
            )
        ).all()
        if d
    }  # fmt: skip
    kev: dict[str, int] = {
        str(d)[:10]: int(n)
        for d, n in (
            await s.execute(
                select(Vulnerability.kev_date_added, func.count())
                .where(Vulnerability.kev.is_(True), Vulnerability.kev_date_added >= first,
                       Vulnerability.kev_date_added < nxt)
                .group_by(Vulnerability.kev_date_added)
            )
        ).all()
        if d
    }  # fmt: skip
    peak = max(new.values(), default=0)
    today = now.date()
    cells: list[dict[str, Any] | None] = [None] * ((first.weekday() + 1) % 7)
    for n in range(1, cal.monthrange(first.year, first.month)[1] + 1):
        d = first.replace(day=n)
        key = d.isoformat()
        count = new.get(key, 0)
        level = 0 if not count else 1 + min(3, int(3 * math.log1p(count) / math.log1p(peak)))
        cells.append({"day": n, "date": d, "new": count, "kev": kev.get(key, 0), "level": level,
                      "today": d == today, "future": d > today})  # fmt: skip
    cells += [None] * (-len(cells) % 7)
    prev = (first - timedelta(days=1)).replace(day=1)
    return {
        "label": first.strftime("%B %Y"),
        "weeks": [cells[i : i + 7] for i in range(0, len(cells), 7)],
        "prev": prev.strftime("%Y-%m"),
        "next": nxt.strftime("%Y-%m") if nxt <= this else None,
        "new_total": sum(new.values()),
        "kev_total": sum(kev.values()),
    }


async def _tactic_counts(s: AsyncSession, techniques: list[Entity]) -> list[tuple[str, int]]:
    """Enterprise tactics in matrix order with how many of the given
    techniques fall under each; empty until ATT&CK is loaded."""
    tactics = {
        e.external_id: e
        for e in (
            await s.scalars(select(Entity).where(Entity.type == "x-mitre-tactic", Entity.revoked.is_(False)))
        ).all()
        if e.external_id and "enterprise-attack" in (e.domains or [])
    }
    if not tactics:
        return []
    counts: Counter[str] = Counter()
    for t in techniques:
        for short in t.tactics or []:
            counts[short] += 1
    order = [t for t in TACTIC_ORDER if t in tactics]
    return [(tactics[t].name, counts.get((tactics[t].aliases or [""])[0], 0)) for t in order]


async def pir_status(
    s: AsyncSession, settings: Settings | None, vis: Any, stack_kev: int, p1_in_stack: int
) -> list[dict[str, Any]]:
    """Each PIR with how much currently matches it (from score relevance hits
    and the vulnerability model)."""
    if settings is None:
        return []
    try:
        profile = load_profile(settings.profile_path)
        pirs = load_pirs(settings.pirs_path, profile)
    except (ProfileError, OSError):
        return []

    async def hits(kind: str) -> int:
        return int(
            await s.scalar(
                select(func.count())
                .select_from(Indicator)
                .where(
                    Indicator.status == "active",
                    vis,
                    cast(Indicator.score_breakdown, String).like(f'%"kind": "{kind}"%'),
                )
            )
            or 0
        )

    out = []
    for p in pirs.pirs:
        w = p.watch
        if "tech_stack" in w.match:
            n, unit = stack_kev, "known-exploited CVEs affect the stack"
            if p1_in_stack:
                unit += f" · {p1_in_stack}+ at P1"
            state = "action" if p1_in_stack else "active" if n else "quiet"
        else:
            kinds = []
            if w.techniques:
                kinds.append("technique")
            if "domains" in w.match or "brands" in w.match:
                kinds.append("impersonation")
            if w.sectors:
                kinds.append("sector")
            if w.geography:
                kinds.append("geography")
            n = sum([await hits(k) for k in kinds])
            unit = "active indicators match (" + ", ".join(kinds or ["no automatic match"]) + ")"
            state = "active" if n else "quiet"
        out.append({"id": p.id, "question": p.question, "n": n, "unit": unit, "state": state})
    return out
