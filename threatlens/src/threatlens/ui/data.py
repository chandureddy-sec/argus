"""Read-side queries for the analyst UI (dashboard aggregates and page data).

Everything is computed from stored data; nothing is estimated or invented.
Where a panel depends on data the platform doesn't collect yet (Phase 4
priority scores), it says so.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from threatlens import tlp as tlp_rules
from threatlens.models import (
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
    s: AsyncSession, now: datetime, stack: list[tuple[str, str]], clearance: str
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

    return {
        "kpis": [
            {
                "value": active,
                "label": "Active indicators",
                "sub": f"+{new_24h:,} in the last 24 h",
                "tone": "orange",
                "href": "/ui/indicators",
            },
            {
                "value": kev,
                "label": "Known exploited CVEs",
                "sub": f"{kev_30d} added in 30 days",
                "tone": "yellow",
                "href": "/ui/vulnerabilities?kev=true",
            },
            {
                "value": stack_kev,
                "label": "Exploited in our stack",
                "sub": f"of {len(stack_ids):,} CVEs matching the tech stack",
                "tone": "cyan",
                "href": "/ui/vulnerabilities?kev=true&stack=true",
            },
            {
                "value": len(families),
                "label": "Malware families seen",
                "sub": "named by feed indicators",
                "tone": "pink",
                "href": "/ui/attack",
            },
            {
                "value": healthy,
                "label": "Healthy sources",
                "sub": f"of {enabled} collecting",
                "tone": "purple",
                "href": "/ui/sources",
            },
        ],
        "collected": collected,
        "new_items": new_items,
        "window": window,
        "kev_months": months,
        "types": [(TYPE_LABELS.get(t, t), int(n), f"/ui/indicators?type={t}") for t, n in types],
        "priority": [
            (b, int(prio_map.get(b, 0))) for b in ("malicious (60+)", "suspicious (30-59)", "low (under 30)")
        ],
        "top": [(i, TYPE_LABELS.get(t, t), v, p) for i, t, v, p in top],
        "by_source": [(n, int(c)) for n, c in by_source],
        "status": {k: int(v) for k, v in status_rows.items()},
        "families": [(name, n, f"/ui/entities/{ext or ref}") for name, n, ref, ext in families[:6]],
        "techniques": [(label, n, f"/ui/entities/{ext}") for label, n, ext in techniques],
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
