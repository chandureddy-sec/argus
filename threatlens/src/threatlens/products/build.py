"""Building intelligence products from stored data (ADR 0021).

A product is a plain dict of sections, built only from the database and an
``as_of`` time, never from "now" and never from upstream services, so the
same data and the same ``as_of`` always give the same product, byte for byte
(``sha256`` of the canonical JSON is stored with it).

* Every statement cites the Argus records behind it: indicator ``#id``, CVE
  id, case ``#id``, source names. The HTML and PDF renderings link them.
* Content is limited to ``max_tlp`` (default TLP:GREEN, so a product can go
  to the whole organisation); the product is marked with the strictest TLP of
  what it includes, and a reader needs that clearance.
* Values are defanged: products are for people.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any, Literal

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from threatlens import assets
from threatlens import tlp as tlp_rules
from threatlens.ioc.extract import defang_text
from threatlens.models import (
    AlertEvent,
    Case,
    ConnectorRun,
    Entity,
    Indicator,
    Lookalike,
    Relationship,
    Sighting,
    Source,
    Vulnerability,
    VulnerabilityProduct,
)
from threatlens.models import Observable as ObsRow
from threatlens.settings import Settings

Kind = Literal["daily", "weekly", "vulns", "exec"]
KINDS: dict[Kind, str] = {
    "daily": "Daily threat brief",
    "weekly": "Weekly CTI report",
    "vulns": "Vulnerability priority list",
    "exec": "Executive one-pager",
}
HIGH = 60.0  # "block-worthy" in the scoring model (ADR 0008)


@dataclass(frozen=True)
class Window:
    start: datetime
    end: datetime

    @property
    def days(self) -> int:
        return max(1, round((self.end - self.start).total_seconds() / 86400))


def window(kind: Kind, as_of: datetime) -> Window:
    end = as_of.astimezone(UTC).replace(minute=0, second=0, microsecond=0)
    if kind == "daily":
        end = end.replace(hour=0)
        return Window(end - timedelta(days=1), end)
    if kind in ("weekly", "exec"):
        end = end.replace(hour=0) - timedelta(days=end.weekday())  # Monday 00:00 UTC
        return Window(end - timedelta(days=7), end)
    end = end.replace(hour=0)
    return Window(end - timedelta(days=1), end)


def _ts(v: datetime | date | None) -> str | None:
    if v is None:
        return None
    if isinstance(v, datetime):
        return (v if v.tzinfo else v.replace(tzinfo=UTC)).astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")
    return v.isoformat()


def digest(product: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(product, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


# ── sections ─────────────────────────────────────────────────────────────────


async def _new_indicators(s: AsyncSession, w: Window, levels: list[str], limit: int = 10) -> dict[str, Any]:
    base = (
        select(Indicator, ObsRow)
        .join(ObsRow, ObsRow.id == Indicator.observable_id)
        .where(
            Indicator.created_at >= w.start,
            Indicator.created_at < w.end,
            Indicator.tlp.in_(levels),
            ObsRow.type != "vulnerability",  # CVEs have their own section
        )
    )
    rows = (await s.execute(base)).all()
    by_type = Counter(o.type for _, o in rows)
    high = sorted(
        ((i, o) for i, o in rows if (i.priority_score or 0) >= HIGH and i.status == "active"),
        key=lambda x: (-(x[0].priority_score or 0), x[0].id),
    )
    srcs: dict[int, list[str]] = {}
    ids = [i.id for i, _ in high[:limit]]
    if ids:
        for ind_id, name in (
            await s.execute(
                select(Sighting.indicator_id, Source.name)
                .join(Source, Source.id == Sighting.source_id)
                .where(Sighting.indicator_id.in_(ids), Source.kind != "environment")
            )
        ).all():
            srcs.setdefault(int(ind_id), []).append(name)
    return {
        "total": len(rows),
        "high": len(high),
        "byType": sorted(by_type.items(), key=lambda x: (-x[1], x[0])),
        "top": [
            {
                "ref": f"indicator #{i.id}",
                "link": f"/indicators/{i.id}",
                "type": o.type,
                "value": o.defanged,
                "score": round(i.priority_score or 0),
                "tlp": i.tlp,
                "sources": sorted(srcs.get(i.id, [])),
                "labels": sorted(i.labels or [])[:5],
            }
            for i, o in high[:limit]
        ],
        "tlps": sorted({i.tlp for i, _ in high[:limit]}),
    }


async def _families(s: AsyncSession, w: Window, levels: list[str], limit: int = 8) -> list[dict[str, Any]]:
    rows = (
        await s.execute(
            select(Relationship.dst_ref, func.count(func.distinct(Relationship.src_ref)))
            .join(Indicator, Indicator.stix_id == Relationship.src_ref)
            .where(
                Relationship.rel_type == "indicates",
                Relationship.last_seen >= w.start,
                Relationship.last_seen < w.end,
                Indicator.tlp.in_(levels),
            )
            .group_by(Relationship.dst_ref)
        )
    ).all()
    ents = {
        e.stix_id: e
        for e in (await s.scalars(select(Entity).where(Entity.stix_id.in_([r for r, _ in rows])))).all()
    }
    out: list[dict[str, Any]] = [
        {
            "name": ents[r].name,
            "ref": ents[r].external_id or r,
            "link": f"/entities/{ents[r].external_id or r}",
            "indicators": int(n),
        }
        for r, n in rows
        if r in ents
    ]
    return sorted(out, key=lambda x: (-int(x["indicators"]), str(x["name"])))[:limit]


async def _kev(s: AsyncSession, w: Window, settings: Settings) -> dict[str, Any]:
    stack = [(v, p) for _, v, p in await assets.org_stack(s, settings)]
    in_stack: set[int] = set()
    if stack:
        cond = or_(
            *(and_(VulnerabilityProduct.vendor == v, VulnerabilityProduct.product == p) for v, p in stack)
        )
        in_stack = set((await s.scalars(select(VulnerabilityProduct.vulnerability_id).where(cond))).all())
    rows = (
        await s.scalars(
            select(Vulnerability)
            .where(
                Vulnerability.kev.is_(True),
                Vulnerability.kev_date_added >= w.start.date(),
                Vulnerability.kev_date_added < w.end.date(),
            )
            .order_by(Vulnerability.kev_date_added.desc(), Vulnerability.cve_id)
        )
    ).all()
    return {
        "added": len(rows),
        "inStack": sum(1 for v in rows if v.id in in_stack),
        "items": [
            {
                "ref": v.cve_id,
                "link": f"/vulnerabilities/{v.cve_id}",
                "name": v.kev_name or "",
                "added": _ts(v.kev_date_added),
                "due": _ts(v.kev_due_date),
                "ransomware": v.kev_ransomware == "Known",
                "priority": v.patch_priority,
                "epss": round(v.epss, 4) if v.epss is not None else None,
                "inStack": v.id in in_stack,
                "sources": ["cisa_kev"],
            }
            for v in rows[:15]
        ],
    }


async def _cases(s: AsyncSession, w: Window, levels: list[str]) -> dict[str, Any]:
    opened = (
        await s.scalars(
            select(Case)
            .where(Case.created_at >= w.start, Case.created_at < w.end, Case.tlp.in_(levels))
            .order_by(Case.created_at, Case.id)
        )
    ).all()
    closed = int(
        await s.scalar(
            select(func.count())
            .select_from(Case)
            .where(Case.closed_at >= w.start, Case.closed_at < w.end, Case.tlp.in_(levels))
        )
        or 0
    )
    return {
        "opened": len(opened),
        "closed": closed,
        "items": [
            {
                "ref": f"case #{c.id}",
                "link": f"/cases/{c.id}",
                "title": defang_text(c.title),
                "severity": c.severity,
                "status": c.status,
            }
            for c in opened[:10]
        ],
    }


async def _feeds(s: AsyncSession, w: Window) -> list[dict[str, Any]]:
    rows = (
        await s.execute(
            select(Source.name, ConnectorRun.status, func.count())
            .join(ConnectorRun, ConnectorRun.source_id == Source.id)
            .where(ConnectorRun.started_at >= w.start, ConnectorRun.started_at < w.end)
            .group_by(Source.name, ConnectorRun.status)
        )
    ).all()
    agg: dict[str, Counter[str]] = {}
    for name, status, n in rows:
        agg.setdefault(name, Counter())[status] += int(n)
    out = []
    for name, c in sorted(agg.items()):
        bad = c["failed"] + c["error"]
        if bad:
            out.append({"ref": name, "link": f"/feeds/{name}", "failed": bad, "runs": sum(c.values())})
    return out


async def _alerts(s: AsyncSession, w: Window, levels: list[str]) -> int:
    return int(
        await s.scalar(
            select(func.count())
            .select_from(AlertEvent)
            .where(
                AlertEvent.created_at >= w.start, AlertEvent.created_at < w.end, AlertEvent.tlp.in_(levels)
            )
        )
        or 0
    )


async def _lookalikes(s: AsyncSession, w: Window, limit: int = 15) -> dict[str, Any]:
    rows = (
        await s.scalars(
            select(Lookalike)
            .where(
                Lookalike.first_seen >= w.start, Lookalike.first_seen < w.end, Lookalike.status != "benign"
            )
            .order_by(Lookalike.domain, Lookalike.candidate)
        )
    ).all()
    return {
        "new": len(rows),
        "items": [
            {
                "ref": f"lookalike #{r.id}",
                "link": "/lookalikes",
                "candidate": defang_text(r.candidate),
                "imitates": r.domain,
                "technique": r.fuzzer,
                "status": r.status,
                "sources": sorted({str(e.get("source", "")) for e in r.evidence or [] if e.get("source")}),
            }
            for r in rows[:limit]
        ],
    }


async def _patch_list(s: AsyncSession, settings: Settings, limit: int = 40) -> list[dict[str, Any]]:
    stack = [(v, p) for _, v, p in await assets.org_stack(s, settings)]
    in_stack: set[int] = set()
    if stack:
        cond = or_(
            *(and_(VulnerabilityProduct.vendor == v, VulnerabilityProduct.product == p) for v, p in stack)
        )
        in_stack = set((await s.scalars(select(VulnerabilityProduct.vulnerability_id).where(cond))).all())
    rows = (
        await s.scalars(
            select(Vulnerability)
            .where(Vulnerability.patch_priority.in_(("P1", "P2")))
            .order_by(Vulnerability.patch_score.desc().nulls_last(), Vulnerability.cve_id)
            .limit(400)
        )
    ).all()
    rows = sorted(rows, key=lambda v: (v.id not in in_stack, -(v.patch_score or 0), v.cve_id))[:limit]
    out = []
    for v in rows:
        why = [
            r.get("reason", "") if isinstance(r, dict) else str(r)
            for r in ((v.patch_breakdown or {}).get("reasons") or [])
        ][:4]
        out.append(
            {
                "ref": v.cve_id,
                "link": f"/vulnerabilities/{v.cve_id}",
                "priority": v.patch_priority,
                "score": round(v.patch_score or 0),
                "kev": v.kev,
                "due": _ts(v.kev_due_date),
                "epss": round(v.epss, 4) if v.epss is not None else None,
                "cvss": v.cvss_score,
                "inStack": v.id in in_stack,
                "name": v.kev_name or (v.description or "")[:120],
                "why": why,
                "sources": sorted(
                    {"nvd", *(["cisa_kev"] if v.kev else []), *(["epss"] if v.epss is not None else [])}
                ),
            }
        )
    return out


# ── products ─────────────────────────────────────────────────────────────────


async def build(
    s: AsyncSession, kind: Kind, as_of: datetime, settings: Settings, max_tlp: str = "TLP:GREEN"
) -> dict[str, Any]:
    w = window(kind, as_of)
    levels = [lv for lv in tlp_rules.readable(max_tlp) if lv != "TLP:RED"]
    head: dict[str, Any] = {
        "kind": kind,
        "title": KINDS[kind],
        "org": settings.org_identity,
        "period": {"start": _ts(w.start), "end": _ts(w.end), "days": w.days},
        "maxTlp": max_tlp,
    }
    body: dict[str, Any]
    if kind in ("daily", "weekly"):
        ind = await _new_indicators(s, w, levels, 10 if kind == "daily" else 15)
        body = {
            "indicators": ind,
            "families": await _families(s, w, levels),
            "kev": await _kev(s, w, settings),
            "cases": await _cases(s, w, levels),
            "alerts": await _alerts(s, w, levels),
            "feeds": await _feeds(s, w),
            "lookalikes": await _lookalikes(s, w),
        }
        if kind == "weekly":
            prev = Window(w.start - (w.end - w.start), w.start)
            body["previous"] = {
                "indicators": (await _new_indicators(s, prev, levels, 0))["total"],
                "kev": (await _kev(s, prev, settings))["added"],
            }
        tlps = ind["tlps"]
    elif kind == "vulns":
        body = {"items": await _patch_list(s, settings)}
        tlps = ["TLP:CLEAR"]
    else:
        ind = await _new_indicators(s, w, levels, 3)
        kev = await _kev(s, w, settings)
        patch = await _patch_list(s, settings, 5)
        cases = await _cases(s, w, levels)
        body = {
            "indicators": ind,
            "kev": kev,
            "patch": patch,
            "cases": cases,
            "alerts": await _alerts(s, w, levels),
            "risks": _risks(ind, kev, patch, cases),
        }
        tlps = ind["tlps"]
    marking = "TLP:CLEAR"
    for t in tlps:
        marking = tlp_rules.stricter(marking, t)
    product = {**head, "tlp": marking, "body": body}
    product["sha256"] = digest(product)
    return product


def _risks(
    ind: dict[str, Any], kev: dict[str, Any], patch: list[dict[str, Any]], cases: dict[str, Any]
) -> list[dict[str, Any]]:
    """Plain-language risks for executives, each with the records behind it."""
    out = []
    stack_kev = [k for k in kev["items"] if k["inStack"]]
    noun = "vulnerability affects" if len(stack_kev) == 1 else "vulnerabilities affect"
    if stack_kev:
        out.append(
            {
                "risk": f"{len(stack_kev)} newly exploited {noun} software we run.",
                "action": "Patch or mitigate before CISA's due date.",
                "refs": [k["ref"] for k in stack_kev[:5]],
            }
        )
    p1 = [p for p in patch if p["priority"] == "P1"]
    if p1:
        out.append(
            {
                "risk": f"{len(p1)} vulnerabilities rated P1 (patch now) in the catalogue.",
                "action": "Confirm exposure and patch the in-stack ones first.",
                "refs": [p["ref"] for p in p1[:5]],
            }
        )
    if ind["high"]:
        out.append(
            {
                "risk": f"{ind['high']} new high-priority indicators of attack infrastructure.",
                "action": "They are available to block (blocklist, firewall feeds, SIEM).",
                "refs": [t["ref"] for t in ind["top"][:3]],
            }
        )
    if cases["opened"]:
        out.append(
            {
                "risk": f"{cases['opened']} investigation(s) opened.",
                "action": "See the cases for status.",
                "refs": [c["ref"] for c in cases["items"][:3]],
            }
        )
    if not out:
        out.append(
            {"risk": "No new high-priority threats in the period.", "action": "No action needed.", "refs": []}
        )
    return out[:4]
