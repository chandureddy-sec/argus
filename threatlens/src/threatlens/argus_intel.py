"""Argus JSON for the threat landscape, the ATT&CK matrix and global search
(ADR 0016). Same rules as the rest of /app/api: a signed-in session or an API
key, TLP clearance on every indicator, values defanged."""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Query, Request
from sqlalchemy import String, cast, func, or_, select

from threatlens import assets, dashboard
from threatlens import cases as case_store
from threatlens import tlp as tlp_rules
from threatlens.api.v1 import Viewer, _app_settings, _sm
from threatlens.kb import graph
from threatlens.kb.ids import alias_key
from threatlens.models import Entity, EntityAlias, Indicator, Vulnerability
from threatlens.models import Observable as ObsRow

router = APIRouter(prefix="/app/api", include_in_schema=False)


def _iso(v: datetime | date | None) -> str | None:
    return v.isoformat() if v else None


def _vuln(v: Vulnerability, products: dict[int, str]) -> dict[str, Any]:
    return {
        "cve": v.cve_id,
        "name": v.kev_name or "",
        "product": products.get(v.id, ""),
        "added": _iso(v.kev_date_added),
        "due": _iso(v.kev_due_date),
        "ransomware": v.kev_ransomware == "Known",
        "epss": v.epss,
        "cvss": v.cvss_score,
        "priority": v.patch_priority,
    }


@router.get("/landscape")
async def landscape(who: Viewer, request: Request) -> dict[str, Any]:
    """The threat landscape for the home page: what to look at first, who is
    active, what is being exploited, where, and what changed this week."""
    now = datetime.now(UTC)
    settings = _app_settings(request)
    async with _sm(request)() as s:
        stack = [(v, p) for _, v, p in await assets.org_stack(s, settings)]
        d = await dashboard.overview(s, now, stack, who.clearance, settings)
        events = await dashboard.activity(s, now, who.clearance, limit=8)
    return {
        "kpis": [{k: x[k] for k in ("label", "value", "sub", "href")} for x in d["kpis"]],
        "queue": [q | {"last_seen": _iso(q["last_seen"])} for q in d["queue"]],
        "families": [{"name": n, "count": c, "href": h} for n, c, h in d["families"]],
        "techniques": [{"label": label, "count": c, "href": h} for label, c, h in d["techniques"]],
        "tactics": [{"name": n, "count": c} for n, c in d["tactics"]],
        "kevLatest": [_vuln(v, d["products"]) for v in d["kev_latest"]],
        "kevStack": [_vuln(v, d["products"]) for v in d["kev_stack"]],
        "patch": [{"priority": p, "count": c} for p, c in d["patch"]],
        "geo": d["geo"],
        "geoLocated": d["geo_located"],
        "ips": d["ips"],
        "pirs": d["pirs"],
        "activity": [e | {"at": _iso(e["at"])} for e in events],
        "feedRates": [{k: f[k] for k in ("name", "health", "ok", "runs", "pct")} for f in d["feed_rates"]],
        "stack": [{"vendor": v, "product": p} for v, p in stack][:30],
    }


@router.get("/attack")
async def attack(who: Viewer, request: Request) -> dict[str, Any]:
    """Enterprise ATT&CK: tactics x techniques, each shaded by how many malware
    families our feeds point at use it."""
    async with _sm(request)() as s:
        m = await dashboard.attack_matrix(s)
    return {
        "families": m["families"],
        "peak": m["peak"],
        "columns": [
            {
                "tactic": {"id": c["tactic"].external_id, "name": c["tactic"].name},
                "hits": c["hits"],
                "cells": [{"id": t.external_id, "name": t.name, "count": n} for t, n in c["cells"]],
            }
            for c in m["columns"]
        ],
    }


def _like(q: str) -> str:
    return "%" + q.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


@router.get("/search")
async def search(
    who: Viewer,
    request: Request,
    q: Annotated[str, Query(max_length=300)] = "",
    all: bool = False,  # noqa: A002
) -> dict[str, Any]:
    """One box for everything. An exact hit (an indicator value, a CVE id, an
    ATT&CK id or an entity name) comes back as ``open``; anything else lists
    matches by value, label (``tag:x``), entity, CVE and case."""
    q = q.strip()
    tag = q[4:].strip().lower() if q.lower().startswith("tag:") else None
    out: dict[str, Any] = {
        "q": q,
        "open": None,
        "indicators": [],
        "indicatorsTotal": 0,
        "entities": [],
        "cves": [],
        "cases": [],
    }
    if not q or (not tag and len(q) < 2):
        return out
    async with _sm(request)() as s:
        if not tag and not all:
            node = await graph.resolve(s, q, clearance=who.clearance)
            if node is not None:
                if node.kind == "vulnerability":
                    out["open"] = f"/vulnerabilities/{node.label}"
                elif node.kind == "indicator":
                    out["open"] = f"/indicators/{node.extra.get('id')}"
                else:
                    out["open"] = f"/entities/{node.external_id or node.ref}"
                return out
        vis = Indicator.tlp.in_(tlp_rules.readable(who.clearance))
        base = select(Indicator, ObsRow).join(ObsRow, ObsRow.id == Indicator.observable_id).where(vis)
        labels = cast(Indicator.labels, String)
        if tag:
            stmt = base.where(labels.like(f'%"{tag.replace(chr(34), "")}"%'))
        else:
            stmt = base.where(
                or_(func.lower(ObsRow.value).like(_like(q), escape="\\"), labels.like(_like(q), escape="\\"))
            )
        out["indicatorsTotal"] = int(await s.scalar(select(func.count()).select_from(stmt.subquery())) or 0)
        out["indicators"] = [
            {
                "id": i.id,
                "type": o.type,
                "value": o.defanged,
                "score": i.priority_score,
                "status": i.status,
                "labels": i.labels[:4],
            }
            for i, o in (
                await s.execute(stmt.order_by(Indicator.priority_score.desc().nulls_last()).limit(25))
            ).all()
        ]
        if not tag:
            key = alias_key(q) or q.lower()
            ent_ids = select(EntityAlias.entity_id).where(EntityAlias.alias_key.like(_like(key), escape="\\"))
            ents = (
                await s.scalars(
                    select(Entity)
                    .where(
                        Entity.revoked.is_(False),
                        or_(
                            Entity.id.in_(ent_ids),
                            func.lower(Entity.name).like(_like(q), escape="\\"),
                            func.lower(Entity.external_id).like(_like(q), escape="\\"),
                        ),
                    )
                    .order_by(Entity.type, Entity.name)
                    .limit(25)
                )
            ).all()
            out["entities"] = [
                {"ref": e.external_id or e.stix_id, "name": e.name, "type": e.type, "id": e.external_id}
                for e in ents
            ]
            cves = (
                await s.scalars(
                    select(Vulnerability)
                    .where(
                        or_(
                            func.lower(Vulnerability.cve_id).like(_like(q), escape="\\"),
                            func.lower(Vulnerability.description).like(_like(q), escape="\\"),
                        )
                    )
                    .order_by(Vulnerability.patch_score.desc().nulls_last())
                    .limit(15)
                )
            ).all()
            out["cves"] = [
                {
                    "cve": v.cve_id,
                    "kev": v.kev,
                    "priority": v.patch_priority,
                    "cvss": v.cvss_score,
                    "description": v.description[:200],
                }
                for v in cves
            ]
            cases = await case_store.list_cases(s, who.clearance, q=q, limit=10)
            out["cases"] = [
                {"id": c.id, "title": c.title, "status": c.status, "severity": c.severity} for c, _ in cases
            ]
    return out
