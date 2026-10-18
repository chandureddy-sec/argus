"""Argus JSON for the threat landscape, the ATT&CK matrix and global search
(ADR 0016). Same rules as the rest of /app/api: a signed-in session or an API
key, TLP clearance on every indicator, values defanged."""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import String, cast, func, or_, select
from sqlalchemy.orm import selectinload

from threatlens import assets, dashboard
from threatlens import cases as case_store
from threatlens import tlp as tlp_rules
from threatlens.api.v1 import Viewer, _app_settings, _sm
from threatlens.enrich.base import REGISTRY as ENRICHERS
from threatlens.ioc.extract import defang_text
from threatlens.kb import graph
from threatlens.kb.ids import alias_key
from threatlens.models import Enrichment, Entity, EntityAlias, Indicator, Sighting, Vulnerability
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


# ── indicator context: enrichment cards, graph pivot, techniques, timeline ───

PIVOT_TYPES = {
    "malware": "Malware",
    "intrusion-set": "Threat actors",
    "threat-actor": "Threat actors",
    "campaign": "Campaigns",
    "tool": "Tools",
    "attack-pattern": "Techniques",
    "vulnerability": "Vulnerabilities",
    "report": "Reports",
    "indicator": "Related indicators",
}
ACTOR_TYPES = ("malware", "intrusion-set", "threat-actor", "campaign", "tool")
TONE_ORDER = {"mal": 0, "sus": 1, "info": 2, "ok": 3, "off": 4}


def _pivot(n: dict[str, Any], edge: dict[str, Any], via: str | None = None) -> dict[str, Any]:
    if n["kind"] == "vulnerability":
        href = f"/vulnerabilities/{n['label']}"
    elif n["kind"] == "indicator":
        href = f"/indicators/{n['extra'].get('id')}"
    else:
        href = f"/entities/{n.get('external_id') or n['ref']}"
    return {
        "ref": n["ref"],
        "label": defang_text(n["label"]),
        "id": n.get("external_id"),
        "type": n["type"],
        "href": href,
        "rel": edge["rel_type"],
        "source": edge["source"],
        "origin": edge["origin"],
        "via": via,
    }


def _aware(v: datetime) -> datetime:
    return v if v.tzinfo else v.replace(tzinfo=UTC)


@router.get("/indicators/{indicator_id}/related")
async def indicator_related(who: Viewer, request: Request, indicator_id: int) -> dict[str, Any]:
    """Everything around one indicator for its page: the latest stored answer
    of each enricher (no new lookups are made), graph neighbours grouped by
    type, the ATT&CK techniques its malware and actors use, and a timeline."""
    from threatlens.argus_api import card  # the Verify page's card, shared

    now = datetime.now(UTC)
    async with _sm(request)() as s:
        ind = await s.scalar(
            select(Indicator)
            .where(Indicator.id == indicator_id)
            .options(
                selectinload(Indicator.observable),
                selectinload(Indicator.sightings).selectinload(Sighting.source),
            )
        )
        if ind is None or not tlp_rules.may_read(who.clearance, ind.tlp):
            raise HTTPException(404, "no such indicator")
        obs = ind.observable
        rows = (
            await s.scalars(
                select(Enrichment)
                .where(or_(Enrichment.observable_id == obs.id, Enrichment.canonical_key == obs.canonical_key))
                .order_by(Enrichment.fetched_at.desc())
            )
        ).all()
        latest: dict[str, Enrichment] = {}
        for e in rows:
            latest.setdefault(e.enricher, e)
        cards = []
        for e in latest.values():
            cls = ENRICHERS.get(e.enricher)
            c = card(
                {
                    "enricher": e.enricher,
                    "title": cls.info.title if cls else e.enricher,
                    "status": "cached",
                    "mode": e.mode,
                    "fetched_at": _iso(e.fetched_at),
                    "summary": e.summary,
                    "evidence": e.evidence,
                    "found": e.status != "not_found",
                }
            )
            c["fresh"] = _aware(e.expires_at) > now
            cards.append(c)
        cards.sort(key=lambda c: (TONE_ORDER.get(c["tone"], 5), c["title"]))

        groups: dict[str, list[dict[str, Any]]] = {}
        techniques: dict[str, dict[str, Any]] = {}
        if ind.stix_id:
            items, _ = await graph.neighbors(s, ind.stix_id, limit=200, clearance=who.clearance)
            seen: set[str] = set()
            actors: list[tuple[str, str]] = []
            for it in items:
                n = it["node"]
                if n["ref"] in seen:
                    continue
                seen.add(n["ref"])
                entry = _pivot(n, it["edge"])
                groups.setdefault(
                    PIVOT_TYPES.get(n["type"]) or PIVOT_TYPES.get(n["kind"], "Other"), []
                ).append(entry)
                if n["type"] == "attack-pattern":
                    techniques.setdefault(n["ref"], entry | {"via": "this indicator"})
                if n["type"] in ACTOR_TYPES:
                    actors.append((n["ref"], entry["label"]))
            for ref, name in actors[:8]:
                uses, _ = await graph.neighbors(
                    s, ref, direction="out", rel="uses", node_type="attack-pattern", limit=80,
                    clearance=who.clearance,
                )  # fmt: skip
                for it in uses:
                    techniques.setdefault(it["node"]["ref"], _pivot(it["node"], it["edge"], via=name))

        timeline: list[dict[str, Any]] = []
        for sg in ind.sightings:
            timeline.append(
                {
                    "at": _iso(sg.first_seen),
                    "kind": "first",
                    "source": sg.source.name,
                    "times": sg.times_reported,
                }
            )
            if sg.last_seen and sg.first_seen and sg.last_seen > sg.first_seen:
                timeline.append(
                    {
                        "at": _iso(sg.last_seen),
                        "kind": "last",
                        "source": sg.source.name,
                        "times": sg.times_reported,
                    }
                )
        for e in latest.values():
            timeline.append(
                {"at": _iso(e.fetched_at), "kind": "enriched", "source": e.enricher, "times": e.times_fetched}
            )
        timeline.sort(key=lambda t: t["at"] or "")
    return {
        "enrichments": cards,
        "groups": [{"name": k, "items": v[:40], "total": len(v)} for k, v in sorted(groups.items())],
        "techniques": sorted(techniques.values(), key=lambda t: t["id"] or t["label"])[:80],
        "timeline": timeline[-60:],
    }


# ── saved searches (one list per account) ────────────────────────────────────


class SavedIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    query: str = Field(min_length=1, max_length=2000)


def _owner(who: Any) -> str:
    return f"{who.kind}:{who.key_id}"


def _saved(r: Any) -> dict[str, Any]:
    return {
        "id": r.id,
        "name": r.name,
        "query": case_store.app_path(r.query),
        "created_at": _iso(r.created_at),
    }


@router.get("/searches")
async def list_searches(who: Viewer, request: Request) -> list[dict[str, Any]]:
    async with _sm(request)() as s:
        return [_saved(r) for r in await case_store.saved_searches(s, _owner(who))]


@router.post("/searches", status_code=201)
async def save_search(who: Viewer, request: Request, body: SavedIn) -> dict[str, Any]:
    async with _sm(request)() as s, s.begin():
        try:
            r = await case_store.save_search(s, _owner(who), body.name, body.query)
        except case_store.CaseError as e:
            raise HTTPException(422, str(e)) from e
        return _saved(r)


@router.delete("/searches/{search_id}", status_code=204)
async def delete_search(who: Viewer, request: Request, search_id: int) -> None:
    async with _sm(request)() as s, s.begin():
        if not await case_store.delete_search(s, _owner(who), search_id):
            raise HTTPException(404, "no such saved search")
