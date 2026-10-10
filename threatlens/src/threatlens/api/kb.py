"""REST API v1, knowledge base (Phase 2): ATT&CK releases and changes,
entities (techniques, groups, software, …), vulnerabilities, and the graph.

All routes are read-only and need the viewer role. Identifiers in paths
accept anything ``graph.resolve`` understands: a STIX id, an ATT&CK id
(T1059.001, S0367, G0102), a name or alias, a CVE id, or an indicator value.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import load_only

from threatlens.auth import Principal, require
from threatlens.kb import graph
from threatlens.kb.vulns import exploit_signals
from threatlens.models import (
    AttackChange,
    AttackRelease,
    Entity,
    Relationship,
    Vulnerability,
    VulnerabilityProduct,
)

router = APIRouter(prefix="/api/v1")
LIST_COLUMNS = (
    Entity.stix_id, Entity.type, Entity.name, Entity.external_id, Entity.aliases, Entity.domains,
    Entity.platforms, Entity.tactics, Entity.is_subtechnique, Entity.revoked, Entity.deprecated,
    Entity.version, Entity.origin,
)  # fmt: skip
Viewer = Annotated[Principal, Depends(require("viewer"))]
Limit = Annotated[int, Query(ge=1, le=500)]
Offset = Annotated[int, Query(ge=0, le=1_000_000)]
Ident = Annotated[str, Path(min_length=1, max_length=300)]


def _sm(request: Request) -> async_sessionmaker[AsyncSession]:
    sm: async_sessionmaker[AsyncSession] = request.app.state.sessionmaker
    return sm


def _like(q: str) -> str:
    return "%" + q.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


# ── schemas ──────────────────────────────────────────────────────────────────


class ReleaseOut(BaseModel):
    domain: str
    version: str
    released: datetime | None
    baseline: bool
    previous_version: str | None
    counts: dict[str, Any]
    summary: dict[str, Any]
    ingested_at: datetime


class ChangeOut(BaseModel):
    stix_id: str
    type: str
    external_id: str | None
    name: str
    change: str
    details: dict[str, Any]


class EntityOut(BaseModel):
    stix_id: str
    type: str
    name: str
    external_id: str | None
    aliases: list[str]
    domains: list[str]
    platforms: list[str]
    tactics: list[str]
    is_subtechnique: bool
    revoked: bool
    deprecated: bool
    version: str | None
    origin: str
    url: str | None


class EntityDetail(EntityOut):
    description: str
    relationship_counts: dict[str, int]


class VulnOut(BaseModel):
    cve_id: str
    stix_id: str
    description: str
    published: datetime | None
    cvss_version: str | None
    cvss_score: float | None
    cvss_severity: str | None
    kev: bool
    kev_date_added: date | None
    epss: float | None
    epss_percentile: float | None
    nvd_fetched: bool
    patch_priority: str | None = Field(default=None, description="P1-P4 (ADR 0008); KEV is at least P2")
    patch_score: float | None = None


class VulnDetail(VulnOut):
    nvd_modified: datetime | None
    vuln_status: str | None
    cvss_vector: str | None
    cvss: list[dict[str, Any]]
    cwes: list[str]
    cpes: list[str]
    products: list[dict[str, str]]
    references: list[dict[str, Any]]
    ssvc: dict[str, Any]
    kev_due_date: date | None
    kev_ransomware: str | None
    kev_name: str | None
    kev_required_action: str | None
    epss_date: date | None
    osv_ids: list[str]
    packages: list[dict[str, Any]]
    exploit_signals: list[dict[str, Any]]
    sources: dict[str, Any]
    patch_breakdown: dict[str, Any] | None = Field(default=None, description="every point and floor")


class Page[T](BaseModel):
    items: list[T]
    total: int
    limit: int
    offset: int


_URL_PATHS = (
    ("TA", "tactics"),
    ("T", "techniques"),
    ("S", "software"),
    ("G", "groups"),
    ("C", "campaigns"),
    ("M", "mitigations"),
    ("DS", "datasources"),
)


def _url(e: Entity) -> str | None:
    """attack.mitre.org page, derived from the ATT&CK id (no need to load the STIX object)."""
    xid = e.external_id
    if e.origin != "attack" or not xid:
        return None
    for prefix, path in _URL_PATHS:
        if xid.startswith(prefix) and xid[len(prefix) :][:1].isdigit():
            return f"https://attack.mitre.org/{path}/{xid.replace('.', '/')}/"
    return None


def _entity_out(e: Entity) -> dict[str, Any]:
    return {
        "stix_id": e.stix_id,
        "type": e.type,
        "name": e.name,
        "external_id": e.external_id,
        "aliases": e.aliases or [],
        "domains": e.domains or [],
        "platforms": e.platforms or [],
        "tactics": e.tactics or [],
        "is_subtechnique": e.is_subtechnique,
        "revoked": e.revoked,
        "deprecated": e.deprecated,
        "version": e.version,
        "origin": e.origin,
        "url": _url(e),
    }


def _vuln_out(v: Vulnerability) -> dict[str, Any]:
    return {
        "cve_id": v.cve_id,
        "stix_id": v.stix_id,
        "description": v.description,
        "published": v.published,
        "cvss_version": v.cvss_version,
        "cvss_score": v.cvss_score,
        "cvss_severity": v.cvss_severity,
        "kev": v.kev,
        "kev_date_added": v.kev_date_added,
        "epss": v.epss,
        "epss_percentile": v.epss_percentile,
        "nvd_fetched": v.nvd_modified is not None,
        "patch_priority": v.patch_priority,
        "patch_score": v.patch_score,
    }


async def _resolve(s: AsyncSession, ident: str, clearance: str) -> graph.Node:
    node = await graph.resolve(s, ident, clearance=clearance)
    if node is None:
        raise HTTPException(404, "nothing matches that identifier")
    return node


# ── ATT&CK releases ──────────────────────────────────────────────────────────


@router.get("/attack/releases", response_model=list[ReleaseOut], tags=["knowledge"])
async def attack_releases(who: Viewer, request: Request) -> list[ReleaseOut]:
    async with _sm(request)() as s:
        rows = (await s.scalars(select(AttackRelease).order_by(AttackRelease.ingested_at.desc()))).all()
    return [ReleaseOut.model_validate(r, from_attributes=True) for r in rows]


@router.get("/attack/releases/{domain}/{version}/changes", response_model=Page[ChangeOut], tags=["knowledge"])
async def attack_changes(
    who: Viewer,
    request: Request,
    domain: Annotated[str, Path(max_length=40)],
    version: Annotated[str, Path(max_length=16)],
    change: Literal["added", "modified", "revoked", "deprecated", "restored", "removed"] | None = None,
    type: Annotated[str | None, Query(max_length=40)] = None,  # noqa: A002 - public API name
    limit: Limit = 100,
    offset: Offset = 0,
) -> Page[ChangeOut]:
    async with _sm(request)() as s:
        rel = await s.scalar(
            select(AttackRelease).where(AttackRelease.domain == domain, AttackRelease.version == version)
        )
        if rel is None:
            raise HTTPException(404, "release not loaded")
        stmt = select(AttackChange).where(AttackChange.release_id == rel.id)
        if change:
            stmt = stmt.where(AttackChange.change == change)
        if type:
            stmt = stmt.where(AttackChange.type == type)
        total = int(await s.scalar(select(func.count()).select_from(stmt.subquery())) or 0)
        rows = (
            await s.scalars(stmt.order_by(AttackChange.change, AttackChange.name).limit(limit).offset(offset))
        ).all()
    return Page[ChangeOut](
        items=[ChangeOut.model_validate(r, from_attributes=True) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


# ── entities ─────────────────────────────────────────────────────────────────


@router.get("/entities", response_model=Page[EntityOut], tags=["knowledge"])
async def list_entities(
    who: Viewer,
    request: Request,
    type: Annotated[str | None, Query(max_length=40)] = None,  # noqa: A002 - public API name
    q: Annotated[str | None, Query(min_length=2, max_length=200)] = None,
    domain: Annotated[str | None, Query(max_length=40)] = None,
    tactic: Annotated[str | None, Query(max_length=64)] = None,
    include_revoked: bool = False,
    limit: Limit = 50,
    offset: Offset = 0,
) -> Page[EntityOut]:
    # Listing never loads descriptions or STIX objects (thousands of rows, megabytes each page).
    stmt = select(Entity).options(load_only(*LIST_COLUMNS))
    if type:
        stmt = stmt.where(Entity.type == type)
    if not include_revoked:
        stmt = stmt.where(Entity.revoked.is_(False), Entity.deprecated.is_(False))
    if q:
        stmt = stmt.where(
            or_(
                func.lower(Entity.name).like(_like(q), escape="\\"),
                func.upper(Entity.external_id) == q.upper(),
            )
        )
    stmt = stmt.order_by(Entity.type, Entity.external_id, Entity.name)
    async with _sm(request)() as s:
        if not domain and not tactic:
            total = int(await s.scalar(select(func.count()).select_from(stmt.subquery())) or 0)
            page = (await s.scalars(stmt.limit(limit).offset(offset))).all()
        else:
            # domain/tactic live in JSON lists: filtered here to stay portable across databases
            rows = [
                e
                for e in (await s.scalars(stmt)).all()
                if (not domain or domain in (e.domains or [])) and (not tactic or tactic in (e.tactics or []))
            ]
            total, page = len(rows), rows[offset : offset + limit]
    return Page[EntityOut](
        items=[EntityOut(**_entity_out(e)) for e in page], total=total, limit=limit, offset=offset
    )


@router.get("/entities/{ident}", response_model=EntityDetail, tags=["knowledge"])
async def get_entity(who: Viewer, request: Request, ident: Ident) -> EntityDetail:
    async with _sm(request)() as s:
        node = await _resolve(s, ident, who.clearance)
        if node.kind != "entity":
            raise HTTPException(404, f"{ident} is a {node.kind}, not an entity")
        e = await s.scalar(select(Entity).where(Entity.stix_id == node.ref))
        if e is None:
            raise HTTPException(404, "no such entity")
        counts: dict[str, int] = {}
        for col, label in ((Relationship.src_ref, "out"), (Relationship.dst_ref, "in")):
            for rel, n in (
                await s.execute(
                    select(Relationship.rel_type, func.count())
                    .where(col == e.stix_id, Relationship.revoked.is_(False))
                    .group_by(Relationship.rel_type)
                )
            ).all():
                counts[f"{rel}:{label}"] = int(n)
    return EntityDetail(**_entity_out(e), description=e.description, relationship_counts=counts)


@router.get("/entities/{ident}/techniques", tags=["knowledge"])
async def entity_techniques(
    who: Viewer, request: Request, ident: Ident, include_subtechniques: bool = True
) -> dict[str, Any]:
    """ATT&CK techniques the entity uses, each with the edge that says so."""
    async with _sm(request)() as s:
        node = await _resolve(s, ident, who.clearance)
        items, _total = await graph.neighbors(
            s,
            node.ref,
            direction="out",
            rel="uses",
            node_type="attack-pattern",
            limit=2000,
            clearance=who.clearance,
        )
        ents = {
            e.stix_id: e
            for e in (
                await s.scalars(select(Entity).where(Entity.stix_id.in_([i["node"]["ref"] for i in items])))
            ).all()
        }
    out = []
    for i in items:
        e = ents.get(i["node"]["ref"])
        if e is None or (e.is_subtechnique and not include_subtechniques):
            continue
        out.append(
            {
                "technique": {k: v for k, v in _entity_out(e).items() if k not in ("aliases", "domains")},
                "evidence": i["edge"],
            }
        )
    out.sort(key=lambda x: x["technique"]["external_id"] or "")
    return {"entity": node.__dict__, "count": len(out), "techniques": out}


# ── vulnerabilities ──────────────────────────────────────────────────────────


@router.get("/vulnerabilities", response_model=Page[VulnOut], tags=["knowledge"])
async def list_vulnerabilities(
    who: Viewer,
    request: Request,
    kev: bool | None = None,
    epss_min: Annotated[float | None, Query(ge=0, le=1)] = None,
    cvss_min: Annotated[float | None, Query(ge=0, le=10)] = None,
    vendor: Annotated[str | None, Query(max_length=200)] = None,
    product: Annotated[str | None, Query(max_length=200)] = None,
    q: Annotated[str | None, Query(min_length=2, max_length=200)] = None,
    sort: Literal["epss", "cvss", "published", "kev_date", "cve", "patch"] = "epss",
    patch_priority: Literal["P1", "P2", "P3", "P4"] | None = None,
    limit: Limit = 50,
    offset: Offset = 0,
) -> Page[VulnOut]:
    stmt = select(Vulnerability)
    if patch_priority is not None:
        stmt = stmt.where(Vulnerability.patch_priority == patch_priority)
    if kev is not None:
        stmt = stmt.where(Vulnerability.kev.is_(kev))
    if epss_min is not None:
        stmt = stmt.where(Vulnerability.epss >= epss_min)
    if cvss_min is not None:
        stmt = stmt.where(Vulnerability.cvss_score >= cvss_min)
    if vendor or product:
        sub = select(VulnerabilityProduct.vulnerability_id)
        if vendor:
            sub = sub.where(VulnerabilityProduct.vendor == vendor.lower())
        if product:
            sub = sub.where(VulnerabilityProduct.product == product.lower())
        stmt = stmt.where(Vulnerability.id.in_(sub))
    if q:
        stmt = stmt.where(
            or_(
                func.lower(Vulnerability.cve_id).like(_like(q), escape="\\"),
                func.lower(Vulnerability.description).like(_like(q), escape="\\"),
            )
        )
    key: dict[str, Any] = {
        "epss": Vulnerability.epss,
        "cvss": Vulnerability.cvss_score,
        "published": Vulnerability.published,
        "kev_date": Vulnerability.kev_date_added,
        "patch": Vulnerability.patch_score,
    }
    order = [key[sort].desc().nulls_last(), Vulnerability.cve_id] if sort in key else [Vulnerability.cve_id]
    async with _sm(request)() as s:
        total = int(await s.scalar(select(func.count()).select_from(stmt.subquery())) or 0)
        rows = (await s.scalars(stmt.order_by(*order).limit(limit).offset(offset))).all()
    return Page[VulnOut](
        items=[VulnOut(**_vuln_out(v)) for v in rows], total=total, limit=limit, offset=offset
    )


@router.get("/vulnerabilities/{cve}", response_model=VulnDetail, tags=["knowledge"])
async def get_vulnerability(
    _: Viewer, request: Request, cve: Annotated[str, Path(max_length=32)]
) -> VulnDetail:
    async with _sm(request)() as s:
        v = await s.scalar(select(Vulnerability).where(Vulnerability.cve_id == cve.upper()))
        if v is None:
            raise HTTPException(404, "CVE not tracked")
        products = (
            await s.scalars(select(VulnerabilityProduct).where(VulnerabilityProduct.vulnerability_id == v.id))
        ).all()
    sources: dict[str, Any] = {}
    if v.nvd_modified:
        sources["nvd"] = {"last_modified": v.nvd_modified.isoformat()}
    if v.kev:
        sources["cisa_kev"] = {"date_added": v.kev_date_added.isoformat() if v.kev_date_added else None}
    if v.epss_date:
        sources["epss"] = {"score_date": v.epss_date.isoformat()}
    if v.osv_checked_at:
        sources["osv"] = {"checked_at": v.osv_checked_at.isoformat()}
    return VulnDetail(
        **_vuln_out(v),
        nvd_modified=v.nvd_modified,
        vuln_status=v.vuln_status,
        cvss_vector=v.cvss_vector,
        cvss=v.cvss or [],
        cwes=v.cwes or [],
        cpes=v.cpes or [],
        products=[{"part": p.part, "vendor": p.vendor, "product": p.product} for p in products],
        references=v.references or [],
        ssvc=v.ssvc or {},
        kev_due_date=v.kev_due_date,
        kev_ransomware=v.kev_ransomware,
        kev_name=v.kev_name,
        kev_required_action=v.kev_required_action,
        epss_date=v.epss_date,
        osv_ids=v.osv_ids or [],
        packages=v.packages or [],
        exploit_signals=exploit_signals(v),
        sources=sources,
        patch_breakdown=v.patch_breakdown,
    )


# ── graph ────────────────────────────────────────────────────────────────────


@router.get("/graph/node", tags=["graph"])
async def graph_node(
    who: Viewer, request: Request, node: Annotated[str, Query(min_length=1, max_length=300)]
) -> dict[str, Any]:
    async with _sm(request)() as s:
        return (await _resolve(s, node, who.clearance)).__dict__


@router.get("/graph/neighbors", tags=["graph"])
async def graph_neighbors(
    who: Viewer,
    request: Request,
    node: Annotated[str, Query(min_length=1, max_length=300)],
    rel: Annotated[str | None, Query(max_length=40)] = None,
    type: Annotated[str | None, Query(max_length=40)] = None,  # noqa: A002 - public API name
    direction: Literal["out", "in", "both"] = "both",
    limit: Limit = 200,
) -> dict[str, Any]:
    async with _sm(request)() as s:
        n = await _resolve(s, node, who.clearance)
        items, total = await graph.neighbors(
            s, n.ref, direction=direction, rel=rel, node_type=type, limit=limit, clearance=who.clearance
        )
    return {"node": n.__dict__, "total": total, "items": items}


@router.get("/graph/paths", tags=["graph"])
async def graph_paths(
    who: Viewer,
    request: Request,
    from_: Annotated[str, Query(alias="from", min_length=1, max_length=300)],
    to: Annotated[str, Query(min_length=1, max_length=300)],
    max_depth: Annotated[int, Query(ge=1, le=6)] = 4,
    limit: Annotated[int, Query(ge=1, le=50)] = 5,
) -> dict[str, Any]:
    """Shortest paths between two nodes; every edge carries its provenance."""
    async with _sm(request)() as s:
        a = await _resolve(s, from_, who.clearance)
        b = await _resolve(s, to, who.clearance)
        res = await graph.paths(s, a.ref, b.ref, max_depth=max_depth, limit=limit, clearance=who.clearance)
    return {
        "from": a.__dict__,
        "to": b.__dict__,
        "length": res.length,
        "truncated": res.truncated,
        "paths": res.paths,
        "nodes": res.nodes,
    }
