"""API v1 own assets (Phase 3b, ADR 0006): import ReconX scans, list assets
(those a feed lists first), and the observed tech stack with its exposure."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from threatlens import assets as asset_store
from threatlens.api.v1 import Analyst, Limit, Offset, Page, Viewer
from threatlens.models import Asset, AssetImport, AssetProduct, Vulnerability, VulnerabilityProduct

router = APIRouter(prefix="/api/v1/assets", tags=["assets"])
MAX_IMPORT_BYTES = 50 * 1024 * 1024


def _sm(request: Request) -> async_sessionmaker[AsyncSession]:
    sm: async_sessionmaker[AsyncSession] = request.app.state.sessionmaker
    return sm


class ImportOut(BaseModel):
    import_id: int | None
    duplicate: bool
    target: str
    scanned_at: datetime | None
    hosts: int
    ips: int
    products: int
    new_assets: int
    updated_assets: int
    rejected: list[dict[str, str]]


class FlagOut(BaseModel):
    indicator_id: int
    status: str
    confidence: int
    priority_score: float | None = None
    sources: list[str]


class AssetOut(BaseModel):
    id: int
    kind: str
    value: str
    target: str
    origin: str
    first_seen: datetime
    last_seen: datetime
    details: dict[str, Any]
    products: list[str]
    indicator: FlagOut | None


class ProductOut(BaseModel):
    vendor: str
    product: str
    versions: list[str]
    assets: int
    cves: int
    kev_cves: int


class ImportRow(BaseModel):
    id: int
    source: str
    target: str
    scanned_at: datetime | None
    imported_at: datetime
    imported_by: str
    counts: dict[str, Any]


@router.post("/import/reconx", response_model=ImportOut)
async def import_reconx(who: Analyst, request: Request) -> dict[str, Any]:
    """Import a ReconX scan report (its JSON file, as the request body) as the
    organization's own assets and observed tech stack. Import only scans of
    your own targets. Re-sending the same file changes nothing."""
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_IMPORT_BYTES:
        raise HTTPException(413, f"report larger than {MAX_IMPORT_BYTES // (1024 * 1024)} MB")
    body = await request.body()
    if len(body) > MAX_IMPORT_BYTES:
        raise HTTPException(413, f"report larger than {MAX_IMPORT_BYTES // (1024 * 1024)} MB")
    try:
        doc = json.loads(body)
    except ValueError as e:
        raise HTTPException(422, "body is not JSON") from e
    try:
        s = await asset_store.import_reconx(_sm(request), doc, hashlib.sha256(body).hexdigest(), who.name)
    except asset_store.ImportFormatError as e:
        raise HTTPException(422, str(e)) from e
    return s.__dict__


@router.get("", response_model=Page[AssetOut])
async def list_assets(
    who: Viewer,
    request: Request,
    kind: Literal["domain", "host", "ip"] | None = None,
    flagged: bool = False,
    q: Annotated[str | None, Query(min_length=2, max_length=200)] = None,
    limit: Limit = 100,
    offset: Offset = 0,
) -> Page[AssetOut]:
    """Own assets; those that are also indicators (a feed lists them) first.
    ``flagged=true`` returns only assets an active indicator matches."""
    async with _sm(request)() as s:
        flags = await asset_store.flagged_keys(s, who.clearance)
        stmt = select(Asset)
        if kind:
            stmt = stmt.where(Asset.kind == kind)
        if q:
            like = "%" + q.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            stmt = stmt.where(func.lower(Asset.value).like(like, escape="\\"))
        if flagged:
            active = [k for k, v in flags.items() if v["status"] in ("active", "new")]
            stmt = stmt.where(Asset.canonical_key.in_(active))
        total = int(await s.scalar(select(func.count()).select_from(stmt.subquery())) or 0)
        rows = list((await s.scalars(stmt.order_by(Asset.kind, Asset.value))).all())
        rows.sort(key=lambda a: (a.canonical_key not in flags, a.kind, a.value))
        rows = rows[offset : offset + limit]
        prods: dict[int, list[str]] = {}
        for aid, cpe in (
            await s.execute(
                select(AssetProduct.asset_id, AssetProduct.cpe).where(
                    AssetProduct.asset_id.in_([a.id for a in rows])
                )
            )
        ).all():
            prods.setdefault(aid, []).append(cpe)
    items = [
        AssetOut(
            id=a.id, kind=a.kind, value=a.value, target=a.target, origin=a.origin,
            first_seen=a.first_seen, last_seen=a.last_seen, details=a.details,
            products=sorted(prods.get(a.id, [])),
            indicator=FlagOut(**flags[a.canonical_key]) if a.canonical_key in flags else None,
        )
        for a in rows
    ]  # fmt: skip
    return Page[AssetOut](items=items, total=total, limit=limit, offset=offset)


@router.get("/products", response_model=list[ProductOut])
async def products(_: Viewer, request: Request) -> list[ProductOut]:
    """The observed tech stack: each (vendor, product) seen on own assets, how
    many assets run it, and how many known CVEs (and KEV CVEs) affect it."""
    async with _sm(request)() as s:
        rows = (
            await s.execute(
                select(
                    AssetProduct.vendor,
                    AssetProduct.product,
                    func.count(func.distinct(AssetProduct.asset_id)),
                )
                .group_by(AssetProduct.vendor, AssetProduct.product)
                .order_by(func.count(func.distinct(AssetProduct.asset_id)).desc(), AssetProduct.vendor)
            )
        ).all()
        versions: dict[tuple[str, str], set[str]] = {}
        for v, p, ver in (
            await s.execute(select(AssetProduct.vendor, AssetProduct.product, AssetProduct.version))
        ).all():
            if ver:
                versions.setdefault((v, p), set()).add(ver)
        out = []
        for vendor, product, n in rows:
            match = and_(VulnerabilityProduct.vendor == vendor, VulnerabilityProduct.product == product)
            cves, kev = (
                await s.execute(
                    select(
                        func.count(func.distinct(Vulnerability.id)),
                        func.count(func.distinct(Vulnerability.id)).filter(Vulnerability.kev.is_(True)),
                    )
                    .join(VulnerabilityProduct, VulnerabilityProduct.vulnerability_id == Vulnerability.id)
                    .where(match)
                )
            ).one()
            out.append(
                ProductOut(
                    vendor=vendor, product=product, versions=sorted(versions.get((vendor, product), set())),
                    assets=int(n), cves=int(cves or 0), kev_cves=int(kev or 0),
                )
            )  # fmt: skip
    return out


@router.get("/imports", response_model=list[ImportRow])
async def imports(_: Viewer, request: Request, limit: Limit = 20) -> list[ImportRow]:
    async with _sm(request)() as s:
        rows = (
            await s.scalars(select(AssetImport).order_by(AssetImport.imported_at.desc()).limit(limit))
        ).all()
    return [ImportRow.model_validate(r, from_attributes=True) for r in rows]
