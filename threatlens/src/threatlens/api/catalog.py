"""Feed catalog API (ADR 0012): switch sources on and off, queue a pull of
every enabled source, and add, edit or remove custom feeds. Admin keys only;
reading the contribution of a source needs a viewer key and respects TLP.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, BackgroundTasks, HTTPException, Path, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from threatlens import catalog
from threatlens.api.v1 import Admin, SourceOut, Viewer, _app_settings, _sm, _source_out
from threatlens.ioc.defang import defang
from threatlens.ioc.types import IOCType
from threatlens.models import AuditLog, Source
from threatlens.scoring.store import rescore
from threatlens.settings import Settings
from threatlens.vault import VaultError

router = APIRouter(prefix="/api/v1", tags=["sources"])
Name = Annotated[str, Path(max_length=64)]


class FeedIn(BaseModel):
    title: str = Field(min_length=3, max_length=80)
    url: str = Field(min_length=8, max_length=2000)
    format: Literal["text", "csv", "json"] = "text"
    ioc_type: Literal["auto", "ip", "domain", "url", "hash"] = "auto"
    verdict: Literal["malicious", "suspicious"] = "malicious"
    confidence: int = Field(default=70, ge=0, le=100)
    interval_minutes: int = Field(default=360, ge=catalog.MIN_MINUTES, le=catalog.MAX_MINUTES)
    tlp: str = "TLP:CLEAR"
    reliability: Literal["A", "B", "C", "D", "E", "F"] = "C"
    comment_char: str = Field(default="#", max_length=4)
    value_column: int = Field(default=0, ge=0, le=255)
    json_path: str = Field(default="", max_length=200)
    auth_header: str = Field(default="", max_length=64)
    secret: str = Field(default="", max_length=4000, description="sent in auth_header; stored encrypted")
    clear_secret: bool = False
    upstream: str = Field(default="", max_length=60, description="original producer, for corroboration")


class EnabledIn(BaseModel):
    enabled: bool


async def queue_runs(request: Request, names: list[str], actor: str) -> list[str]:
    """Queue a pull of each source (never faster than the source allows: a
    queued run that comes too soon is recorded as "too soon")."""
    enqueue = getattr(request.app.state, "enqueue", None)
    if enqueue is None:
        raise HTTPException(503, "no worker queue: start the worker to pull feeds")
    queued = [n for n in names if await enqueue(n, False)]
    async with _sm(request)() as s, s.begin():
        s.add(AuditLog(actor=actor[:100], action="source.sync", target=",".join(names)[:500],
                       details={"queued": queued}))  # fmt: skip
    return queued


def forget_enabled(request: Request) -> None:
    """An enricher switched on or off applies to this process's next lookup."""
    svc = getattr(request.app.state, "enrich", None)
    if svc is not None:
        svc.forget_enabled()


async def enabled_sources(sm: async_sessionmaker[AsyncSession]) -> list[str]:
    async with sm() as s:
        custom = await catalog.custom_names(s)
        rows = (await s.scalars(select(Source).where(Source.enabled.is_(True)).order_by(Source.name))).all()
    return [r.name for r in rows if catalog.collectable(r, custom)]


async def rescore_ids(sm: async_sessionmaker[AsyncSession], settings: Settings, ids: list[int]) -> None:
    if ids:
        await rescore(sm, settings, ids=ids)


@router.post("/sources/sync", status_code=202)
async def sync_all(who: Admin, request: Request) -> dict[str, Any]:
    names = await enabled_sources(_sm(request))
    queued = await queue_runs(request, names, who.name)
    return {"sources": names, "queued": queued}


@router.patch("/sources/{name}", response_model=SourceOut)
async def set_enabled(who: Admin, request: Request, name: Name, body: EnabledIn) -> SourceOut:
    try:
        async with _sm(request)() as s, s.begin():
            src = await catalog.set_enabled(s, name, body.enabled, actor=who.name)
    except catalog.CatalogError as e:
        raise HTTPException(404, str(e)) from None
    forget_enabled(request)
    return _source_out(src, _app_settings(request))


def _form(body: FeedIn) -> catalog.FeedForm:
    return catalog.FeedForm(**body.model_dump())


@router.post("/sources/custom", response_model=SourceOut, status_code=201)
async def create_feed(who: Admin, request: Request, body: FeedIn) -> SourceOut:
    try:
        async with _sm(request)() as s, s.begin():
            src = await catalog.create(s, _form(body), actor=who.name, settings=_app_settings(request))
    except (catalog.CatalogError, VaultError) as e:
        raise HTTPException(422, str(e)) from None
    return _source_out(src, _app_settings(request))


@router.put("/sources/custom/{name}", response_model=SourceOut)
async def edit_feed(who: Admin, request: Request, name: Name, body: FeedIn) -> SourceOut:
    try:
        async with _sm(request)() as s, s.begin():
            src = await catalog.edit(s, name, _form(body), actor=who.name, settings=_app_settings(request))
    except (catalog.CatalogError, VaultError) as e:
        raise HTTPException(404 if "no such" in str(e) else 422, str(e)) from None
    return _source_out(src, _app_settings(request))


@router.delete("/sources/custom/{name}")
async def remove_feed(who: Admin, request: Request, name: Name, tasks: BackgroundTasks) -> dict[str, Any]:
    try:
        async with _sm(request)() as s, s.begin():
            ids = await catalog.remove(s, name, actor=who.name)
    except catalog.CatalogError as e:
        raise HTTPException(404, str(e)) from None
    tasks.add_task(rescore_ids, _sm(request), _app_settings(request), ids)
    return {"removed": name, "indicators": len(ids)}


@router.get("/sources/{name}/contribution")
async def contribution(who: Viewer, request: Request, name: Name) -> dict[str, Any]:
    async with _sm(request)() as s:
        src = await s.scalar(select(Source).where(Source.name == name))
        if src is None:
            raise HTTPException(404, "unknown source")
        c = await catalog.contribution(s, src.id, who.clearance)
    top = [
        {"id": ind.id, "type": obs.type, "value": defang(obs.value, IOCType(obs.type)),
         "priority_score": ind.priority_score, "tlp": ind.tlp}
        for ind, obs in c.pop("top")
    ]  # fmt: skip
    return c | {"top": top}
