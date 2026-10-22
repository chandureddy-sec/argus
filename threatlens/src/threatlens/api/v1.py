"""REST API v1: sources and their health, indicators (with their scores and
analyst feedback), IOC extraction, and the allowlist.

Every route requires an API key; responses are explicit Pydantic models so
no database object is ever serialized directly (OWASP API3). Indicators above
the caller's TLP clearance don't exist for that caller (ADR 0008).
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Path, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload

from threatlens import catalog
from threatlens import tlp as tlp_rules
from threatlens.auth import Principal, require
from threatlens.collect import reapply_allowlist
from threatlens.connectors import REGISTRY
from threatlens.enrich import REGISTRY as ENRICHERS
from threatlens.ioc.defang import defang
from threatlens.ioc.extract import extract
from threatlens.ioc.normalize import normalize
from threatlens.ioc.types import IOCType, Observable, Rejected
from threatlens.kb import KB_REGISTRY
from threatlens.models import AllowlistEntry, AuditLog, ConnectorRun, Indicator, Sighting, Source
from threatlens.models import Observable as ObsRow
from threatlens.scoring.feedback import give_feedback, history, rescore_sources
from threatlens.settings import Settings, get_settings

router = APIRouter(prefix="/api/v1")
Viewer = Annotated[Principal, Depends(require("viewer"))]
Analyst = Annotated[Principal, Depends(require("analyst"))]
Admin = Annotated[Principal, Depends(require("admin"))]
Limit = Annotated[int, Query(ge=1, le=500)]
Offset = Annotated[int, Query(ge=0, le=1_000_000)]


def _sm(request: Request) -> async_sessionmaker[AsyncSession]:
    sm: async_sessionmaker[AsyncSession] = request.app.state.sessionmaker
    return sm


def _app_settings(request: Request) -> Settings:
    s: Settings = getattr(request.app.state, "settings", None) or get_settings()
    return s


# ── schemas ──────────────────────────────────────────────────────────────────


class SourceOut(BaseModel):
    name: str
    title: str
    kind: str
    reliability: str
    reliability_note: str
    credibility: int = Field(description="Admiralty information credibility 1-6 (6: cannot be judged)")
    weight_factor: float = Field(description="from analyst TP/FP feedback; multiplies the reliability weight")
    feedback_tp: int
    feedback_fp: int
    license: str
    license_url: str
    commercial_use: bool
    redistribution: bool
    attribution: str | None
    requires_key: bool
    key_configured: bool
    enabled: bool
    health: str
    interval_minutes: int
    last_run_at: datetime | None
    last_success_at: datetime | None
    next_run_at: datetime | None
    last_error: str | None
    custom: bool = Field(default=False, description="added in the feed catalog (ADR 0012)")


class RunOut(BaseModel):
    started_at: datetime
    finished_at: datetime | None
    status: str
    http_status: int | None
    items_total: int
    items_new: int
    items_updated: int
    items_rejected: int
    items_allowlisted: int
    error: str | None


class SightingOut(BaseModel):
    source: str
    first_seen: datetime
    last_seen: datetime
    times_reported: int
    confidence: int
    labels: list[str]
    context: dict[str, Any]


class IndicatorOut(BaseModel):
    id: int
    type: str
    value: str
    defanged: str
    status: str
    confidence: int
    tlp: str
    labels: list[str]
    pattern: str | None
    allowlist_reason: str | None
    first_seen: datetime
    last_seen: datetime
    sources: list[str]
    priority_score: float | None = Field(description="0-100, scoring model v1 (ADR 0008)")
    verdict: str | None = Field(description="malicious | suspicious | benign | unknown, from the score")
    valid_until: datetime | None = Field(description="when it expires unless a source reports it again")
    analyst_verdict: str | None = Field(description="tp | fp: the latest analyst feedback")


class FeedbackOut(BaseModel):
    verdict: str
    actor: str
    note: str
    at: datetime


class IndicatorDetail(IndicatorOut):
    sightings: list[SightingOut]
    score_breakdown: dict[str, Any] | None
    feedback: list[FeedbackOut]


class FeedbackIn(BaseModel):
    verdict: Literal["tp", "fp", "reset"] = Field(
        description="tp: confirmed malicious; fp: not malicious (score 0, never re-activated); "
        "reset: remove the analyst decision"
    )
    note: str = Field(default="", max_length=2000)


class WeightChangeOut(BaseModel):
    source: str
    tp: int
    fp: int
    before: float
    after: float


class FeedbackResult(BaseModel):
    indicator: IndicatorDetail
    source_weights: list[WeightChangeOut]


class Page[T](BaseModel):
    items: list[T]
    total: int
    limit: int
    offset: int


class ExtractIn(BaseModel):
    text: str = Field(max_length=1_000_000)
    include_rejected: bool = False


class ExtractedOut(BaseModel):
    type: str
    value: str
    defanged: str


class RejectedOut(BaseModel):
    type: str | None
    raw: str
    reason: str


class ExtractOut(BaseModel):
    observables: list[ExtractedOut]
    rejected: list[RejectedOut]


class AllowlistIn(BaseModel):
    kind: Literal["domain", "cidr"]
    value: str = Field(min_length=1, max_length=300)
    effect: Literal["suppress", "flag"] = "suppress"
    reason: str = Field(min_length=3, max_length=500)


class AllowlistOut(BaseModel):
    id: int
    kind: str
    value: str
    effect: str
    reason: str
    origin: str
    created_by: str
    created_at: datetime


# ── sources ──────────────────────────────────────────────────────────────────


def _key_configured(name: str, settings: Settings) -> bool:
    cls = REGISTRY.get(name) or KB_REGISTRY.get(name) or ENRICHERS.get(name)
    attr = cls.info.key_setting if cls else None
    return bool(attr and getattr(settings, attr, None))


def _source_out(s: Source, settings: Settings) -> SourceOut:
    return SourceOut(
        **{k: getattr(s, k) for k in SourceOut.model_fields if k not in ("key_configured", "custom")},
        key_configured=_key_configured(s.name, settings) or (s.kind.startswith("custom") and s.requires_key),
        custom=s.kind.startswith("custom"),
    )


@router.get("/sources", response_model=list[SourceOut], tags=["sources"])
async def list_sources(_: Viewer, request: Request) -> list[SourceOut]:
    svc = getattr(request.app.state, "enrich", None)
    if svc is not None:  # lookup providers get their rows on first use; list them before that
        await svc.ensure_sources()
    async with _sm(request)() as s:
        rows = (await s.scalars(select(Source).order_by(Source.name))).all()
    settings: Settings = getattr(request.app.state, "settings", None) or get_settings()
    return [_source_out(r, settings) for r in rows]


@router.get("/sources/{name}/runs", response_model=list[RunOut], tags=["sources"])
async def source_runs(
    _: Viewer, request: Request, name: Annotated[str, Path(max_length=64)], limit: Limit = 20
) -> list[RunOut]:
    async with _sm(request)() as s:
        src = await s.scalar(select(Source).where(Source.name == name))
        if src is None:
            raise HTTPException(404, "unknown source")
        runs = (
            await s.scalars(
                select(ConnectorRun)
                .where(ConnectorRun.source_id == src.id)
                .order_by(ConnectorRun.started_at.desc(), ConnectorRun.id.desc())
                .limit(limit)
            )
        ).all()
    return [RunOut.model_validate(r, from_attributes=True) for r in runs]


@router.post("/sources/{name}/run", status_code=202, tags=["sources"])
async def trigger_run(
    who: Admin, request: Request, name: Annotated[str, Path(max_length=64)], force: bool = False
) -> dict[str, Any]:
    async with _sm(request)() as s:
        src = await s.scalar(select(Source).where(Source.name == name))
        custom = await catalog.custom_names(s)
    if src is None or not catalog.collectable(src, custom):
        raise HTTPException(404, "unknown source")
    queued = await request.app.state.enqueue(name, force)
    async with _sm(request)() as s, s.begin():
        s.add(AuditLog(actor=who.name, action="source.run", target=name, details={"force": force}))
    return {"source": name, "queued": bool(queued)}


# ── indicators ───────────────────────────────────────────────────────────────


def _indicator_out(ind: Indicator, obs: ObsRow, sources: list[str]) -> dict[str, Any]:
    bd = ind.score_breakdown or {}
    return {
        "priority_score": ind.priority_score,
        "verdict": bd.get("verdict"),
        "valid_until": ind.valid_until,
        "analyst_verdict": ind.analyst_verdict,
        "id": ind.id,
        "type": obs.type,
        "value": obs.value,
        "defanged": obs.defanged,
        "status": ind.status,
        "confidence": ind.confidence,
        "tlp": ind.tlp,
        "labels": ind.labels or [],
        "pattern": ind.pattern,
        "allowlist_reason": ind.allowlist_reason,
        "first_seen": obs.first_seen,
        "last_seen": obs.last_seen,
        "sources": sources,
    }


def _utc(v: datetime) -> datetime:
    return v if v.tzinfo else v.replace(tzinfo=UTC)


@router.get("/indicators", response_model=Page[IndicatorOut], tags=["indicators"])
async def list_indicators(
    who: Viewer,
    request: Request,
    type: Annotated[IOCType | None, Query()] = None,  # noqa: A002 - public API name
    status: Annotated[
        Literal["new", "active", "expired", "revoked", "false_positive"] | None, Query()
    ] = None,
    source: Annotated[str | None, Query(max_length=64)] = None,
    q: Annotated[str | None, Query(min_length=2, max_length=200)] = None,
    limit: Limit = 50,
    offset: Offset = 0,
    sort: Literal["recent", "priority"] = "recent",
    min_score: Annotated[float | None, Query(ge=0, le=100)] = None,
    added_from: Annotated[datetime | None, Query(description="added at or after (ISO date or time)")] = None,
    added_until: Annotated[datetime | None, Query(description="added before (ISO date or time)")] = None,
) -> Page[IndicatorOut]:
    stmt = (
        select(Indicator, ObsRow)
        .join(ObsRow, Indicator.observable_id == ObsRow.id)
        .where(Indicator.tlp.in_(tlp_rules.readable(who.clearance)))
    )
    if min_score is not None:
        stmt = stmt.where(Indicator.priority_score >= min_score)
    if added_from is not None:
        stmt = stmt.where(Indicator.created_at >= _utc(added_from))
    if added_until is not None:
        stmt = stmt.where(Indicator.created_at < _utc(added_until))
    if type is not None:
        stmt = stmt.where(ObsRow.type == type.value)
    if status is not None:
        stmt = stmt.where(Indicator.status == status)
    if source is not None:
        stmt = stmt.where(
            Indicator.id.in_(select(Sighting.indicator_id).join(Source).where(Source.name == source))
        )
    if q is not None:
        # Parameterized LIKE with the wildcards in user input escaped.
        pattern = "%" + q.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        stmt = stmt.where(ObsRow.value.ilike(pattern, escape="\\"))  # trigram-indexed on Postgres
    async with _sm(request)() as s:
        total = int(await s.scalar(select(func.count()).select_from(stmt.subquery())) or 0)
        order = (
            (Indicator.priority_score.desc().nulls_last(), Indicator.id.desc())
            if sort == "priority"
            else (ObsRow.last_seen.desc(), ObsRow.id.desc())  # ix_observables_type_seen
        )
        rows = (await s.execute(stmt.order_by(*order).limit(limit).offset(offset))).all()
        ids = [ind.id for ind, _ in rows]
        names: dict[int, list[str]] = {}
        for ind_id, src_name in (
            await s.execute(
                select(Sighting.indicator_id, Source.name).join(Source).where(Sighting.indicator_id.in_(ids))
            )
        ).all():
            names.setdefault(ind_id, []).append(src_name)
    items = [IndicatorOut(**_indicator_out(ind, obs, sorted(names.get(ind.id, [])))) for ind, obs in rows]
    return Page[IndicatorOut](items=items, total=total, limit=limit, offset=offset)


@router.get("/indicators/{indicator_id}", response_model=IndicatorDetail, tags=["indicators"])
async def get_indicator(who: Viewer, request: Request, indicator_id: int) -> IndicatorDetail:
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
            raise HTTPException(404, "no such indicator")  # above clearance: as if it didn't exist
        sightings = [
            SightingOut(
                source=sg.source.name,
                first_seen=sg.first_seen,
                last_seen=sg.last_seen,
                times_reported=sg.times_reported,
                confidence=sg.confidence,
                labels=sg.labels or [],
                context=sg.context or {},
            )
            for sg in ind.sightings
        ]
        base = _indicator_out(ind, ind.observable, sorted(x.source for x in sightings))
        fb = [FeedbackOut(**f) for f in await history(s, ind.id)]
    return IndicatorDetail(**base, sightings=sightings, score_breakdown=ind.score_breakdown, feedback=fb)


@router.post("/indicators/{indicator_id}/feedback", response_model=FeedbackResult, tags=["indicators"])
async def indicator_feedback(
    who: Analyst, request: Request, indicator_id: int, body: FeedbackIn, tasks: BackgroundTasks
) -> FeedbackResult:
    """Analyst true/false-positive feedback. Updates the indicator and its score
    at once, re-derives every source's weight from all verdicts (each change is
    audited) and re-scores the affected sources' indicators in the background."""
    await get_indicator(who, request, indicator_id)  # 404 when missing or above clearance
    changes = await give_feedback(
        _sm(request), _app_settings(request), indicator_id, body.verdict, actor=who.name, note=body.note
    )
    if changes:
        tasks.add_task(rescore_sources, _sm(request), _app_settings(request), [c.source for c in changes])
    return FeedbackResult(
        indicator=await get_indicator(who, request, indicator_id),
        source_weights=[WeightChangeOut(**c.__dict__) for c in changes],
    )


# ── extraction ───────────────────────────────────────────────────────────────


@router.post("/extract", response_model=ExtractOut, tags=["tools"])
async def extract_iocs(_: Analyst, body: ExtractIn) -> ExtractOut:
    """Extract and normalize IOCs from free text. Nothing is stored."""
    obs: list[ExtractedOut] = []
    rej: list[RejectedOut] = []
    for r in extract(body.text, include_rejected=body.include_rejected):
        if isinstance(r, Observable):
            obs.append(ExtractedOut(type=r.type.value, value=r.value, defanged=defang(r.value, r.type)))
        elif isinstance(r, Rejected):
            rej.append(RejectedOut(type=r.type.value if r.type else None, raw=r.raw[:300], reason=r.reason))
    return ExtractOut(observables=obs, rejected=rej)


# ── allowlist ────────────────────────────────────────────────────────────────


@router.get("/allowlist", response_model=Page[AllowlistOut], tags=["allowlist"])
async def list_allowlist(
    _: Viewer,
    request: Request,
    origin: Annotated[str | None, Query(max_length=32)] = None,
    limit: Limit = 100,
    offset: Offset = 0,
) -> Page[AllowlistOut]:
    stmt = select(AllowlistEntry)
    if origin:
        stmt = stmt.where(AllowlistEntry.origin == origin)
    async with _sm(request)() as s:
        total = int(await s.scalar(select(func.count()).select_from(stmt.subquery())) or 0)
        rows = (await s.scalars(stmt.order_by(AllowlistEntry.id).limit(limit).offset(offset))).all()
    return Page[AllowlistOut](
        items=[AllowlistOut.model_validate(r, from_attributes=True) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


def _canonical_entry(kind: str, value: str) -> str:
    if kind == "cidr":
        try:
            return str(ipaddress.ip_network(value.strip(), strict=False))
        except ValueError as e:
            raise HTTPException(422, f"not a CIDR range: {e}") from e
    r = normalize(IOCType.DOMAIN, value)
    if not isinstance(r, Observable):
        raise HTTPException(422, f"not a domain: {r.reason}")
    return r.value


@router.post("/allowlist", response_model=AllowlistOut, status_code=201, tags=["allowlist"])
async def add_allowlist(
    who: Admin, request: Request, body: AllowlistIn, tasks: BackgroundTasks
) -> AllowlistOut:
    value = _canonical_entry(body.kind, body.value)
    async with _sm(request)() as s, s.begin():
        dup = await s.scalar(
            select(AllowlistEntry).where(
                AllowlistEntry.kind == body.kind,
                AllowlistEntry.value == value,
                AllowlistEntry.origin == "manual",
            )
        )
        if dup is not None:
            raise HTTPException(409, "already on the allowlist")
        row = AllowlistEntry(
            kind=body.kind,
            value=value,
            effect=body.effect,
            reason=body.reason,
            origin="manual",
            created_by=who.name,
        )
        s.add(row)
        s.add(
            AuditLog(
                actor=who.name,
                action="allowlist.add",
                target=f"{body.kind}:{value}",
                details=body.model_dump(),
            )
        )
        await s.flush()
        out = AllowlistOut.model_validate(row, from_attributes=True)
    tasks.add_task(reapply_allowlist, _sm(request), _app_settings(request))
    return out


@router.delete("/allowlist/{entry_id}", status_code=204, tags=["allowlist"])
async def delete_allowlist(who: Admin, request: Request, entry_id: int, tasks: BackgroundTasks) -> None:
    async with _sm(request)() as s, s.begin():
        row = await s.get(AllowlistEntry, entry_id)
        if row is None:
            raise HTTPException(404, "no such entry")
        if row.origin != "manual":
            raise HTTPException(
                403, f"{row.origin} entries are managed by the allowlist refresh, not by hand"
            )
        await s.delete(row)
        s.add(
            AuditLog(actor=who.name, action="allowlist.delete", target=f"{row.kind}:{row.value}", details={})
        )
    tasks.add_task(reapply_allowlist, _sm(request), _app_settings(request))
