"""Cases and indicator notes over the API (Phase 5, ADR 0009).

Reads need a viewer key, writes an analyst key. A case above the caller's TLP
clearance does not exist for them (404), and nothing can be added that the
caller couldn't read.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field

from threatlens import cases as case_store
from threatlens.api.enrich import NOT_LOOKUPS
from threatlens.api.v1 import Analyst, Viewer, _sm, get_indicator
from threatlens.ioc.extract import extract
from threatlens.ioc.types import Observable
from threatlens.models import AuditLog, Case

router = APIRouter(prefix="/api/v1", tags=["cases"])
TLP = Literal["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"]
Severity = Literal["low", "medium", "high", "critical"]


class CaseIn(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    severity: Severity = "medium"
    tlp: TLP = "TLP:AMBER"
    summary: str = Field(default="", max_length=20_000)


class CasePatch(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    status: Literal["open", "closed"] | None = None
    severity: Severity | None = None
    summary: str | None = Field(default=None, max_length=20_000)
    conclusion: str | None = Field(default=None, max_length=20_000)


class ItemIn(BaseModel):
    kind: Literal["indicator", "vulnerability", "entity", "note"] | None = Field(
        default=None,
        description="with ref: an indicator id, a CVE id or an entity STIX id; note: needs `note`",
    )
    ref: str = Field(default="", max_length=300)
    values: list[str] = Field(default_factory=list, max_length=500, description="values to look up and add")
    note: str = Field(default="", max_length=5000)


class ItemOut(BaseModel):
    id: int
    kind: str
    ref: str
    label: str
    snapshot: dict[str, Any]
    note: str
    tlp: str
    added_by: str
    added_at: datetime


class CaseOut(BaseModel):
    id: int
    title: str
    status: str
    severity: str
    tlp: str
    summary: str
    conclusion: str
    created_by: str
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None
    items: int


class CaseDetail(CaseOut):
    evidence: list[ItemOut]


class NoteIn(BaseModel):
    body: str = Field(min_length=1, max_length=5000)


class NoteOut(BaseModel):
    id: int
    author: str
    body: str
    created_at: datetime


def _out(c: Case, n: int) -> dict[str, Any]:
    return {k: getattr(c, k) for k in CaseOut.model_fields if k != "items"} | {"items": n}


def _detail(c: Case) -> CaseDetail:
    return CaseDetail(
        **_out(c, len(c.items)),
        evidence=[ItemOut.model_validate(i, from_attributes=True) for i in c.items],
    )


@router.get("/cases", response_model=list[CaseOut])
async def list_cases(
    who: Viewer, request: Request, status: Literal["open", "closed"] | None = None
) -> list[CaseOut]:
    async with _sm(request)() as s:
        rows = await case_store.list_cases(s, who.clearance, status=status)
    return [CaseOut(**_out(c, n)) for c, n in rows]


@router.post("/cases", response_model=CaseDetail, status_code=201)
async def create_case(who: Analyst, request: Request, body: CaseIn) -> CaseDetail:
    try:
        async with _sm(request)() as s, s.begin():
            c = await case_store.create_case(
                s, title=body.title, severity=body.severity, tlp=body.tlp, summary=body.summary,
                actor=who.name, clearance=who.clearance,
            )  # fmt: skip
            case_id = c.id
    except case_store.CaseError as e:
        raise HTTPException(422, str(e)) from e
    return await get_case(who, request, case_id)


@router.get("/cases/{case_id}", response_model=CaseDetail)
async def get_case(who: Viewer, request: Request, case_id: int) -> CaseDetail:
    async with _sm(request)() as s:
        c = await case_store.get_case(s, case_id, who.clearance)
    if c is None:
        raise HTTPException(404, "no such case")
    return _detail(c)


@router.patch("/cases/{case_id}", response_model=CaseDetail)
async def update_case(who: Analyst, request: Request, case_id: int, body: CasePatch) -> CaseDetail:
    try:
        async with _sm(request)() as s, s.begin():
            c = await case_store.get_case(s, case_id, who.clearance)
            if c is None:
                raise HTTPException(404, "no such case")
            await case_store.update_case(s, c, actor=who.name, **body.model_dump(exclude_none=True))
    except case_store.CaseError as e:
        raise HTTPException(422, str(e)) from e
    return await get_case(who, request, case_id)


@router.post("/cases/{case_id}/items", response_model=CaseDetail)
async def add_items(who: Analyst, request: Request, case_id: int, body: ItemIn) -> CaseDetail:
    """Add evidence by reference (indicator id, CVE, entity), as a note, or by
    looking ``values`` up (local knowledge only: no provider is asked)."""
    svc = getattr(request.app.state, "enrich", None)
    try:
        async with _sm(request)() as s, s.begin():
            c = await case_store.get_case(s, case_id, who.clearance)
            if c is None:
                raise HTTPException(404, "no such case")
            if body.kind == "note":
                await case_store.add_item(s, c, kind="note", ref="", label="note", snapshot={},
                                          tlp="TLP:CLEAR", actor=who.name, note=body.note)  # fmt: skip
            elif body.values:
                if svc is None:
                    raise HTTPException(503, "lookups are not configured")
                obs = [
                    o for v in body.values for o in extract(v)
                    if isinstance(o, Observable) and o.type not in NOT_LOOKUPS
                ]  # fmt: skip
                results, _ = await svc.lookup_many(
                    obs, actor=who.name, clearance=who.clearance, providers=False
                )
                for r in results:
                    ind_id = (r.get("known") or {}).get("indicator_id")
                    ev = await case_store.indicator_evidence(s, ind_id, who.clearance) if ind_id else None
                    kind = "indicator" if ev else "observable"
                    ref, label, snap, tlp = ev or case_store.lookup_evidence(r)
                    await case_store.add_item(s, c, kind=kind, ref=ref, label=label, snapshot=snap, tlp=tlp,
                                              actor=who.name, note=body.note)  # fmt: skip
            elif body.kind and body.ref:
                found = None
                if body.kind == "indicator" and body.ref.isdigit():
                    found = await case_store.indicator_evidence(s, int(body.ref), who.clearance)
                elif body.kind == "vulnerability":
                    found = await case_store.vulnerability_evidence(s, body.ref)
                elif body.kind == "entity":
                    found = await case_store.entity_evidence(s, body.ref)
                if found is None:
                    raise HTTPException(404, "nothing to add: unknown or above your clearance")
                ref, label, snap, tlp = found
                await case_store.add_item(s, c, kind=body.kind, ref=ref, label=label, snapshot=snap, tlp=tlp,
                                          actor=who.name, note=body.note)  # fmt: skip
            else:
                raise HTTPException(422, "give kind + ref, kind=note + note, or values")
    except case_store.CaseError as e:
        raise HTTPException(422, str(e)) from e
    return await get_case(who, request, case_id)


@router.delete("/cases/{case_id}/items/{item_id}", status_code=204)
async def remove_item(who: Analyst, request: Request, case_id: int, item_id: int) -> Response:
    async with _sm(request)() as s, s.begin():
        c = await case_store.get_case(s, case_id, who.clearance)
        if c is None or not await case_store.remove_item(s, c, item_id, actor=who.name):
            raise HTTPException(404, "no such case item")
    return Response(status_code=204)


@router.get("/cases/{case_id}/export.md")
async def export_case(who: Viewer, request: Request, case_id: int) -> Response:
    async with _sm(request)() as s, s.begin():
        c = await case_store.get_case(s, case_id, who.clearance)
        if c is None:
            raise HTTPException(404, "no such case")
        s.add(
            AuditLog(
                actor=who.name, action="case.export", target=f"case:{c.id}", details={"format": "markdown"}
            )
        )
        body = case_store.to_markdown(c, exported_by=who.name)
    return Response(body, media_type="text/markdown; charset=utf-8")


@router.get("/cases/{case_id}/export.pdf")
async def export_case_pdf(who: Viewer, request: Request, case_id: int) -> Response:
    async with _sm(request)() as s, s.begin():
        c = await case_store.get_case(s, case_id, who.clearance)
        if c is None:
            raise HTTPException(404, "no such case")
        s.add(
            AuditLog(actor=who.name, action="case.export", target=f"case:{c.id}", details={"format": "pdf"})
        )
        body = case_store.to_pdf(c, exported_by=who.name)
    return Response(
        body,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="case-{c.id}.pdf"'},
    )


@router.get("/indicators/{indicator_id}/notes", response_model=list[NoteOut], tags=["indicators"])
async def list_notes(who: Viewer, request: Request, indicator_id: int) -> list[NoteOut]:
    await get_indicator(who, request, indicator_id)  # 404 when missing or above clearance
    async with _sm(request)() as s:
        rows = await case_store.notes_for(s, indicator_id)
    return [NoteOut.model_validate(n, from_attributes=True) for n in rows]


@router.post("/indicators/{indicator_id}/notes", response_model=NoteOut, status_code=201, tags=["indicators"])
async def add_note(who: Analyst, request: Request, indicator_id: int, body: NoteIn) -> NoteOut:
    await get_indicator(who, request, indicator_id)
    try:
        async with _sm(request)() as s, s.begin():
            n = await case_store.add_note(s, indicator_id, author=who.name, body=body.body)
            out = NoteOut.model_validate(n, from_attributes=True)
    except case_store.CaseError as e:
        raise HTTPException(422, str(e)) from e
    return out
