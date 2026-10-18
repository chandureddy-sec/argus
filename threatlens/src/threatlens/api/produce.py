"""Production and AI API (Phase 8, ADR 0021, 0022).

* ``/api/v1/products``: generated products (daily brief, weekly CTI report,
  vulnerability priority list, executive one-pager) as JSON, HTML and PDF;
  ``POST /generate`` (analyst) builds one now, ``/verify`` rebuilds a stored
  one and compares fingerprints. A reader needs the product's TLP clearance.
* ``/api/v1/lookalikes``: domains imitating ours; ``/scan`` (analyst) runs the
  passive search now; ``/{id}/review`` confirms (optionally blocking it in
  monitor mode) or dismisses one.
* ``/api/v1/ai``: the guarded report assistant. ``/extract`` makes a draft
  (needs ``TL_AI_ENABLED``), ``/deterministic`` runs the extractor that needs
  no model, ``/drafts/{id}/review`` approves into a case or rejects.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field

from threatlens import ai, blocking, lookalike
from threatlens import tlp as tlp_rules
from threatlens.api.v1 import Analyst, Viewer, _app_settings, _sm
from threatlens.models import AuditLog, Lookalike
from threatlens.net.http import SafeHttp
from threatlens.products import render, store
from threatlens.products.build import Kind

router = APIRouter(prefix="/api/v1", tags=["production"])

Tlp = Literal["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"]

# ── products ─────────────────────────────────────────────────────────────────


async def _product(request: Request, who: Any, product_id: int) -> Any:
    async with _sm(request)() as s:
        row = await store.get(s, product_id, who.clearance)
    if row is None:
        raise HTTPException(404, "no such product")
    return row


@router.get("/products")
async def products(
    who: Viewer, request: Request, kind: Annotated[Kind | None, Query()] = None
) -> list[dict[str, Any]]:
    async with _sm(request)() as s:
        return [store.view(r) for r in await store.listing(s, who.clearance, kind)]


class GenerateIn(BaseModel):
    kind: Kind
    as_of: datetime | None = None  # default: now; the product covers the period that ended last


@router.post("/products/generate", status_code=201)
async def generate(who: Analyst, request: Request, body: GenerateIn) -> dict[str, Any]:
    as_of = body.as_of or datetime.now(UTC)
    if as_of.tzinfo is None:
        as_of = as_of.replace(tzinfo=UTC)
    if as_of > datetime.now(UTC):
        raise HTTPException(422, "as_of can't be in the future")
    settings = _app_settings(request)
    row = await store.generate(_sm(request), settings, body.kind, as_of, actor=who.name)
    if not tlp_rules.may_read(who.clearance, row.tlp):
        raise HTTPException(403, f"the product is {row.tlp}, above your clearance")
    return store.view(row)


@router.get("/products/{product_id}")
async def product(who: Viewer, request: Request, product_id: int) -> dict[str, Any]:
    row = await _product(request, who, product_id)
    return {**store.view(row), "content": row.content}


@router.get("/products/{product_id}/html", response_class=HTMLResponse)
async def product_html(who: Viewer, request: Request, product_id: int) -> HTMLResponse:
    row = await _product(request, who, product_id)
    page = render.html(row.content, _app_settings(request).public_url)
    # Self-contained: inline CSS, no scripts; links open the Argus records.
    return HTMLResponse(
        page,
        headers={
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'",
            "Content-Disposition": f'inline; filename="argus-{row.kind}-{row.period_end:%Y%m%d}.html"',
        },
    )


@router.get("/products/{product_id}/pdf")
async def product_pdf(who: Viewer, request: Request, product_id: int) -> Response:
    row = await _product(request, who, product_id)
    return Response(
        render.to_pdf(row.content),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="argus-{row.kind}-{row.period_end:%Y%m%d}.pdf"'
        },
    )


@router.post("/products/{product_id}/verify")
async def product_verify(who: Viewer, request: Request, product_id: int) -> dict[str, Any]:
    row = await _product(request, who, product_id)
    async with _sm(request)() as s:
        return await store.verify(s, row, _app_settings(request))


# ── lookalikes ───────────────────────────────────────────────────────────────


@router.get("/lookalikes")
async def lookalikes(
    who: Viewer,
    request: Request,
    status: Annotated[Literal["new", "confirmed", "benign"] | None, Query()] = None,
) -> dict[str, Any]:
    domains, _ = lookalike.org_domains(_app_settings(request))
    async with _sm(request)() as s:
        rows = await lookalike.recent(s, status)
    return {"domains": domains, "items": [lookalike.view(r) for r in rows]}


@router.post("/lookalikes/scan")
async def lookalike_scan(who: Analyst, request: Request) -> dict[str, Any]:
    settings = _app_settings(request)
    domains, ours = lookalike.org_domains(settings)
    if not domains:
        raise HTTPException(422, "no domains in the org profile (org.domains) to protect")
    # crt.sh is slow for broad queries; tests swap the transport.
    transport = getattr(request.app.state, "http_transport", None)
    async with SafeHttp(timeout=90.0, retries=1, transport=transport) as http:
        return await lookalike.scan(_sm(request), http, domains, ours, use_ct=settings.lookalike_ct)


class ReviewIn(BaseModel):
    status: Literal["confirmed", "benign"]
    block: bool = False  # confirmed only: add it to the blocklist (monitor mode)


@router.post("/lookalikes/{lookalike_id}/review")
async def lookalike_review(
    who: Analyst, request: Request, lookalike_id: int, body: ReviewIn
) -> dict[str, Any]:
    async with _sm(request)() as s, s.begin():
        row = await s.get(Lookalike, lookalike_id)
        if row is None:
            raise HTTPException(404, "no such lookalike")
        row.status = body.status
        row.reviewed_by = who.name[:100]
        row.reviewed_at = datetime.now(UTC)
        out: dict[str, Any] = {}
        if body.status == "confirmed" and body.block:
            try:
                b = await blocking.create_block(
                    s, row.candidate, actor=who.name, clearance=who.clearance, origin="manual",
                    note=f"Lookalike of {row.domain} ({row.fuzzer}), lookalike #{row.id}",
                )  # fmt: skip
                out["block"] = b.id
            except blocking.BlockError as e:
                out["blockError"] = str(e)
        s.add(
            AuditLog(
                actor=who.name[:100],
                action="lookalike.review",
                target=f"lookalike:{row.id}",
                details={"status": body.status, "candidate": row.candidate, **out},
            )
        )
        return {**lookalike.view(row), **out}


# ── AI assistant ─────────────────────────────────────────────────────────────


def _model(request: Request) -> ai.Model:
    model: ai.Model | None = getattr(request.app.state, "ai_model", None)
    if model is not None:
        return model
    settings = _app_settings(request)
    if not settings.ai_enabled:
        raise HTTPException(
            503, "the AI assistant is off: set TL_AI_ENABLED=true and a Claude API key (TL_AI_API_KEY)"
        )
    model = ai.ClaudeModel(settings)
    request.app.state.ai_model = model
    return model


@router.get("/ai/status")
async def ai_status(who: Viewer, request: Request) -> dict[str, Any]:
    s = _app_settings(request)
    on = s.ai_enabled or getattr(request.app.state, "ai_model", None) is not None
    return {"enabled": on, "model": s.ai_model if on else None, "maxTlp": s.ai_max_tlp}


class ExtractIn(BaseModel):
    title: str = Field(min_length=2, max_length=300)
    text: str = Field(min_length=1, max_length=ai.MAX_REPORT)
    tlp: Tlp = "TLP:CLEAR"


@router.post("/ai/extract", status_code=201)
async def ai_extract(who: Analyst, request: Request, body: ExtractIn) -> dict[str, Any]:
    model = _model(request)
    try:
        d = await ai.draft(
            _sm(request), _app_settings(request), model, title=body.title, text=body.text,
            tlp=body.tlp, actor=who.name, clearance=who.clearance,
        )  # fmt: skip
    except ai.AIError as e:
        raise HTTPException(422, str(e)) from None
    return ai.view(d, full=True)


class DeterministicIn(BaseModel):
    text: str = Field(min_length=1, max_length=ai.MAX_REPORT)


@router.post("/ai/deterministic")
async def ai_deterministic(who: Viewer, body: DeterministicIn) -> dict[str, Any]:
    return {"iocs": ai.deterministic(body.text), "warnings": ai.injection_signals(body.text)}


@router.get("/ai/drafts")
async def ai_drafts(who: Viewer, request: Request) -> list[dict[str, Any]]:
    async with _sm(request)() as s:
        return [ai.view(d) for d in await ai.drafts(s, who.clearance)]


@router.get("/ai/drafts/{draft_id}")
async def ai_draft(who: Viewer, request: Request, draft_id: int) -> dict[str, Any]:
    async with _sm(request)() as s:
        d = await ai.get_draft(s, draft_id, who.clearance)
    if d is None:
        raise HTTPException(404, "no such draft")
    return ai.view(d, full=True)


class DraftReviewIn(BaseModel):
    decision: Literal["approve", "reject"]
    keep: list[int] | None = Field(default=None, max_length=1000)  # indexes of the IOCs to keep


@router.post("/ai/drafts/{draft_id}/review")
async def ai_review(who: Analyst, request: Request, draft_id: int, body: DraftReviewIn) -> dict[str, Any]:
    try:
        async with _sm(request)() as s, s.begin():
            d = await ai.get_draft(s, draft_id, who.clearance)
            if d is None:
                raise HTTPException(404, "no such draft")
            await ai.review(
                s, d, decision=body.decision, actor=who.name, clearance=who.clearance, keep=body.keep
            )
            return ai.view(d, full=True)
    except ai.AIError as e:
        raise HTTPException(409, str(e)) from None
