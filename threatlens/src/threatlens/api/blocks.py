"""Blocklist API and the token-protected feed export (ADR 0010).

* ``/api/v1/blocks``: read with a viewer key, block / request / lift with an
  analyst key, approve with an admin key (never your own request when the
  four-eyes rule is on). Blocks above the caller's TLP clearance don't exist
  for them.
* ``/feeds/{token}/{format}``: what firewalls and other tools pull. No API
  key, just a feed token (Settings → Feed export), so a Palo Alto or Fortinet
  External Dynamic List can point at the URL. A wrong or revoked token is a
  plain 404, and the token is never written to the request log.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from threatlens import blocking
from threatlens.api.v1 import Admin, Analyst, Viewer, _sm
from threatlens.models import Block

router = APIRouter(prefix="/api/v1", tags=["blocks"])
feeds_router = APIRouter(include_in_schema=False)
FEED_RATE_PER_MINUTE = 60


class BlockIn(BaseModel):
    value: str = Field(min_length=1, max_length=2000, description="an IP, a CIDR range, a domain or a URL")
    note: str = Field(default="", max_length=blocking.MAX_NOTE)


class LiftIn(BaseModel):
    note: str = Field(default="", max_length=blocking.MAX_NOTE)


class BlockOut(BaseModel):
    id: int
    kind: str
    value: str
    state: str
    mode: str
    reason: str
    score: float | None
    tlp: str
    note: str
    created_by: str
    created_at: datetime
    expires_at: datetime
    requested_by: str | None
    approved_by: str | None
    lifted_by: str | None
    lifted_at: datetime | None


class BlockPage(BaseModel):
    total: int
    items: list[BlockOut]


def _out(b: Block) -> BlockOut:
    return BlockOut(
        id=b.id, kind=b.kind, value=b.value, state=blocking.state(b), mode=b.mode, reason=b.reason,
        score=b.score, tlp=b.tlp, note=b.note, created_by=b.created_by, created_at=b.created_at,
        expires_at=b.expires_at, requested_by=b.requested_by, approved_by=b.approved_by,
        lifted_by=b.lifted_by, lifted_at=b.lifted_at,
    )  # fmt: skip


@router.get("/blocks", response_model=BlockPage)
async def list_blocks(
    who: Viewer,
    request: Request,
    view: Literal["live", "enforce", "monitor", "pending", "expired", "lifted", "all"] = "live",
    q: Annotated[str | None, Query(max_length=200)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> BlockPage:
    async with _sm(request)() as s:
        rows, total = await blocking.list_blocks(s, who.clearance, view=view, q=q, limit=limit, offset=offset)
    return BlockPage(total=total, items=[_out(b) for b in rows])


@router.post("/blocks", response_model=BlockOut, status_code=201)
async def create_block(who: Analyst, request: Request, body: BlockIn) -> BlockOut:
    try:
        async with _sm(request)() as s, s.begin():
            b = await blocking.create_block(
                s, body.value, actor=who.name, clearance=who.clearance, origin="manual", note=body.note
            )
            return _out(b)
    except blocking.BlockError as e:
        raise HTTPException(422, str(e)) from None


Action = Callable[[AsyncSession, Block], Awaitable[Block]]


async def _act(request: Request, block_id: int, clearance: str, fn: Action) -> BlockOut:
    try:
        async with _sm(request)() as s, s.begin():
            b = await blocking.get_block(s, block_id, clearance)
            if b is None:
                raise HTTPException(404, "no such block")
            await fn(s, b)
            return _out(b)
    except blocking.BlockError as e:
        raise HTTPException(409, str(e)) from None


@router.post("/blocks/{block_id}/request-enforce", response_model=BlockOut)
async def request_enforce(who: Analyst, request: Request, block_id: int) -> BlockOut:
    return await _act(
        request, block_id, who.clearance,
        lambda s, b: blocking.request_enforce(s, b, actor=who.name, is_admin=who.can("admin")),
    )  # fmt: skip


@router.post("/blocks/{block_id}/approve", response_model=BlockOut)
async def approve(who: Admin, request: Request, block_id: int) -> BlockOut:
    return await _act(
        request, block_id, who.clearance, lambda s, b: blocking.approve(s, b, actor=who.name, is_admin=True)
    )


@router.post("/blocks/{block_id}/lift", response_model=BlockOut)
async def lift(who: Analyst, request: Request, block_id: int, body: LiftIn) -> BlockOut:
    return await _act(
        request, block_id, who.clearance, lambda s, b: blocking.lift(s, b, actor=who.name, note=body.note)
    )


@feeds_router.get("/feeds/{token}/{fmt}")
async def feed(request: Request, token: str, fmt: str) -> Response:
    client = request.client.host if request.client else "unknown"
    if await request.app.state.limiter.hit(f"feed:{client}", FEED_RATE_PER_MINUTE):
        raise HTTPException(429, "too many feed pulls; wait a minute")
    media = blocking.FORMATS.get(fmt)
    if media is None:
        raise HTTPException(404, "not found")
    async with _sm(request)() as s, s.begin():
        if await blocking.check_token(s, token) is None:
            raise HTTPException(404, "not found")
        body = blocking.render(await blocking.export_entries(s), fmt)
    return Response(body, media_type=media, headers={"Cache-Control": "no-store"})
