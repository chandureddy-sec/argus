"""Analyst-facing AED routes (Slice 6): read the endpoint registry and alerts,
and revoke an agent — all via the admin client, which talks to the separate AED
gateway over HTTP.

Session cookie only (like the rest of /app/api). Reading needs a sign-in;
revoking an agent needs the admin role, a same-site request, and is audited.
The admin token lives on the server (``app.state.aed_admin``); the browser never
sees it. When the gateway isn't configured the routes return 503, never fake
data.
"""

from __future__ import annotations

import re
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Path, Request
from pydantic import BaseModel

from threatlens.aed_admin import AedAdminClient, AedAdminError
from threatlens.auth import same_origin as _same_origin
from threatlens.models import AuditLog
from threatlens.webapp import _me, _sm

router = APIRouter(prefix="/app/api/aed", include_in_schema=False)
_AGENT_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def _client(request: Request) -> AedAdminClient:
    client: AedAdminClient | None = getattr(request.app.state, "aed_admin", None)
    if client is None:
        raise HTTPException(503, "the AED gateway isn't configured (TL_AED_ADMIN_URL)")
    return client


@router.get("/endpoints")
async def endpoints(request: Request) -> dict[str, Any]:
    await _me(request)
    try:
        return {"agents": await _client(request).endpoints()}
    except AedAdminError as e:
        raise HTTPException(502, "the AED gateway is unavailable") from e


@router.get("/alerts")
async def alerts(request: Request) -> dict[str, Any]:
    await _me(request)
    try:
        return {"alerts": await _client(request).alerts()}
    except AedAdminError as e:
        raise HTTPException(502, "the AED gateway is unavailable") from e


@router.get("/endpoints/{agent_id}/events")
async def endpoint_events(request: Request, agent_id: Annotated[str, Path(max_length=128)]) -> dict[str, Any]:
    await _me(request)
    if not _AGENT_ID.match(agent_id):
        raise HTTPException(400, "not an agent id")
    try:
        return {"events": await _client(request).events(agent_id)}
    except AedAdminError as e:
        raise HTTPException(502, "the AED gateway is unavailable") from e


class _MintBody(BaseModel):
    os: Literal["linux", "windows"]
    name: str | None = None
    group: str | None = None


@router.post("/enrollments")
async def create_enrollment(request: Request, body: _MintBody) -> dict[str, Any]:
    # Onboard an endpoint: admin + same-site, audited. The gateway returns the
    # single-use token and install command once; we pass them straight back to
    # the admin and NEVER record the token (audit keeps only os/name/group).
    me = await _me(request)
    if not _same_origin(request):
        raise HTTPException(403, "cross-site request refused")
    if not me.can("admin"):
        raise HTTPException(403, "this needs the admin role")
    client = _client(request)
    try:
        res = await client.create_enrollment(body.os, body.name, body.group)
    except AedAdminError as e:
        raise HTTPException(502, "the AED gateway is unavailable") from e
    async with _sm(request)() as s, s.begin():
        s.add(
            AuditLog(
                actor=me.name[:100],
                action="aed.enroll_create",
                target=(body.name or body.os)[:500],
                details={"os": body.os, "group": body.group},
            )
        )
    return res


@router.post("/agents/{agent_id}/revoke")
async def revoke(request: Request, agent_id: Annotated[str, Path(max_length=128)]) -> dict[str, Any]:
    me = await _me(request)
    if not _same_origin(request):
        raise HTTPException(403, "cross-site request refused")
    if not me.can("admin"):
        raise HTTPException(403, "this needs the admin role")
    if not _AGENT_ID.match(agent_id):
        raise HTTPException(400, "not an agent id")
    client = _client(request)
    try:
        await client.revoke(agent_id)
    except AedAdminError as e:
        raise HTTPException(502, "the AED gateway is unavailable") from e
    async with _sm(request)() as s, s.begin():
        s.add(AuditLog(actor=me.name[:100], action="aed.revoke", target=agent_id[:500], details={}))
    return {"revoked": agent_id}
