"""Response pages (ADR 0010): the blocklist, the never-block list, and
Settings (blocking policy, feed export tokens).

Same rules as every UI page: a signed session, TLP clearance on every read,
state changes only by POST from this site. Blocking and lifting need the
analyst role; approving an enforce request, the never-block list, the policy
and feed tokens need admin.
"""

from __future__ import annotations

import ipaddress
from collections import Counter
from typing import Annotated, Any, Literal

from fastapi import APIRouter, BackgroundTasks, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from sqlalchemy import func, select

from threatlens import blocking
from threatlens.auth import Principal
from threatlens.collect import reapply_allowlist
from threatlens.ioc.extract import defang_text
from threatlens.ioc.normalize import guess
from threatlens.ioc.types import IOCType, Observable
from threatlens.models import AllowlistEntry, Asset, AuditLog, FeedToken
from threatlens.ui.routes import _same_origin, _settings, _sm, page, who

router = APIRouter(prefix="/ui", include_in_schema=False)
PER_PAGE = 50
MAX_VALUES = 500
Action = Literal["request", "approve", "decline", "lift", "extend"]


def _need(request: Request, me: Principal, role: str) -> None:
    if not _same_origin(request):
        raise HTTPException(403, "cross-site request refused")
    if not me.can(role):
        raise HTTPException(403, f"this needs the {role} role")


async def _never_block(request: Request) -> dict[str, Any]:
    async with _sm(request)() as s:
        rows = (
            await s.scalars(select(AllowlistEntry).order_by(AllowlistEntry.origin, AllowlistEntry.value))
        ).all()
        assets = dict((await s.execute(select(Asset.kind, func.count()).group_by(Asset.kind))).all())
    by_origin = Counter(r.origin for r in rows)
    return {
        "manual": [r for r in rows if r.origin == "manual"],
        "own": [r for r in rows if r.origin == "org_profile"],
        "by_origin": dict(by_origin),
        "assets": {str(k): int(v) for k, v in assets.items()},
        "resolvers": sorted(blocking.PUBLIC_RESOLVERS, key=lambda x: (":" in x, x)),
    }


async def _blocklist_ctx(
    request: Request, me: Principal, view: blocking.View, q: str, page_no: int
) -> dict[str, Any]:
    async with _sm(request)() as s:
        rows, total = await blocking.list_blocks(
            s, me.clearance, view=view, q=q or None, limit=PER_PAGE, offset=(page_no - 1) * PER_PAGE
        )
        counts = await blocking.counts(s, me.clearance)
        policy = await blocking.get_policy(s)
    return {
        "me": me, "rows": rows, "total": total, "counts": counts, "policy": policy, "view": view, "q": q,
        "page_no": page_no, "pages": max(1, -(-total // PER_PAGE)), "state": blocking.state,
        "never": await _never_block(request), "outcome": None, "error": None,
    }  # fmt: skip


@router.get("/blocklist", response_class=HTMLResponse)
async def blocklist(
    request: Request,
    view: Annotated[str, Query(max_length=10)] = "live",
    q: Annotated[str, Query(max_length=200)] = "",
    page_no: Annotated[int, Query(alias="page", ge=1, le=10_000)] = 1,
) -> HTMLResponse:
    me = await who(request)
    v: blocking.View = view if view in blocking.VIEWS else "live"
    return page(request, "blocklist.html", await _blocklist_ctx(request, me, v, q, page_no))


@router.post("/blocklist", response_model=None)
async def block_values(
    request: Request,
    values: Annotated[list[str] | None, Form(max_length=MAX_VALUES)] = None,
    text: Annotated[str, Form(max_length=200_000)] = "",
    note: Annotated[str, Form(max_length=blocking.MAX_NOTE)] = "",
    origin: Annotated[Literal["manual", "indicator", "lookup"], Form()] = "manual",
    nxt: Annotated[str, Form(alias="next", max_length=2000)] = "",
) -> Response:
    """Block one or many values (a typed list, the rows ticked in a bulk
    lookup, or an indicator page's button). Each is checked on its own:
    protected, invalid or already-blocked values are reported, not fatal."""
    me = await who(request)
    _need(request, me, "analyst")
    wanted = [v for v in (values or []) if v.strip()] + [ln for ln in text.splitlines() if ln.strip()]
    wanted = list(dict.fromkeys(v.strip() for v in wanted))
    if len(wanted) > MAX_VALUES:
        raise HTTPException(422, f"at most {MAX_VALUES} values per request")
    created: list[Any] = []
    inputs: list[str] = []
    refused: list[tuple[str, str]] = []
    async with _sm(request)() as s, s.begin():
        guard = await blocking.load_guard(s)
        for raw in wanted:
            try:  # every refusal is raised before anything is written, so no savepoint is needed
                created.append(
                    await blocking.create_block(
                        s, raw, actor=me.name, clearance=me.clearance, origin=origin, note=note, guard=guard
                    )
                )
                inputs.append(raw)
            except blocking.BlockError as e:
                refused.append((raw, str(e)))
    if "application/json" in request.headers.get("accept", ""):  # the in-page Block buttons
        made = [
            {"input": raw, "id": b.id, "state": blocking.state(b), "expires_at": b.expires_at.isoformat()}
            for raw, b in zip(inputs, created, strict=True)
        ]
        return JSONResponse(
            {"created": made, "refused": [{"input": raw, "why": defang_text(why)} for raw, why in refused]},
            status_code=200 if created or not refused else 422,
        )
    if nxt.startswith("/ui/") and not nxt.startswith("//") and len(wanted) == 1 and created:
        return RedirectResponse(nxt, status_code=303)
    ctx = await _blocklist_ctx(request, me, "live", "", 1)
    ctx["outcome"] = {"created": created, "refused": refused}
    if not wanted:
        ctx["error"] = "Nothing to block: enter at least one IP, range, domain or URL."
    return page(request, "blocklist.html", ctx, 200 if created or not wanted else 422)


@router.post("/blocklist/{block_id:int}/{action}", response_model=None)
async def block_action(
    request: Request,
    block_id: int,
    action: Action,
    note: Annotated[str, Form(max_length=blocking.MAX_NOTE)] = "",
    days: Annotated[int, Form(ge=1, le=365)] = 7,
    view: Annotated[str, Form(max_length=10)] = "live",
) -> Response:
    me = await who(request)
    _need(request, me, "admin" if action == "approve" else "analyst")
    admin = me.can("admin")
    try:
        async with _sm(request)() as s, s.begin():
            b = await blocking.get_block(s, block_id, me.clearance)
            if b is None:
                raise HTTPException(404, "no such block")
            match action:
                case "request":
                    await blocking.request_enforce(s, b, actor=me.name, is_admin=admin)
                case "approve":
                    await blocking.approve(s, b, actor=me.name, is_admin=admin)
                case "decline":
                    await blocking.decline(s, b, actor=me.name, is_admin=admin)
                case "lift":
                    await blocking.lift(s, b, actor=me.name, note=note)
                case "extend":
                    await blocking.extend(s, b, actor=me.name, days=days)
    except blocking.BlockError as e:
        v: blocking.View = view if view in blocking.VIEWS else "live"
        ctx = await _blocklist_ctx(request, me, v, "", 1)
        ctx["error"] = str(e)
        return page(request, "blocklist.html", ctx, 409)
    target = view if view in blocking.VIEWS else "live"
    return RedirectResponse(f"/ui/blocklist?view={target}#block-{block_id}", status_code=303)


def _never_entry(raw: str) -> tuple[str, str]:
    v = raw.strip()
    try:
        net = ipaddress.ip_network(v, strict=False)
    except ValueError:
        r = guess(v)
        if isinstance(r, Observable) and r.type == IOCType.DOMAIN:
            return "domain", r.value
        raise blocking.BlockError(f"{v[:80]!r} is not an IP address, a CIDR range or a domain") from None
    return "cidr", str(net)


@router.post("/blocklist/never", response_model=None)
async def never_add(
    request: Request,
    tasks: BackgroundTasks,
    value: Annotated[str, Form(max_length=300)],
    reason: Annotated[str, Form(min_length=3, max_length=300)],
) -> Response:
    """Mark an address, range or domain as ours: it can never be blocked. It is
    an allowlist entry with effect ``flag``: indicators on it stay visible,
    labelled, so a compromise of our own host is still noticed."""
    me = await who(request)
    _need(request, me, "admin")
    try:
        kind, val = _never_entry(value)
    except blocking.BlockError as e:
        ctx = await _blocklist_ctx(request, me, "live", "", 1)
        ctx["error"] = str(e)
        return page(request, "blocklist.html", ctx, 422)
    async with _sm(request)() as s, s.begin():
        dup = await s.scalar(
            select(AllowlistEntry).where(
                AllowlistEntry.kind == kind, AllowlistEntry.value == val, AllowlistEntry.origin == "manual"
            )
        )
        if dup is None:
            s.add(AllowlistEntry(kind=kind, value=val, effect="flag", reason=reason.strip(), origin="manual",
                                 created_by=me.name[:100]))  # fmt: skip
            details = {"effect": "flag", "reason": reason.strip(), "via": "never-block"}
            s.add(
                AuditLog(actor=me.name[:100], action="allowlist.add", target=f"{kind}:{val}", details=details)
            )
    tasks.add_task(reapply_allowlist, _sm(request), _settings(request))
    return RedirectResponse("/ui/blocklist#never", status_code=303)


@router.post("/blocklist/never/{entry_id:int}/delete", response_model=None)
async def never_delete(request: Request, tasks: BackgroundTasks, entry_id: int) -> Response:
    me = await who(request)
    _need(request, me, "admin")
    async with _sm(request)() as s, s.begin():
        row = await s.get(AllowlistEntry, entry_id)
        if row is None or row.origin != "manual":
            raise HTTPException(404, "no such manual entry")
        await s.delete(row)
        s.add(
            AuditLog(
                actor=me.name[:100], action="allowlist.delete", target=f"{row.kind}:{row.value}", details={}
            )
        )
    tasks.add_task(reapply_allowlist, _sm(request), _settings(request))
    return RedirectResponse("/ui/blocklist#never", status_code=303)


# ── settings ─────────────────────────────────────────────────────────────────


async def _settings_ctx(request: Request, me: Principal) -> dict[str, Any]:
    async with _sm(request)() as s:
        policy = await blocking.get_policy(s)
        tokens = (
            await s.scalars(select(FeedToken).order_by(FeedToken.revoked_at.is_not(None), FeedToken.name))
        ).all()
        exported = await blocking.export_entries(s)
    base = str(request.base_url).rstrip("/")
    return {"me": me, "policy": policy, "tokens": tokens, "new_token": None, "error": None, "base": base,
            "formats": list(blocking.FORMATS), "exported": Counter(b.kind for b in exported),
            "export_tlps": blocking.EXPORT_TLPS}  # fmt: skip


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request) -> HTMLResponse:
    me = await who(request)
    return page(request, "settings.html", await _settings_ctx(request, me))


@router.post("/settings", response_model=None)
async def settings_save(
    request: Request,
    known_bad_days: Annotated[int, Form()],
    suspect_days: Annotated[int, Form()],
    manual_days: Annotated[int, Form()],
    known_bad_score: Annotated[float, Form()],
    export_max_tlp: Annotated[str, Form(max_length=20)],
    require_second_approver: Annotated[bool, Form()] = False,
) -> Response:
    me = await who(request)
    _need(request, me, "admin")
    try:
        async with _sm(request)() as s, s.begin():
            await blocking.set_policy(
                s,
                {"known_bad_days": known_bad_days, "suspect_days": suspect_days, "manual_days": manual_days,
                 "known_bad_score": known_bad_score, "export_max_tlp": export_max_tlp,
                 "require_second_approver": require_second_approver},
                actor=me.name,
            )  # fmt: skip
    except blocking.BlockError as e:
        ctx = await _settings_ctx(request, me)
        ctx["error"] = str(e)
        return page(request, "settings.html", ctx, 422)
    return RedirectResponse("/ui/settings#policy", status_code=303)


@router.post("/settings/tokens", response_model=None)
async def token_create(request: Request, name: Annotated[str, Form(max_length=64)]) -> Response:
    me = await who(request)
    _need(request, me, "admin")
    try:
        async with _sm(request)() as s, s.begin():
            row, token = await blocking.create_token(s, name, actor=me.name)
    except blocking.BlockError as e:
        ctx = await _settings_ctx(request, me)
        ctx["error"] = str(e)
        return page(request, "settings.html", ctx, 422)
    ctx = await _settings_ctx(request, me)
    ctx["new_token"] = (row.name, token)  # shown once, never stored in clear
    resp = page(request, "settings.html", ctx)
    resp.headers["Cache-Control"] = "no-store"
    return resp


@router.post("/settings/tokens/{token_id:int}/revoke", response_model=None)
async def token_revoke(request: Request, token_id: int) -> Response:
    me = await who(request)
    _need(request, me, "admin")
    try:
        async with _sm(request)() as s, s.begin():
            await blocking.revoke_token(s, token_id, actor=me.name)
    except blocking.BlockError:
        raise HTTPException(404, "no such token") from None
    return RedirectResponse("/ui/settings#export", status_code=303)
