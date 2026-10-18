"""JSON the Argus pages need beyond the REST API (ADR 0015).

Argus reads and changes most things through ``/api/v1`` (which accepts the
signed-in session since ADR 0015). This module adds what only existed as
server-rendered HTML in the classic UI:

* Verify, live: the lookup stream as NDJSON events with the same plain-language
  headlines and fields the classic cards show (``threatlens.verify``).
* Bulk check, live: one JSON row per value as it is answered.
* Flag malicious / not malicious, block counts, decline and extend.
* Settings: blocking policy, feed-export tokens, the never-block list.
* A custom feed's edit form (never its key).

Every value that could be an indicator is defanged before it leaves the
server (PROMPT section 2); live links exist only where the marking allows.
"""

from __future__ import annotations

import asyncio
import csv
import io
import ipaddress
import json
import re
from collections import Counter
from collections.abc import AsyncIterator
from typing import Annotated, Any, Literal

from fastapi import APIRouter, BackgroundTasks, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import String, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from threatlens import blocking, catalog, internal, session, totp, users, verify
from threatlens.api.blocks import BlockOut, _out
from threatlens.api.enrich import NOT_LOOKUPS
from threatlens.api.v1 import Admin, Analyst, Viewer, _app_settings, _sm
from threatlens.collect import reapply_allowlist
from threatlens.enrich.service import Budget, EnrichmentService
from threatlens.intake import BLOCKABLE, BULK_MAX, gather_text, observables
from threatlens.ioc.extract import defang_text
from threatlens.ioc.normalize import guess
from threatlens.ioc.types import IOCType, Observable
from threatlens.logs import get_logger
from threatlens.models import AllowlistEntry, AppSetting, Asset, AuditLog, FeedToken, User
from threatlens.scoring.feedback import rescore_sources
from threatlens.users import UserError

router = APIRouter(prefix="/app/api", include_in_schema=False)
log = get_logger("threatlens.argus")
TLP = Literal["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"]
VERIFY_PER_MINUTE = 60
BULK_PER_MINUTE = 20
BULK_CONCURRENCY = 8
STREAM = {"Cache-Control": "no-store", "X-Accel-Buffering": "no"}
SIGNALS = {
    "virustotal": "VT",
    "abuseipdb": "AbuseIPDB",
    "greynoise": "GreyNoise",
    "malwarebazaar": "MalwareBazaar",
}
TONE_KIND = {"mal": "malicious", "sus": "suspicious", "ok": "benign"}


def _svc(request: Request) -> EnrichmentService:
    svc: EnrichmentService | None = getattr(request.app.state, "enrich", None)
    if svc is None:
        raise HTTPException(503, "lookups are not configured")
    return svc


async def _limit(request: Request, who: Any, bucket: str, n: int) -> None:
    if await request.app.state.limiter.hit(f"{bucket}:{who.kind}:{who.key_id}", n):
        raise HTTPException(429, "too many lookups; wait a minute")


def _df(v: Any) -> Any:
    """Defang every string in a JSON-like value."""
    if isinstance(v, str):
        return defang_text(v)
    if isinstance(v, list):
        return [_df(x) for x in v]
    if isinstance(v, dict):
        return {k: _df(x) for k, x in v.items()}
    return v


def sheet_safe(v: Any) -> str:
    """A CSV cell a spreadsheet won't evaluate: text starting with = + - @ or a
    tab/CR gets a leading apostrophe (OWASP CSV injection guidance)."""
    t = "" if v is None else str(v)
    return "'" + t if t[:1] in ("=", "+", "-", "@", "\t", "\r") else t


def _line(obj: dict[str, Any]) -> bytes:
    return (json.dumps(obj, default=str) + "\n").encode()


def _query(q: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": q["type"],
        "typeLabel": verify.TYPE.get(q["type"], q["type"]),
        "value": q.get("defanged") or defang_text(str(q.get("value", ""))),
    }


def card(e: dict[str, Any]) -> dict[str, Any]:
    """One provider's answer as the Verify page shows it."""
    text, tone = verify.headline(e)
    evidence = [ev for ev in (e.get("evidence") or []) if ev.get("kind") != "info"][:4]
    return {
        "enricher": e.get("enricher"),
        "title": verify.CARD_TITLE.get(e.get("enricher") or "", e.get("title") or e.get("enricher")),
        "status": e.get("status"),
        "mode": e.get("mode"),
        "fetchedAt": e.get("fetched_at"),
        "headline": defang_text(text),
        "tone": tone,
        "rows": _df(
            [[label, value] for label, value in verify.fields(e.get("enricher") or "", e.get("summary"))]
        ),
        "evidence": _df(
            [{"kind": ev.get("kind"), "text": str(ev.get("text") or "")[:300]} for ev in evidence]
        ),
        "error": (str(e.get("error"))[:200] if e.get("error") and e.get("status") == "stale" else None),
    }


def _local(data: dict[str, Any]) -> dict[str, Any]:
    """Our own knowledge: indicator, asset, allowlist, related entities."""
    known = data.get("known")
    return {
        "known": _df(known) if known else None,
        "asset": _df(data.get("asset")) if data.get("asset") else None,
        "allowlist": _df(data.get("allowlist")) if data.get("allowlist") else None,
        "related": _df(
            [
                {"label": x.get("label"), "ref": x.get("external_id") or x.get("ref")}
                for x in (data.get("related") or [])[:8]
            ]
        ),
    }


def _verdict(r: dict[str, Any]) -> dict[str, Any]:
    return {
        "verdict": r["verdict"],
        "verdictLabel": verify.VERDICT.get(r["verdict"], r["verdict"]),
        "score": r.get("score"),
        "action": r.get("recommended_action"),
        "actionLabel": verify.ACTION.get(r.get("recommended_action") or "", r.get("recommended_action")),
        "actionText": defang_text(str(r.get("recommended_action_text") or "")),
        "tlp": r.get("tlp"),
        "summary": verify.summary_line(r),
        "partial": r.get("partial", False),
    }


# ── verify one value, live ───────────────────────────────────────────────────


@router.get("/verify/stream")
async def verify_stream(
    who: Viewer,
    request: Request,
    q: Annotated[str, Query(max_length=2000)],
    tlp: TLP = "TLP:GREEN",
    providers: bool = True,
) -> StreamingResponse:
    if internal.classify(q) is not None:
        # A private or reserved address: no provider or feed knows it, and sending
        # it out would describe our network. Answer from our own data only.
        await _limit(request, who, "verify", VERIFY_PER_MINUTE)
        async with _sm(request)() as s:
            found = await internal.lookup(s, q, who.clearance)
        if found is None:  # is_internal() said yes, so lookup always answers
            raise HTTPException(500, "internal lookup returned nothing")
        query = {
            "type": f"ipv{found['version']}",
            "typeLabel": f"Internal IPv{found['version']} address",
            "value": defang_text(found["address"]),
        }
        line = _line({"event": "internal", "query": query, **_df(found)})
        return StreamingResponse(iter([line]), media_type="application/x-ndjson", headers=STREAM)
    try:
        obs = verify.parse(q)
        if obs.type in NOT_LOOKUPS:
            raise verify.FlagError(f"a {obs.type.value} can't be looked up")
    except verify.FlagError as e:
        raise HTTPException(422, str(e)) from None
    await _limit(request, who, "verify", VERIFY_PER_MINUTE)
    svc = _svc(request)

    async def gen() -> AsyncIterator[bytes]:
        try:
            async for kind, data in svc.lookup_stream(
                obs, actor=who.name, tlp=tlp, clearance=who.clearance, providers=providers
            ):
                if kind == "start":
                    pending = [
                        {
                            "enricher": p["enricher"],
                            "title": verify.CARD_TITLE.get(p["enricher"], p.get("title")),
                        }
                        for p in data.get("pending", [])
                    ]
                    yield _line(
                        {"event": "start", "query": _query(data["query"]), **_local(data), "pending": pending}
                    )
                elif kind == "enricher":
                    yield _line({"event": "provider", "card": card(data)})
                else:
                    async with _sm(request)() as s:
                        block = await blocking.live_block(s, data["query"]["canonical_key"])
                    qq = data["query"]
                    links = verify.second_opinion(qq["type"], qq["value"], data["tlp"])
                    yield _line(
                        {
                            "event": "done",
                            "query": _query(qq),
                            **_local(data),
                            **_verdict(data),
                            "cards": [card(e) for e in data.get("enrichments", [])],
                            "links": [{"title": link.title, "url": link.url} for link in links],
                            "block": _out(block).model_dump(mode="json") if block else None,
                            "blockable": qq["type"] in BLOCKABLE,
                        }
                    )
        except Exception as e:  # the page must learn the stream failed, not wait forever
            log.exception("argus.verify_stream_failed", error=str(e))
            yield _line({"event": "error", "message": "The lookup failed; try again."})

    return StreamingResponse(gen(), media_type="application/x-ndjson", headers=STREAM)


class FlagIn(BaseModel):
    values: list[str] = Field(min_length=1, max_length=BULK_MAX)
    verdict: Literal["tp", "fp"]
    tlp: TLP = "TLP:GREEN"
    note: str = Field(default="", max_length=500)


@router.post("/verify/flag")
async def flag(who: Analyst, request: Request, tasks: BackgroundTasks, body: FlagIn) -> dict[str, Any]:
    """Flag malicious (tp) or not malicious (fp): feedback on the indicator, and
    for an unknown value, a new analyst-submitted indicator."""
    done: list[dict[str, Any]] = []
    refused: list[dict[str, str]] = []
    weights: set[str] = set()
    for raw in dict.fromkeys(v.strip() for v in body.values if v.strip()):
        why = body.note or ("flagged malicious" if body.verdict == "tp" else "marked not malicious")
        try:
            f = await verify.flag(
                _sm(request),
                _app_settings(request),
                raw,
                body.verdict,
                actor=who.name,
                clearance=who.clearance,
                tlp=body.tlp,
                note=why,
            )
        except verify.FlagError as e:
            refused.append({"value": defang_text(raw), "why": defang_text(str(e))})
            continue
        done.append({"value": defang_text(f.value), "indicatorId": f.indicator_id, "created": f.created})
        weights |= {c.source for c in f.changes}
    if weights:
        tasks.add_task(rescore_sources, _sm(request), _app_settings(request), sorted(weights))
    return {"verdict": body.verdict, "done": done, "refused": refused}


# ── bulk check, live ─────────────────────────────────────────────────────────


def bulk_row(r: dict[str, Any], block: Any) -> dict[str, Any]:
    by = {e["enricher"]: (e.get("summary") or {}) for e in r.get("enrichments", [])}
    country = (
        by.get("ripestat", {}).get("country")
        or by.get("abuseipdb", {}).get("country")
        or by.get("rdap", {}).get("country")
    )
    signals = []
    for e in r.get("enrichments", []):
        name = e.get("enricher") or ""
        if name in SIGNALS and e.get("status") in ("ok", "cached", "stale", "not_found"):
            text, tone = verify.headline(e)
            s = e.get("summary") or {}
            figure = (
                s.get("malicious")
                if name == "virustotal"
                else s.get("abuse_confidence")
                if name == "abuseipdb"
                else None
            )
            signals.append(
                {
                    "name": SIGNALS[name],
                    "kind": TONE_KIND.get(tone, "info"),
                    "text": defang_text(text),
                    "figure": figure,
                }
            )
    known = r.get("known") or {}
    return {
        "query": _query(r["query"]),
        **_verdict(r),
        "sources": known.get("sources", []),
        "known": bool(known),
        "analystVerdict": known.get("analyst_verdict"),
        "country": country,
        "signals": signals,
        "asset": bool(r.get("asset")),
        "block": {"id": block.id, "mode": block.mode, "state": blocking.state(block)} if block else None,
        "blockable": r["query"]["type"] in BLOCKABLE,
    }


@router.post("/bulk/stream")
async def bulk_stream(
    who: Analyst,
    request: Request,
    text: Annotated[str, Form(max_length=1_000_000)] = "",
    files: Annotated[list[UploadFile] | None, File()] = None,
    tlp: Annotated[TLP, Form()] = "TLP:GREEN",
    providers: Annotated[bool, Form()] = False,
    autoblock: Annotated[bool, Form()] = False,
) -> StreamingResponse:
    await _limit(request, who, "bulk", BULK_PER_MINUTE)
    svc = _svc(request)
    body, notes = await gather_text(text, files)
    obs = observables(body)
    if not obs:
        raise HTTPException(
            422, "No indicators found (IPs, domains, URLs, hashes and emails; defanged is fine)."
        )
    if len(obs) > BULK_MAX:
        raise HTTPException(
            422, f"Found {len(obs):,} indicators; at most {BULK_MAX} per check. Split the list."
        )
    total = len(obs)

    async def gen() -> AsyncIterator[bytes]:
        counts: Counter[str] = Counter()
        budget = Budget(svc.settings.enrich_budget)
        start = budget.left
        sem = asyncio.Semaphore(BULK_CONCURRENCY)
        blocked: list[str] = []
        refused: list[str] = []

        async def one(o: Observable) -> dict[str, Any]:
            async with sem:
                return await svc.lookup(
                    o, actor=who.name, tlp=tlp, budget=budget, clearance=who.clearance, providers=providers
                )

        yield _line({"event": "start", "total": total, "notes": _df(notes)})
        tasks = [asyncio.ensure_future(one(o)) for o in obs]
        done = 0
        try:
            for fut in asyncio.as_completed(tasks):
                try:
                    r = await fut
                except Exception as e:  # one bad value must not end the whole check
                    log.warning("argus.bulk_item_failed", error=str(e))
                    done += 1
                    yield _line({"event": "skip", "done": done, "total": total})
                    continue
                done += 1
                counts[r["verdict"]] += 1
                block = None
                async with _sm(request)() as s, s.begin():
                    if autoblock and r["verdict"] == "malicious" and r["query"]["type"] in BLOCKABLE:
                        try:
                            block = await blocking.create_block(
                                s,
                                r["query"]["value"],
                                actor=who.name,
                                clearance=who.clearance,
                                origin="lookup",
                                note="auto-blocked from a bulk check",
                            )
                            blocked.append(r["query"]["defanged"])
                        except blocking.BlockError as e:
                            refused.append(defang_text(str(e)))
                    if block is None:
                        block = await blocking.live_block(s, r["query"]["canonical_key"])
                yield _line(
                    {
                        "event": "row",
                        "row": bulk_row(r, block),
                        "done": done,
                        "total": total,
                        "counts": dict(counts),
                    }
                )
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
        yield _line(
            {
                "event": "done",
                "total": total,
                "counts": dict(counts),
                "calls": start - budget.left,
                "providers": providers,
                "blocked": blocked,
                "refused": refused,
            }
        )

    return StreamingResponse(gen(), media_type="application/x-ndjson", headers=STREAM)


# ── blocks: counts, decline, extend ──────────────────────────────────────────


@router.get("/blocks/counts")
async def block_counts(who: Viewer, request: Request) -> dict[str, Any]:
    async with _sm(request)() as s:
        counts = await blocking.counts(s, who.clearance)
        policy = await blocking.get_policy(s)
    return {
        "counts": counts,
        "requireSecondApprover": policy["require_second_approver"],
        "policy": {k: policy[k] for k in ("known_bad_days", "suspect_days", "manual_days")},
    }


class ExtendIn(BaseModel):
    days: int = Field(ge=1, le=365)


async def _block_act(request: Request, who: Any, block_id: int, fn: Any) -> BlockOut:
    try:
        async with _sm(request)() as s, s.begin():
            b = await blocking.get_block(s, block_id, who.clearance)
            if b is None:
                raise HTTPException(404, "no such block")
            await fn(s, b)
            return _out(b)
    except blocking.BlockError as e:
        raise HTTPException(409, str(e)) from None


@router.post("/blocks/{block_id}/decline", response_model=BlockOut)
async def decline(who: Analyst, request: Request, block_id: int) -> BlockOut:
    return await _block_act(
        request, who, block_id, lambda s, b: blocking.decline(s, b, actor=who.name, is_admin=who.can("admin"))
    )


@router.post("/blocks/{block_id}/extend", response_model=BlockOut)
async def extend(who: Analyst, request: Request, block_id: int, body: ExtendIn) -> BlockOut:
    return await _block_act(
        request, who, block_id, lambda s, b: blocking.extend(s, b, actor=who.name, days=body.days)
    )


# ── settings: policy, feed tokens, never-block ───────────────────────────────


@router.get("/settings")
async def settings_get(who: Viewer, request: Request) -> dict[str, Any]:
    async with _sm(request)() as s:
        policy = await blocking.get_policy(s)
        tokens = (
            await s.scalars(select(FeedToken).order_by(FeedToken.revoked_at.is_not(None), FeedToken.name))
        ).all()
        exported = Counter(b.kind for b in await blocking.export_entries(s))
    return {
        "policy": policy,
        "exportTlps": list(blocking.EXPORT_TLPS),
        "formats": list(blocking.FORMATS),
        "exported": dict(exported),
        "base": str(request.base_url).rstrip("/"),
        "canEdit": who.can("admin"),
        "tokens": [
            {
                "id": t.id,
                "name": t.name,
                "prefix": t.prefix,
                "createdBy": t.created_by,
                "createdAt": t.created_at,
                "lastUsedAt": t.last_used_at,
                "revokedAt": t.revoked_at,
            }
            for t in tokens
        ],
    }


class PolicyIn(BaseModel):
    known_bad_days: int
    suspect_days: int
    manual_days: int
    known_bad_score: float
    export_max_tlp: str
    require_second_approver: bool


@router.put("/settings/policy")
async def settings_policy(who: Admin, request: Request, body: PolicyIn) -> dict[str, Any]:
    try:
        async with _sm(request)() as s, s.begin():
            return await blocking.set_policy(s, body.model_dump(), actor=who.name)
    except blocking.BlockError as e:
        raise HTTPException(422, str(e)) from None


class TokenIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)


@router.post("/settings/tokens")
async def token_create(who: Admin, request: Request, body: TokenIn) -> JSONResponse:
    try:
        async with _sm(request)() as s, s.begin():
            row, token = await blocking.create_token(s, body.name, actor=who.name)
    except blocking.BlockError as e:
        raise HTTPException(422, str(e)) from None
    base = str(request.base_url).rstrip("/")
    return JSONResponse(  # shown once; only a hash is stored
        {"name": row.name, "token": token, "urls": [f"{base}/feeds/{token}/{f}" for f in blocking.FORMATS]},
        headers={"Cache-Control": "no-store"},
    )


@router.post("/settings/tokens/{token_id}/revoke")
async def token_revoke(who: Admin, request: Request, token_id: int) -> dict[str, str]:
    try:
        async with _sm(request)() as s, s.begin():
            await blocking.revoke_token(s, token_id, actor=who.name)
    except blocking.BlockError:
        raise HTTPException(404, "no such token") from None
    return {"status": "revoked"}


@router.get("/neverblock")
async def neverblock(who: Viewer, request: Request) -> dict[str, Any]:
    async with _sm(request)() as s:
        rows = (
            await s.scalars(select(AllowlistEntry).order_by(AllowlistEntry.origin, AllowlistEntry.value))
        ).all()
        assets = dict((await s.execute(select(Asset.kind, func.count()).group_by(Asset.kind))).all())

    def entry(r: AllowlistEntry) -> dict[str, Any]:
        return {
            "id": r.id,
            "kind": r.kind,
            "value": defang_text(r.value),
            "reason": r.reason,
            "createdBy": getattr(r, "created_by", None),
        }

    return {
        "manual": [entry(r) for r in rows if r.origin == "manual"],
        "own": [entry(r) for r in rows if r.origin == "org_profile"],
        "byOrigin": dict(Counter(r.origin for r in rows)),
        "assets": {str(k): int(v) for k, v in assets.items()},
        "resolvers": sorted(blocking.PUBLIC_RESOLVERS, key=lambda x: (":" in x, x)),
        "canEdit": who.can("admin"),
    }


class NeverIn(BaseModel):
    value: str = Field(min_length=1, max_length=300)
    reason: str = Field(min_length=3, max_length=300)


def _never_entry(raw: str) -> tuple[str, str]:
    v = raw.strip()
    try:
        return "cidr", str(ipaddress.ip_network(v, strict=False))
    except ValueError:
        r = guess(v)
        if isinstance(r, Observable) and r.type == IOCType.DOMAIN:
            return "domain", r.value
        raise HTTPException(
            422, f"{defang_text(v[:80])!r} is not an IP address, a CIDR range or a domain"
        ) from None


@router.post("/neverblock")
async def neverblock_add(
    who: Admin, request: Request, tasks: BackgroundTasks, body: NeverIn
) -> dict[str, Any]:
    kind, val = _never_entry(body.value)
    async with _sm(request)() as s, s.begin():
        dup = await s.scalar(
            select(AllowlistEntry).where(
                AllowlistEntry.kind == kind, AllowlistEntry.value == val, AllowlistEntry.origin == "manual"
            )
        )
        if dup is None:
            s.add(
                AllowlistEntry(
                    kind=kind,
                    value=val,
                    effect="flag",
                    reason=body.reason.strip(),
                    origin="manual",
                    created_by=who.name[:100],
                )
            )
            s.add(
                AuditLog(
                    actor=who.name[:100],
                    action="allowlist.add",
                    target=f"{kind}:{val}",
                    details={"effect": "flag", "reason": body.reason.strip(), "via": "never-block"},
                )
            )
    tasks.add_task(reapply_allowlist, _sm(request), _app_settings(request))
    return {"kind": kind, "value": defang_text(val), "duplicate": dup is not None}


@router.delete("/neverblock/{entry_id}")
async def neverblock_delete(
    who: Admin, request: Request, tasks: BackgroundTasks, entry_id: int
) -> dict[str, str]:
    async with _sm(request)() as s, s.begin():
        row = await s.get(AllowlistEntry, entry_id)
        if row is None or row.origin != "manual":
            raise HTTPException(404, "no such manual entry")
        await s.delete(row)
        s.add(
            AuditLog(
                actor=who.name[:100], action="allowlist.delete", target=f"{row.kind}:{row.value}", details={}
            )
        )
    tasks.add_task(reapply_allowlist, _sm(request), _app_settings(request))
    return {"status": "deleted"}


# ── a custom feed's edit form ────────────────────────────────────────────────


@router.get("/feeds/{name}/form")
async def feed_form(who: Admin, request: Request, name: str) -> dict[str, Any]:
    async with _sm(request)() as s:
        found = await catalog.get_custom(s, name)
    if found is None:
        raise HTTPException(404, "no such custom feed")
    src, feed = found
    return {
        "title": src.title,
        "url": feed.url,
        "format": feed.format,
        "ioc_type": feed.ioc_type,
        "verdict": feed.verdict,
        "confidence": feed.confidence,
        "interval_minutes": src.interval_minutes,
        "tlp": src.tlp_default,
        "reliability": src.reliability,
        "comment_char": feed.comment_char,
        "value_column": feed.value_column,
        "json_path": feed.json_path or "",
        "auth_header": feed.auth_header or "",
        "has_secret": bool(feed.auth_secret),
        "upstream": "" if src.upstream.startswith("custom:") else src.upstream,
        "allow_internal": feed.allow_internal,
    }


# ── team & user management (ADR 0017) ─────────────────────────────────────────


class UserCreateIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=6, max_length=256)
    role: Literal["admin", "analyst", "viewer"] = "analyst"
    clearance: TLP | None = None


class UserRoleIn(BaseModel):
    role: Literal["admin", "analyst", "viewer"]
    clearance: TLP | None = None


class PasswordResetIn(BaseModel):
    password: str = Field(min_length=6, max_length=256)


@router.get("/settings/users")
async def users_list(who: Admin, request: Request) -> list[dict[str, Any]]:
    """List all accounts inside Argus for admin review."""
    async with _sm(request)() as s:
        rows = await users.list_users(s)
    return [
        {
            "id": u.id,
            "name": u.name,
            "login": u.login,
            "role": u.role,
            "tlpClearance": u.tlp_clearance,
            "createdAt": u.created_at,
            "lastLoginAt": u.last_login_at,
            "disabledAt": u.disabled_at,
            "totpEnabled": bool(u.totp_secret),
            "ssoProvider": u.sso_provider,
        }
        for u in rows
    ]


@router.post("/settings/users")
async def user_create(who: Admin, request: Request, body: UserCreateIn) -> dict[str, Any]:
    """Create a new user account directly from Settings."""
    try:
        async with _sm(request)() as s, s.begin():
            row = await users.create_user(
                s, body.name, body.password, body.role, actor=who.name, clearance=body.clearance
            )
            return {
                "id": row.id,
                "name": row.name,
                "login": row.login,
                "role": row.role,
                "tlpClearance": row.tlp_clearance,
                "createdAt": row.created_at,
            }
    except UserError as e:
        raise HTTPException(422, str(e)) from None


@router.patch("/settings/users/{user_id}/role")
async def user_change_role(who: Admin, request: Request, user_id: int, body: UserRoleIn) -> dict[str, Any]:
    """Change an account's role and/or TLP clearance."""
    try:
        async with _sm(request)() as s, s.begin():
            target = await users.get_user_by_id(s, user_id)
            if target is None:
                raise HTTPException(404, "no such user")
            # Safety check: Prevent demoting the last active administrator
            if target.id == who.key_id and body.role != "admin":
                other_admins = (
                    await s.scalars(
                        select(User).where(
                            User.role == "admin", User.disabled_at.is_(None), User.id != target.id
                        )
                    )
                ).all()
                if not other_admins:
                    raise HTTPException(422, "Cannot demote the sole active administrator.")
            await users.set_role(s, target.name, body.role, actor=who.name)
            await users.set_clearance(s, target.name, body.clearance, actor=who.name)
            return {"status": "updated", "role": target.role, "clearance": target.tlp_clearance}
    except UserError as e:
        raise HTTPException(422, str(e)) from None


@router.post("/settings/users/{user_id}/password")
async def user_reset_password(
    who: Admin, request: Request, user_id: int, body: PasswordResetIn
) -> dict[str, str]:
    """Reset an account's password from Settings. Sessions signed in with the old one end."""
    try:
        async with _sm(request)() as s, s.begin():
            target = await users.get_user_by_id(s, user_id)
            if target is None:
                raise HTTPException(404, "no such user")
            await users.set_password(s, target.name, body.password, actor=who.name)
            return {"status": "password_reset"}
    except UserError as e:
        raise HTTPException(422, str(e)) from None


@router.post("/settings/users/{user_id}/disable")
async def user_disable(who: Admin, request: Request, user_id: int) -> dict[str, str]:
    """Disable an account, immediately terminating all its active sessions."""
    try:
        async with _sm(request)() as s, s.begin():
            target = await users.get_user_by_id(s, user_id)
            if target is None:
                raise HTTPException(404, "no such user")
            if target.id == who.key_id:
                raise HTTPException(422, "You cannot disable your own active administrator account.")
            await users.set_disabled(s, target.name, True, actor=who.name)
            return {"status": "disabled"}
    except UserError as e:
        raise HTTPException(422, str(e)) from None


@router.post("/settings/users/{user_id}/enable")
async def user_enable(who: Admin, request: Request, user_id: int) -> dict[str, str]:
    """Re-enable a disabled account."""
    try:
        async with _sm(request)() as s, s.begin():
            target = await users.get_user_by_id(s, user_id)
            if target is None:
                raise HTTPException(404, "no such user")
            await users.set_disabled(s, target.name, False, actor=who.name)
            return {"status": "enabled"}
    except UserError as e:
        raise HTTPException(422, str(e)) from None


@router.post("/settings/users/{user_id}/reset-2fa")
async def user_reset_2fa(who: Admin, request: Request, user_id: int) -> dict[str, str]:
    """Reset a user's 2FA (TOTP) secret (e.g. if device was lost)."""
    try:
        async with _sm(request)() as s, s.begin():
            target = await users.get_user_by_id(s, user_id)
            if target is None:
                raise HTTPException(404, "no such user")
            await users.reset_totp(s, target.name, actor=who.name)
            return {"status": "2fa_reset"}
    except UserError as e:
        raise HTTPException(422, str(e)) from None


# ── two-factor authentication (TOTP) ──────────────────────────────────────────


class Enable2FaIn(BaseModel):
    secret: str = Field(min_length=16, max_length=64)
    code: str = Field(min_length=6, max_length=6)


class Disable2FaIn(BaseModel):
    code: str = Field(min_length=6, max_length=6)


@router.get("/settings/2fa")
async def two_factor_status(who: Viewer, request: Request) -> dict[str, Any]:
    """Get 2FA status for the currently authenticated user."""
    if who.kind != "user":
        raise HTTPException(
            400, "Two-factor authentication is only available for user accounts, not API keys."
        )
    async with _sm(request)() as s:
        target = await users.get_user_by_id(s, who.key_id)
    if target is None:
        return {"enabled": False, "enabledAt": None}
    return {"enabled": bool(target.totp_secret), "enabledAt": target.totp_enabled_at}


@router.post("/settings/2fa/setup")
async def two_factor_setup(who: Viewer, request: Request) -> dict[str, str]:
    """Generate a new TOTP secret, otpauth URL, and SVG QR code."""
    if who.kind != "user":
        raise HTTPException(
            400, "Two-factor authentication is only available for user accounts, not API keys."
        )
    secret = totp.generate_secret()
    url = totp.otpauth_url(who.name, secret, issuer="Argus")
    svg = totp.qr_svg(url)
    return {"secret": secret, "otpauth_url": url, "qr_svg": svg}


@router.post("/settings/2fa/enable")
async def two_factor_enable(who: Viewer, request: Request, body: Enable2FaIn) -> dict[str, Any]:
    """Verify code and activate TOTP for the current user."""
    if who.kind != "user":
        raise HTTPException(
            400, "Two-factor authentication is only available for user accounts, not API keys."
        )
    if not totp.verify_totp(body.secret, body.code):
        raise HTTPException(422, "Invalid verification code; check the code from your authenticator app.")
    async with _sm(request)() as s, s.begin():
        await users.set_totp_secret(s, who.name, body.secret, actor=who.name)
    return {"ok": True, "status": "enabled"}


@router.post("/settings/2fa/disable")
async def two_factor_disable(who: Viewer, request: Request, body: Disable2FaIn) -> dict[str, Any]:
    """Disable TOTP after verifying a code from the authenticator."""
    if who.kind != "user":
        raise HTTPException(
            400, "Two-factor authentication is only available for user accounts, not API keys."
        )
    async with _sm(request)() as s:
        target = await users.get_user_by_id(s, who.key_id)
    if target is None or not target.totp_secret:
        return {"ok": True, "status": "not_enabled"}
    if not totp.verify_totp(target.totp_secret, body.code):
        raise HTTPException(422, "Invalid verification code.")
    if await request.app.state.limiter.hit(f"totp-disable:{target.id}:{body.code.strip()}", 1, 90):
        raise HTTPException(401, "This two-factor code was already used. Please wait for the next code.")
    async with _sm(request)() as s, s.begin():
        await users.set_totp_secret(s, who.name, None, actor=who.name)
    return {"ok": True, "status": "disabled"}


# ── single sign-on (SSO) ─────────────────────────────────────────────────────

SSO_SETTING_KEY = "security.sso"
REDACTED_VALUE = "********"
DEFAULT_SSO_CONFIG = {
    "enabled": False,
    "default_role": "analyst",
    "auto_provision": True,
    "providers": {
        "google": {"enabled": False, "client_id": "", "client_secret": "", "hosted_domain": ""},  # nosec B105
        "microsoft": {"enabled": False, "client_id": "", "client_secret": "", "tenant": "common"},  # nosec B105
        "okta": {"enabled": False, "client_id": "", "client_secret": "", "domain": ""},  # nosec B105
    },
}


async def _get_sso_config(s: AsyncSession) -> dict[str, Any]:
    row = await s.get(AppSetting, SSO_SETTING_KEY)
    if row is None or not isinstance(row.value, dict):
        return dict(DEFAULT_SSO_CONFIG)
    cfg = dict(DEFAULT_SSO_CONFIG)
    cfg.update(row.value)
    return cfg


@router.get("/auth/sso/providers")
async def sso_providers(request: Request) -> list[dict[str, Any]]:
    """Public list of active SSO providers for the login page."""
    async with _sm(request)() as s:
        cfg = await _get_sso_config(s)
    if not cfg.get("enabled"):
        return []
    provs = cfg.get("providers", {})
    out = []
    if provs.get("google", {}).get("enabled"):
        out.append({"id": "google", "name": "Google"})
    if provs.get("microsoft", {}).get("enabled"):
        out.append({"id": "microsoft", "name": "Microsoft"})
    if provs.get("okta", {}).get("enabled"):
        out.append({"id": "okta", "name": "Okta"})
    return out


@router.get("/settings/sso")
async def sso_get(who: Admin, request: Request) -> dict[str, Any]:
    """Retrieve SSO configuration (with secrets masked)."""
    async with _sm(request)() as s:
        cfg = await _get_sso_config(s)
    # Mask secrets
    provs = dict(cfg.get("providers", {}))
    for k, p in provs.items():
        if isinstance(p, dict):
            p_copy = dict(p)
            if p_copy.get("client_secret"):
                p_copy["client_secret"] = REDACTED_VALUE
            provs[k] = p_copy
    return {
        "enabled": cfg.get("enabled", False),
        "default_role": cfg.get("default_role", "analyst"),
        "auto_provision": cfg.get("auto_provision", True),
        "providers": provs,
    }


class SsoConfigIn(BaseModel):
    enabled: bool
    default_role: Literal["admin", "analyst", "viewer"] = "analyst"
    auto_provision: bool = True
    providers: dict[str, Any] = Field(default_factory=dict)


@router.put("/settings/sso")
async def sso_save(who: Admin, request: Request, body: SsoConfigIn) -> dict[str, Any]:
    """Update SSO settings."""
    async with _sm(request)() as s, s.begin():
        existing = await _get_sso_config(s)
        new_data = body.model_dump()
        # Preserve masked secrets
        new_provs = new_data.get("providers", {})
        old_provs = existing.get("providers", {})
        for k, p in new_provs.items():
            if isinstance(p, dict) and p.get("client_secret") == REDACTED_VALUE:
                p["client_secret"] = old_provs.get(k, {}).get("client_secret", "")
        row = await s.get(AppSetting, SSO_SETTING_KEY)
        if row is None:
            s.add(AppSetting(key=SSO_SETTING_KEY, value=new_data, updated_by=who.name))
        else:
            row.value = new_data
            row.updated_by = who.name
        s.add(
            AuditLog(
                actor=who.name,
                action="settings.sso_update",
                target=f"settings:{SSO_SETTING_KEY}",
                details={"enabled": body.enabled, "default_role": body.default_role},
            )
        )
    return {"status": "saved"}


class MockSsoIn(BaseModel):
    provider: Literal["google", "microsoft", "okta"]
    email: str = Field(min_length=3, max_length=200)
    name: str = Field(default="", max_length=100)


@router.post("/auth/sso/mock")
async def sso_mock_login(request: Request, body: MockSsoIn) -> Response:
    """Development stand-in for an identity provider (TL_SSO_MOCK=true only).

    Nothing verifies the posted identity, so it is off by default, honours the SSO
    switches in Settings, finds accounts only by their stored SSO link (never by
    email or name) and never signs in or creates an admin."""
    if not _app_settings(request).sso_mock:
        raise HTTPException(404, "Not Found")
    client = request.client.host if request.client else "unknown"
    limiter = request.app.state.limiter
    if await limiter.hit(f"sso:{client}", 20):
        raise HTTPException(429, "Too many requests; wait a minute.")
    async with _sm(request)() as s, s.begin():
        cfg = await _get_sso_config(s)
        if not cfg.get("enabled") or not cfg.get("providers", {}).get(body.provider, {}).get("enabled"):
            raise HTTPException(403, "This sign-in method is switched off.")
        role = cfg.get("default_role", "analyst")
        if role == "admin":
            role = "analyst"  # an unverified identity never becomes an admin
        try:
            user = await users.get_or_create_sso_user(
                s,
                email=body.email,
                name=body.name or body.email.split("@")[0],
                provider=body.provider,
                sso_id=f"sso-{body.provider}-{body.email}",
                default_role=role,
                actor=f"sso:{body.provider}",
                auto_provision=bool(cfg.get("auto_provision", True)),
            )
        except UserError as e:
            raise HTTPException(403, str(e)) from None
        if user.role == "admin":
            raise HTTPException(403, "Admins sign in with their password.")
        tag = session.password_tag(user.password_hash)
        uid = user.id
    resp = JSONResponse({"ok": True, "user": user.name})
    resp.set_cookie(
        session.COOKIE,
        session.issue(_app_settings(request), uid, tag),
        max_age=session.LIFETIME_S,
        httponly=True,
        samesite="strict",
        secure=request.url.scheme == "https",
        path="/",
    )
    return resp


# ── audit log viewer (who blocked, approved, scanned or changed what) ─────────


@router.get("/settings/audit")
async def audit_logs(
    who: Analyst,
    request: Request,
    q: str | None = None,
    category: str | None = None,
    actor: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    """Search and browse audit logs: who blocked, approved, scanned, or changed what."""
    conds = []
    if actor and actor.strip():
        conds.append(AuditLog.actor == actor.strip())
    if category and category != "all":
        if category == "block":
            conds.append(AuditLog.action.like("block.%"))
        elif category == "recon":
            conds.append(AuditLog.action.like("recon.%"))
        elif category == "user":
            conds.append(or_(AuditLog.action.like("user.%"), AuditLog.action.like("api_key.%")))
        elif category == "settings":
            conds.append(
                or_(
                    AuditLog.action.like("settings.%"),
                    AuditLog.action.like("allowlist.%"),
                    AuditLog.action.like("feed_token.%"),
                )
            )
        elif category == "case":
            conds.append(or_(AuditLog.action.like("case.%"), AuditLog.action.like("note.%")))
        else:
            conds.append(AuditLog.action.like(f"{category}.%"))
    if q and q.strip():
        term = f"%{q.strip().lower()}%"
        conds.append(
            or_(
                func.lower(AuditLog.actor).like(term),
                func.lower(AuditLog.action).like(term),
                func.lower(AuditLog.target).like(term),
                func.cast(AuditLog.details, String).like(term),
            )
        )

    async with _sm(request)() as s:
        total = int(await s.scalar(select(func.count()).select_from(AuditLog).where(*conds)) or 0)
        query = select(AuditLog).where(*conds).order_by(AuditLog.id.desc()).offset(offset).limit(limit)
        items = (await s.scalars(query)).all()

        # Gather actors for filtering
        actor_rows = (
            await s.execute(
                select(AuditLog.actor, func.count())
                .group_by(AuditLog.actor)
                .order_by(func.count().desc())
                .limit(20)
            )
        ).all()
        actors = [r[0] for r in actor_rows]

        # Gather category counts
        cat_all = int(await s.scalar(select(func.count()).select_from(AuditLog)) or 0)
        cat_block = int(
            await s.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.action.like("block.%")))
            or 0
        )
        cat_recon = int(
            await s.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.action.like("recon.%")))
            or 0
        )
        cat_user = int(
            await s.scalar(
                select(func.count())
                .select_from(AuditLog)
                .where(or_(AuditLog.action.like("user.%"), AuditLog.action.like("api_key.%")))
            )
            or 0
        )
        cat_settings = int(
            await s.scalar(
                select(func.count())
                .select_from(AuditLog)
                .where(
                    or_(
                        AuditLog.action.like("settings.%"),
                        AuditLog.action.like("allowlist.%"),
                        AuditLog.action.like("feed_token.%"),
                    )
                )
            )
            or 0
        )
        cat_case = int(
            await s.scalar(
                select(func.count())
                .select_from(AuditLog)
                .where(or_(AuditLog.action.like("case.%"), AuditLog.action.like("note.%")))
            )
            or 0
        )

    return {
        "total": total,
        "items": [
            {
                "id": row.id,
                "at": row.at,
                "actor": row.actor,
                "action": row.action,
                "target": defang_text(row.target) if row.target else "",
                "details": _df(row.details),
            }
            for row in items
        ],
        "actors": actors,
        "categories": [
            {"id": "all", "label": "All", "count": cat_all},
            {"id": "block", "label": "Blocks & Approvals", "count": cat_block},
            {"id": "recon", "label": "Scans", "count": cat_recon},
            {"id": "user", "label": "Team & Security", "count": cat_user},
            {"id": "settings", "label": "Policy & Settings", "count": cat_settings},
            {"id": "case", "label": "Cases", "count": cat_case},
        ],
    }


@router.get("/settings/audit/export")
async def audit_export(
    who: Analyst,
    request: Request,
    q: str | None = None,
    category: str | None = None,
    actor: str | None = None,
) -> StreamingResponse:
    """Export filtered audit logs as CSV for compliance or reporting."""
    conds = []
    if actor and actor.strip():
        conds.append(AuditLog.actor == actor.strip())
    if category and category != "all":
        if category == "block":
            conds.append(AuditLog.action.like("block.%"))
        elif category == "recon":
            conds.append(AuditLog.action.like("recon.%"))
        elif category == "user":
            conds.append(or_(AuditLog.action.like("user.%"), AuditLog.action.like("api_key.%")))
        elif category == "settings":
            conds.append(
                or_(
                    AuditLog.action.like("settings.%"),
                    AuditLog.action.like("allowlist.%"),
                    AuditLog.action.like("feed_token.%"),
                )
            )
        elif category == "case":
            conds.append(or_(AuditLog.action.like("case.%"), AuditLog.action.like("note.%")))
        else:
            conds.append(AuditLog.action.like(f"{category}.%"))
    if q and q.strip():
        term = f"%{q.strip().lower()}%"
        conds.append(
            or_(
                func.lower(AuditLog.actor).like(term),
                func.lower(AuditLog.action).like(term),
                func.lower(AuditLog.target).like(term),
                func.cast(AuditLog.details, String).like(term),
            )
        )

    async with _sm(request)() as s:
        rows = (
            await s.scalars(select(AuditLog).where(*conds).order_by(AuditLog.id.desc()).limit(2000))
        ).all()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["ID", "Timestamp (UTC)", "Actor", "Action", "Target", "Details"])
    for r in rows:
        cells = (r.id, r.at.isoformat(), r.actor, r.action, r.target, json.dumps(r.details))
        # every cell goes through sheet_safe, which neutralises formulas
        writer.writerow([sheet_safe(x) for x in cells])  # nosemgrep
    buf.seek(0)

    tag = re.sub(r"[^A-Za-z0-9_.-]+", "_", request.url.query)[:80] or "all"
    filename = f"audit_log_{tag}.csv"
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
