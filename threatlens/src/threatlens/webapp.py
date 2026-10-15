"""Argus: the unified front end (web/), served at /app, and the JSON it reads.

* ``/app/*`` serves the built single-page app (``Settings.web_dist``). The
  page itself needs a signed-in session (the same cookie as /ui); its static
  files (scripts, styles, fonts) hold no data and are served to anyone, with
  long caching for the content-hashed bundles.
* ``/app/api/*`` answers the app with the session cookie, never an API key, and
  applies the reader's TLP clearance to every count, series and row
  (ADR 0008): indicators above it don't exist for them.

The figures are computed from the live store; nothing here is cached or
precomputed, so a feed pull shows up on the next refresh.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from threatlens import catalog, session, totp
from threatlens import tlp as tlp_rules
from threatlens.auth import Principal, same_origin
from threatlens.logs import get_logger
from threatlens.models import (
    Asset,
    ConnectorRun,
    Enrichment,
    Indicator,
    Sighting,
    Source,
    User,
)
from threatlens.models import Observable as ObsRow
from threatlens.settings import Settings, get_settings
from threatlens.users import authenticate_user, login_key

# Register ``api`` before ``router``: the app's catch-all route would otherwise answer /app/api/*.
api = APIRouter(prefix="/app/api", include_in_schema=False)
router = APIRouter(include_in_schema=False)

log = get_logger("threatlens.argus")
APP_CSP = (
    "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; img-src 'self' data:; "
    "font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
)
MALICIOUS, SUSPICIOUS = 60.0, 30.0  # config/scoring.yaml thresholds (ADR 0008)
OK_RUNS = ("success", "not_modified", "unchanged")
Range = Literal["Year", "Month", "Week", "Day"]

TYPE_FAMILY = {
    "ipv4-addr": "ip", "ipv6-addr": "ip", "ipv4-net": "ip", "ipv6-net": "ip", "domain-name": "domain",
    "url": "url", "file-md5": "hash", "file-sha1": "hash", "file-sha256": "hash", "vulnerability": "cve",
    "email-addr": "email", "file-name": "file", "windows-registry-key": "registry",
}  # fmt: skip
TYPE_LABEL = {
    "url": "URLs", "ipv4-net": "IP ranges", "ipv6-net": "IPv6 ranges", "ipv4-addr": "IP addresses",
    "ipv6-addr": "IPv6 addresses", "vulnerability": "Exploited CVEs", "domain-name": "Domains",
    "file-md5": "MD5 hashes", "file-sha1": "SHA-1 hashes", "file-sha256": "SHA-256 hashes",
    "email-addr": "Email addresses", "file-name": "File names", "windows-registry-key": "Registry keys",
}  # fmt: skip
FAMILY_TYPES = {
    "ip": ("ipv4-addr", "ipv6-addr", "ipv4-net", "ipv6-net"),
    "domain": ("domain-name",),
    "url": ("url",),
    "hash": ("file-md5", "file-sha1", "file-sha256"),
    "cve": ("vulnerability",),
}
_REFANG = re.compile(r"\[(\.|:|@)\]")


def _sm(request: Request) -> async_sessionmaker[AsyncSession]:
    sm: async_sessionmaker[AsyncSession] = request.app.state.sessionmaker
    return sm


def _settings(request: Request) -> Settings:
    s: Settings = getattr(request.app.state, "settings", None) or get_settings()
    return s


async def _me(request: Request) -> Principal:
    p = await session.principal(request, _settings(request))
    if p is None:
        raise HTTPException(401, "sign in first")
    return p


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(dt: datetime) -> datetime:
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt


def _pct(now: float, before: float) -> float | None:
    return round((now - before) / before * 100, 1) if before else None


# ── the app itself ───────────────────────────────────────────────────────────


def _dist(request: Request) -> Path:
    return _settings(request).web_dist.resolve()


@router.get("/app")
async def app_root() -> RedirectResponse:
    return RedirectResponse("/app/", status_code=307)


@router.get("/app/{path:path}", response_model=None)
async def app_files(request: Request, path: str) -> Response:
    if path.startswith("api/"):
        raise HTTPException(404, "no such endpoint")
    dist = _dist(request)
    index = dist / "index.html"
    if not index.is_file():
        return HTMLResponse(
            "<h1>Argus is not built</h1><p>Run <code>npm run build</code> in <code>web/</code> and point "
            "<code>TL_WEB_DIST</code> at <code>web/dist</code>.</p>",
            status_code=503,
        )
    if path and not path.endswith("/"):
        target = (dist / path).resolve()
        if target.is_relative_to(dist) and target.is_file() and target.name != "index.html":
            cache = (
                "public, max-age=31536000, immutable"
                if path.startswith("assets/")
                else "public, max-age=3600"
            )
            return FileResponse(target, headers={"Cache-Control": cache})
        if path.startswith(("assets/", "fonts/")):
            raise HTTPException(
                404, "not found"
            )  # a missing static file; anything else is an app route (scan pages end in .json)
    # Any other path is an app route: the page needs a session, except the sign-in page.
    if path != "login" and await session.principal(request, _settings(request)) is None:
        here = "/app/" + path + (f"?{request.url.query}" if request.url.query else "")
        return RedirectResponse(f"/app/login?next={quote(here, safe='/')}", status_code=303)
    return FileResponse(
        index,
        headers={
            "Content-Security-Policy": APP_CSP,
            "Cache-Control": "no-store",
            "Referrer-Policy": "same-origin",
        },
    )


# ── sign in / sign out ───────────────────────────────────────────────────────


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=200)
    password: str = Field(min_length=1, max_length=1000)
    totp_code: str | None = None


def safe_next(nxt: str) -> str:
    """Only Argus paths are valid post-login targets (no open redirect)."""
    ok = nxt.startswith("/app/") and "//" not in nxt and "\\" not in nxt
    return nxt if ok else "/app/"


@api.post("/session")
async def login(request: Request, body: LoginIn) -> Response:
    """Username + password sign-in (ADR 0007, 0017): same-site only, rate-limited per
    address and per account, a signed HttpOnly SameSite=Strict cookie, with TOTP 2FA support."""
    if not same_origin(request):
        raise HTTPException(403, "cross-site sign-in refused")
    client = request.client.host if request.client else "unknown"
    limiter = request.app.state.limiter
    if await limiter.hit(f"login:{client}", 10) or await limiter.hit(
        f"login-user:{login_key(body.username)}", 10
    ):
        raise HTTPException(429, "Too many attempts; wait a minute.")
    async with _sm(request)() as s, s.begin():
        user = await authenticate_user(s, body.username, body.password)
        if user is not None and user.totp_secret:
            if not body.totp_code:
                # Signal to the frontend that 2FA is required for this user
                return JSONResponse({"ok": False, "totp_required": True, "username": user.name})
            if not totp.verify_totp(user.totp_secret, body.totp_code):
                log.warning("argus.totp_failed", user=user.name, client=client)
                raise HTTPException(401, "Invalid two-factor authentication code.")
            wait_replay = await limiter.hit(f"totp-login:{user.id}:{body.totp_code.strip()}", 1, 90)
            if wait_replay:
                log.warning("argus.totp_replayed", user=user.name, client=client)
                raise HTTPException(
                    401, "This two-factor code was already used. Please wait for the next code."
                )
        tag = session.password_tag(user.password_hash) if user else ""
        uid = user.id if user else 0
    if user is None:
        log.warning("argus.login_failed", user=body.username[:100], client=client)
        raise HTTPException(401, "Wrong username or password.")
    resp = JSONResponse({"ok": True})
    resp.set_cookie(
        session.COOKIE,
        session.issue(_settings(request), uid, tag),
        max_age=session.LIFETIME_S,
        httponly=True,
        samesite="strict",
        secure=request.url.scheme == "https",
        path="/",
    )
    return resp


@api.delete("/session")
async def logout(request: Request) -> Response:
    if not same_origin(request):
        raise HTTPException(403, "cross-site request refused")
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(session.COOKIE, path="/")
    return resp


# ── who is signed in ─────────────────────────────────────────────────────────


@api.get("/me")
async def me(request: Request) -> dict[str, Any]:
    p = await _me(request)
    words = [w for w in re.split(r"[\s._-]+", p.name) if w]
    initials = "".join(w[0] for w in words[:2]).upper() or "?"
    async with _sm(request)() as s:
        user_row = await s.get(User, p.key_id) if p.kind == "user" else None
    return {
        "id": p.key_id,
        "name": p.name.title(),
        "login": user_row.login if user_row else p.name.lower(),
        "role": p.role,
        "clearance": p.clearance,
        "initials": initials,
        "totp_enabled": bool(user_row and user_row.totp_secret),
    }


# ── the Reports dashboard ────────────────────────────────────────────────────


@api.get("/kpis")
async def kpis(request: Request) -> list[dict[str, Any]]:
    p = await _me(request)
    now = _now()
    week_ago = now - timedelta(days=7)
    vis = Indicator.tlp.in_(tlp_rules.readable(p.clearance))
    async with _sm(request)() as s:
        count = select(func.count()).select_from(Indicator)
        active = await s.scalar(count.where(Indicator.status == "active", vis)) or 0
        total = await s.scalar(count.where(vis)) or 0
        before = await s.scalar(count.where(vis, Indicator.created_at < week_ago)) or 0
        malicious = (
            await s.scalar(
                count.where(Indicator.status == "active", vis, Indicator.priority_score >= MALICIOUS)
            )
            or 0
        )
        assets = await s.scalar(select(func.count()).select_from(Asset)) or 0
        assets_before = (
            await s.scalar(select(func.count()).select_from(Asset).where(Asset.first_seen < week_ago)) or 0
        )
        custom = await catalog.custom_names(s)
        feeds = [
            r
            for r in (await s.scalars(select(Source).where(Source.enabled.is_(True)))).all()
            if catalog.collectable(r, custom)
        ]
    healthy = sum(1 for f in feeds if f.health == "ok")
    failing = sum(1 for f in feeds if f.health in ("failing", "degraded"))
    return [
        {"key": "active", "label": "Active indicators", "value": active, "change": _pct(total, before),
         "hint": f"{total - before:,} new this week", "icon": "radar"},
        {"key": "malicious", "label": "Scored malicious", "value": malicious, "change": None,
         "hint": f"score {MALICIOUS:.0f}+ of 100", "icon": "alert"},
        {"key": "assets", "label": "Assets monitored", "value": assets, "change": _pct(assets, assets_before),
         "hint": "hosts, IPs, domains" if assets else "run or import a ReconX scan", "icon": "server"},
        {"key": "feeds", "label": "Feeds healthy", "value": healthy, "of": len(feeds), "change": None,
         "hint": f"{failing} need attention" if failing else "all pulling normally", "icon": "feed"},
    ]  # fmt: skip


def _buckets(rng: Range, now: datetime) -> tuple[datetime, timedelta | None, list[tuple[str, str, datetime]]]:
    """(start, step, [(axis label, tooltip date, bucket start)]); a None step means calendar months."""
    if rng == "Day":
        start = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=23)
        return start, timedelta(hours=1), [
            ((start + timedelta(hours=i)).strftime("%H:00"),
             (start + timedelta(hours=i)).strftime("%b %d, %Y · %H:00"), start + timedelta(hours=i))
            for i in range(24)
        ]  # fmt: skip
    if rng in ("Week", "Month"):
        n = 7 if rng == "Week" else 30
        start = now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=n - 1)
        days = [start + timedelta(days=i) for i in range(n)]
        fmt = "%a" if rng == "Week" else "%d"
        return (
            start,
            timedelta(days=1),
            [(d.strftime(fmt).lstrip("0"), d.strftime("%b %d, %Y"), d) for d in days],
        )
    first = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    months = []
    y, m = first.year, first.month
    for _ in range(12):
        months.append(datetime(y, m, 1, tzinfo=UTC))
        y, m = (y, m - 1) if m > 1 else (y - 1, 12)
    months.reverse()
    return months[0], None, [(d.strftime("%b"), d.strftime("%B %Y"), d) for d in months]


@api.get("/activity")
async def activity(request: Request, range_: Annotated[str, Query(alias="range")] = "Year") -> dict[str, Any]:
    """New indicators per period, split by today's verdict, and the total
    against the previous period of the same length."""
    p = await _me(request)
    rng: Range = range_ if range_ in ("Year", "Month", "Week", "Day") else "Year"  # type: ignore[assignment]
    now = _now()
    start, step, buckets = _buckets(rng, now)
    span = now - start
    vis = Indicator.tlp.in_(tlp_rules.readable(p.clearance))
    async with _sm(request)() as s:
        rows = (
            await s.execute(
                select(Indicator.created_at, Indicator.priority_score).where(
                    vis, Indicator.created_at >= start
                )
            )
        ).all()
        previous = (
            await s.scalar(
                select(func.count())
                .select_from(Indicator)
                .where(vis, Indicator.created_at >= start - span, Indicator.created_at < start)
            )
            or 0
        )
    mal: Counter[int] = Counter()
    sus: Counter[int] = Counter()
    starts = [b[2] for b in buckets]
    for created, score in rows:
        t = _aware(created)
        if step is None:
            i = (t.year - starts[0].year) * 12 + t.month - starts[0].month
        else:
            i = int((t - start) / step)
        if not 0 <= i < len(buckets):
            continue
        if (score or 0) >= MALICIOUS:
            mal[i] += 1
        elif (score or 0) >= SUSPICIOUS:
            sus[i] += 1
    points = [
        {"label": label, "date": date, "malicious": mal[i], "suspicious": sus[i]}
        for i, (label, date, _) in enumerate(buckets)
    ]
    return {"range": rng, "total": len(rows), "change": _pct(len(rows), previous), "points": points}


@api.get("/types")
async def types(request: Request, scope: str = "Active") -> dict[str, Any]:
    """Indicators by type (the rings) within the reader's clearance."""
    p = await _me(request)
    vis = Indicator.tlp.in_(tlp_rules.readable(p.clearance))
    where: list[Any] = [vis]
    if scope == "Active":
        where.append(Indicator.status == "active")
    elif scope == "Malicious":
        where += [Indicator.status == "active", Indicator.priority_score >= MALICIOUS]
    async with _sm(request)() as s:
        rows = (
            await s.execute(
                select(ObsRow.type, func.count())
                .join(Indicator, Indicator.observable_id == ObsRow.id)
                .where(*where)
                .group_by(ObsRow.type)
                .order_by(func.count().desc())
            )
        ).all()
    items = [{"type": t, "name": TYPE_LABEL.get(t, t), "value": int(n)} for t, n in rows]
    return {"scope": scope, "scopes": ["Active", "Malicious", "All"], "total": sum(i["value"] for i in items),
            "items": items}  # fmt: skip


@api.get("/collection")
async def collection(request: Request, week: str = "This week") -> dict[str, Any]:
    """Feed pulls per weekday: succeeded vs skipped or failed."""
    await _me(request)
    now = _now()
    monday = now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=now.weekday())
    if week == "Last week":
        monday -= timedelta(days=7)
    end = monday + timedelta(days=7)
    async with _sm(request)() as s:
        rows = (
            await s.execute(
                select(ConnectorRun.started_at, ConnectorRun.status).where(
                    ConnectorRun.started_at >= monday, ConnectorRun.started_at < end
                )
            )
        ).all()
    ok: Counter[int] = Counter()
    bad: Counter[int] = Counter()
    for started, status in rows:
        d = (_aware(started) - monday).days
        (ok if status in OK_RUNS else bad)[d] += 1
    days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    return {
        "week": week,
        "weeks": ["This week", "Last week"],
        "total": len(rows),
        "days": [{"day": d, "ok": ok[i], "other": bad[i]} for i, d in enumerate(days)],
    }


@api.get("/indicators")
async def indicators(
    request: Request,
    q: Annotated[str, Query(max_length=200)] = "",
    status: Annotated[str, Query(max_length=20)] = "",
    type_: Annotated[str, Query(alias="type", max_length=10)] = "",
    page: Annotated[int, Query(ge=1, le=10_000)] = 1,
    size: Annotated[int, Query(ge=1, le=50)] = 8,
) -> dict[str, Any]:
    """Latest indicators, newest first, filtered and paged on the server."""
    p = await _me(request)
    where: list[Any] = [Indicator.tlp.in_(tlp_rules.readable(p.clearance))]
    if status in ("active", "expired", "false_positive", "revoked"):
        where.append(Indicator.status == status)
    if type_ in FAMILY_TYPES:
        where.append(ObsRow.type.in_(FAMILY_TYPES[type_]))
    needle = _REFANG.sub(r"\1", q.strip()).lower().replace("hxxp", "http")
    if needle:
        where.append(
            or_(
                ObsRow.value.contains(needle, autoescape=True),
                ObsRow.defanged.contains(q.strip(), autoescape=True),
            )
        )
    async with _sm(request)() as s:
        base = select(Indicator, ObsRow).join(ObsRow, Indicator.observable_id == ObsRow.id).where(*where)
        total = await s.scalar(select(func.count()).select_from(base.subquery())) or 0
        rows = (
            await s.execute(
                base.order_by(Indicator.created_at.desc(), Indicator.id.desc())
                .offset((page - 1) * size)
                .limit(size)
            )
        ).all()
        ids = [ind.id for ind, _ in rows]
        sources: dict[int, list[str]] = defaultdict(list)
        country: dict[int, str] = {}
        if ids:
            for ind_id, title, ctx in (
                await s.execute(
                    select(Sighting.indicator_id, Source.title, Sighting.context)
                    .join(Source, Source.id == Sighting.source_id)
                    .where(Sighting.indicator_id.in_(ids))
                )
            ).all():
                sources[ind_id].append(title)
                if isinstance(ctx, dict) and ctx.get("country"):
                    country.setdefault(ind_id, str(ctx["country"]))
            by_obs = {obs.id: ind.id for ind, obs in rows}
            for obs_id, summary in (
                await s.execute(
                    select(Enrichment.observable_id, Enrichment.summary).where(
                        Enrichment.observable_id.in_(list(by_obs)),
                        Enrichment.enricher.in_(("ripestat", "abuseipdb", "rdap")),
                    )
                )
            ).all():
                c = (summary or {}).get("country")
                if c and obs_id in by_obs:
                    country.setdefault(by_obs[obs_id], str(c))
    items = [
        {
            "id": ind.id,
            "value": obs.defanged or obs.value,
            "type": TYPE_FAMILY.get(obs.type, "other"),
            "typeLabel": TYPE_LABEL.get(obs.type, obs.type).rstrip("s")
            if obs.type != "vulnerability"
            else "CVE",
            "sources": sorted(set(sources[ind.id])),
            "firstSeen": _aware(ind.created_at).isoformat(),
            "lastSeen": _aware(obs.last_seen).isoformat() if obs.last_seen else None,
            "country": country.get(ind.id),
            "status": ind.status,
            "score": round(ind.priority_score) if ind.priority_score is not None else None,
            "tlp": ind.tlp,
        }
        for ind, obs in rows
    ]
    return {"total": int(total), "page": page, "size": size, "items": items}


# ── the classic UI moved here (ADR 0016) ─────────────────────────────────────

_RENAMED = {"lookup": "bulk", "sources": "feeds", "": ""}


@router.get("/ui")
@router.get("/ui/{path:path}")
async def classic(request: Request, path: str = "") -> RedirectResponse:
    """Old /ui addresses (bookmarks, links in reports) open the same Argus page."""
    head, _, rest = path.partition("/")
    target = "/app/" + "/".join(x for x in (_RENAMED.get(head, head), rest) if x)
    if request.url.query:
        target += "?" + request.url.query
    return RedirectResponse(target, status_code=301)
