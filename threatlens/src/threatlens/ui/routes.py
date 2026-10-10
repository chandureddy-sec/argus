"""Analyst UI: server-rendered pages under /ui.

Security: every page needs a signed session (see ``session.py``); templates
autoescape everything, so feed content is always shown as text; indicators
are displayed defanged; pages carry a strict CSP with no scripts at all and
external links open with ``rel="noopener noreferrer"``.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, Literal, get_args
from urllib.parse import quote, urlparse

from fastapi import APIRouter, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from threatlens import __version__
from threatlens.api import kb as kb_api
from threatlens.api import v1 as v1_api
from threatlens.auth import Principal, authenticate
from threatlens.connectors.base import clip
from threatlens.ioc.extract import defang_text
from threatlens.ioc.types import IOCType
from threatlens.kb import graph
from threatlens.kb.nvd import stack_cpes
from threatlens.models import Entity, Indicator, Relationship, Source, Vulnerability, VulnerabilityProduct
from threatlens.settings import Settings, get_settings
from threatlens.ui import charts, data, session

HERE = Path(__file__).parent
templates = Jinja2Templates(directory=str(HERE / "templates"))
templates.env.globals.update(charts=charts, version=__version__)
router = APIRouter(prefix="/ui", include_in_schema=False)
Status = Literal["new", "active", "expired", "revoked", "false_positive"]
STATUSES: dict[str, Status] = {s: s for s in get_args(Status)}

UI_CSP = (
    "default-src 'none'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
    "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
)
_CITATION = re.compile(r"\(Citation:[^)]*\)")
_MD_LINK = re.compile(r"\[([^\]]+)\]\((https?://[^)]+)\)")


def plain(text: str | None, n: int = 2000) -> str:
    """ATT&CK prose without citation markers or Markdown link syntax."""
    t = _MD_LINK.sub(r"\1", _CITATION.sub("", text or ""))
    return clip(re.sub(r"[ \t]+", " ", t).strip(), n)


def ago(dt: datetime | None) -> str:
    if dt is None:
        return "never"
    dt = dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    secs = (datetime.now(UTC) - dt).total_seconds()
    if secs < 0:
        return "in " + ago(datetime.now(UTC) - (dt - datetime.now(UTC)))[:-4]
    for unit, n in (("d", 86400), ("h", 3600), ("m", 60)):
        if secs >= n:
            return f"{int(secs // n)}{unit} ago"
    return "just now"


def safe_url(url: str | None) -> str | None:
    return url if url and urlparse(url).scheme in ("http", "https") else None


templates.env.filters.update(
    plain=plain, ago=ago, safe_url=safe_url, defang_text=defang_text, quote=lambda s: quote(str(s), safe="")
)


def _sm(request: Request) -> async_sessionmaker[AsyncSession]:
    sm: async_sessionmaker[AsyncSession] = request.app.state.sessionmaker
    return sm


def _settings(request: Request) -> Settings:
    s: Settings = getattr(request.app.state, "settings", None) or get_settings()
    return s


def page(request: Request, name: str, ctx: dict[str, Any], status: int = 200) -> HTMLResponse:
    resp = templates.TemplateResponse(request, name, {"path": request.url.path, **ctx}, status_code=status)
    resp.headers["Content-Security-Policy"] = UI_CSP
    resp.headers["Referrer-Policy"] = "same-origin"  # never sent to other sites
    return resp


async def who(request: Request) -> Principal:
    p = await session.principal(request, _settings(request))
    if p is None:
        nxt = quote(
            str(request.url.path) + (f"?{request.url.query}" if request.url.query else ""), safe="/?=&"
        )
        raise HTTPException(303, headers={"Location": f"/ui/login?next={nxt}"})
    return p


def _same_origin(request: Request) -> bool:
    """Refuse state-changing requests that another site's page triggered.

    Browsers send ``Sec-Fetch-Site`` (a page cannot set it); older ones fall
    back to ``Origin``. Requests with neither are not from a browser page."""
    site = request.headers.get("sec-fetch-site")
    if site is not None:
        return site in ("same-origin", "none")
    origin = request.headers.get("origin")
    if origin is None:
        return True
    return origin != "null" and urlparse(origin).netloc == request.headers.get("host", "")


def _target(nxt: str) -> str:
    """Only paths inside the UI are valid post-login redirects (no open redirect)."""
    ok = nxt.startswith("/ui") and "//" not in nxt and "\\" not in nxt
    return nxt if ok else "/ui"


# ── login / logout ───────────────────────────────────────────────────────────


@router.get("/login", response_class=HTMLResponse)
async def login_form(
    request: Request, next_: Annotated[str, Query(alias="next", max_length=500)] = "/ui"
) -> HTMLResponse:
    return page(request, "login.html", {"next": _target(next_), "error": None})


@router.post("/login", response_model=None)
async def login(
    request: Request,
    key: Annotated[str, Form(max_length=200)],
    next_: Annotated[str, Form(alias="next", max_length=500)] = "/ui",
) -> Response:
    target = _target(next_)
    if not _same_origin(request):
        raise HTTPException(403, "cross-site login refused")
    client = request.client.host if request.client else "unknown"
    if await request.app.state.limiter.hit(f"login:{client}", 10):
        return page(
            request, "login.html", {"next": target, "error": "Too many attempts; wait a minute."}, 429
        )
    async with _sm(request)() as s:
        p = await authenticate(s, key.strip())
    if p is None:
        return page(
            request,
            "login.html",
            {"next": target, "error": "That key is not valid, expired or revoked."},
            401,
        )
    resp = RedirectResponse(target, status_code=303)
    resp.set_cookie(
        session.COOKIE,
        session.issue(_settings(request), p.key_id),
        max_age=session.LIFETIME_S,
        httponly=True,
        samesite="strict",
        secure=request.url.scheme == "https",
        path="/",
    )
    return resp


@router.post("/logout", response_model=None)
async def logout(request: Request) -> Response:
    if not _same_origin(request):
        raise HTTPException(403, "cross-site request refused")
    resp = RedirectResponse("/ui/login", status_code=303)
    resp.delete_cookie(session.COOKIE, path="/")
    return resp


# ── pages ────────────────────────────────────────────────────────────────────


def _stack(request: Request) -> list[tuple[str, str]]:
    return [(v, p) for _, v, p in stack_cpes(_settings(request))]


@router.get("", response_class=HTMLResponse)
async def overview(request: Request) -> HTMLResponse:
    me = await who(request)
    async with _sm(request)() as s:
        d = await data.overview(s, datetime.now(UTC), _stack(request))
    return page(request, "overview.html", {"me": me, "d": d})


@router.get("/search", response_model=None)
async def search(request: Request, q: Annotated[str, Query(max_length=300)] = "") -> Response:
    await who(request)
    q = q.strip()
    if not q:
        return RedirectResponse("/ui", status_code=303)
    async with _sm(request)() as s:
        node = await graph.resolve(s, q)
        ind_id = None
        if node is not None and node.kind == "indicator":
            ind_id = node.extra.get("id")
    if node is None:
        return RedirectResponse(f"/ui/indicators?q={quote(q)}", status_code=303)
    if node.kind == "vulnerability":
        return RedirectResponse(f"/ui/vulnerabilities/{quote(node.label)}", status_code=303)
    if node.kind == "indicator":
        return RedirectResponse(f"/ui/indicators/{ind_id}", status_code=303)
    return RedirectResponse(f"/ui/entities/{quote(node.external_id or node.ref)}", status_code=303)


@router.get("/indicators", response_class=HTMLResponse)
async def indicators(
    request: Request,
    type: Annotated[str | None, Query(max_length=32)] = None,  # noqa: A002
    status: Annotated[str | None, Query(max_length=20)] = None,
    source: Annotated[str | None, Query(max_length=64)] = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
    page_no: Annotated[int, Query(alias="page", ge=1, le=10_000)] = 1,
) -> HTMLResponse:
    me = await who(request)
    ioc_type = IOCType(type) if type in {t.value for t in IOCType} else None
    st = STATUSES.get(status or "")
    res = await v1_api.list_indicators(
        me, request, type=ioc_type, status=st, source=source or None,
        q=q if q and len(q) >= 2 else None, limit=50, offset=(page_no - 1) * 50,
    )  # fmt: skip
    async with _sm(request)() as s:
        names = list((await s.scalars(select(Source.name).order_by(Source.name))).all())
    return page(
        request,
        "indicators.html",
        {
            "me": me,
            "res": res,
            "f": {"type": type or "", "status": status or "", "source": source or "", "q": q or ""},
            "types": data.TYPE_LABELS,
            "sources": names,
            "page_no": page_no,
        },
    )


@router.get("/indicators/{indicator_id}", response_class=HTMLResponse)
async def indicator(request: Request, indicator_id: int) -> HTMLResponse:
    me = await who(request)
    ind = await v1_api.get_indicator(me, request, indicator_id)
    async with _sm(request)() as s:
        ref = await s.scalar(select(Indicator.stix_id).where(Indicator.id == indicator_id))
        related, _ = await graph.neighbors(s, ref, limit=50) if ref else ([], 0)
        # one more hop: what the linked malware does
        techniques: list[dict[str, Any]] = []
        for r in related:
            if r["node"]["type"] in ("malware", "tool") and r["node"]["kind"] == "entity":
                items, _ = await graph.neighbors(
                    s, r["node"]["ref"], direction="out", rel="uses", node_type="attack-pattern", limit=200
                )
                techniques += [{"via": r["node"]["label"], **i} for i in items]
    return page(
        request, "indicator.html", {"me": me, "ind": ind, "related": related, "techniques": techniques[:60]}
    )


@router.get("/vulnerabilities", response_class=HTMLResponse)
async def vulnerabilities(
    request: Request,
    kev: bool | None = None,
    stack: bool = False,
    q: Annotated[str | None, Query(max_length=200)] = None,
    sort: Annotated[str, Query(max_length=16)] = "epss",
    page_no: Annotated[int, Query(alias="page", ge=1, le=10_000)] = 1,
) -> HTMLResponse:
    me = await who(request)
    stmt = select(Vulnerability)
    async with _sm(request)() as s:
        if stack:
            stmt = stmt.where(Vulnerability.id.in_(await data.stack_cve_ids(s, _stack(request))))
        if kev is not None:
            stmt = stmt.where(Vulnerability.kev.is_(kev))
        if q and len(q) >= 2:
            like = kb_api._like(q)  # shared escaping helper
            stmt = stmt.where(
                or_(
                    func.lower(Vulnerability.cve_id).like(like, escape="\\"),
                    func.lower(Vulnerability.description).like(like, escape="\\"),
                )
            )
        col = {
            "cvss": Vulnerability.cvss_score,
            "kev_date": Vulnerability.kev_date_added,
            "published": Vulnerability.published,
        }.get(sort, Vulnerability.epss)
        total = await data._count(s, stmt)
        rows = (
            await s.scalars(
                stmt.order_by(col.desc().nulls_last(), Vulnerability.cve_id.desc())
                .limit(50)
                .offset((page_no - 1) * 50)
            )
        ).all()
        prods: dict[int, str] = {}
        for vid, vendor, product in (
            await s.execute(
                select(
                    VulnerabilityProduct.vulnerability_id,
                    VulnerabilityProduct.vendor,
                    VulnerabilityProduct.product,
                )
                .where(VulnerabilityProduct.vulnerability_id.in_([v.id for v in rows]))
                .order_by(VulnerabilityProduct.id)
            )
        ).all():
            prods.setdefault(vid, f"{vendor} {product}".replace("_", " "))
    return page(
        request,
        "vulnerabilities.html",
        {"me": me, "rows": rows, "total": total, "prods": prods, "page_no": page_no,
         "f": {"kev": "" if kev is None else str(kev).lower(), "stack": stack, "q": q or "", "sort": sort}},
    )  # fmt: skip


@router.get("/vulnerabilities/{cve}", response_class=HTMLResponse)
async def vulnerability(request: Request, cve: str) -> HTMLResponse:
    me = await who(request)
    v = await kb_api.get_vulnerability(me, request, cve)
    async with _sm(request)() as s:
        related, _ = await graph.neighbors(s, v.stix_id, limit=50)
        vid = await s.scalar(select(Vulnerability.id).where(Vulnerability.cve_id == v.cve_id))
        in_stack = vid in await data.stack_cve_ids(s, _stack(request))
    return page(request, "vulnerability.html", {"me": me, "v": v, "related": related, "in_stack": in_stack})


@router.get("/entities/{ident}", response_class=HTMLResponse)
async def entity(request: Request, ident: str) -> HTMLResponse:
    me = await who(request)
    e = await kb_api.get_entity(me, request, ident)
    async with _sm(request)() as s:
        uses, _ = await graph.neighbors(s, e.stix_id, direction="out", rel="uses", limit=500)
        used_by, _ = await graph.neighbors(s, e.stix_id, direction="in", rel="uses", limit=100)
        indicators_n = await s.scalar(
            select(func.count())
            .select_from(Relationship)
            .where(Relationship.dst_ref == e.stix_id, Relationship.rel_type == "indicates")
        )
        mentions, _ = await graph.neighbors(
            s, e.stix_id, direction="out", rel="related-to", node_type="vulnerability", limit=50
        )
        matrix = (
            await data.attack_matrix(s, [e.stix_id])
            if e.type in ("malware", "tool", "intrusion-set", "campaign")
            else None
        )
    techniques = [u for u in uses if u["node"]["type"] == "attack-pattern"]
    software = [u for u in uses if u["node"]["type"] in ("malware", "tool")]
    return page(
        request,
        "entity.html",
        {"me": me, "e": e, "techniques": techniques, "software": software, "used_by": used_by,
         "indicators_n": indicators_n or 0, "mentions": mentions, "matrix": matrix},
    )  # fmt: skip


@router.get("/attack", response_class=HTMLResponse)
async def attack(request: Request) -> HTMLResponse:
    me = await who(request)
    async with _sm(request)() as s:
        m = await data.attack_matrix(s)
        fams = (
            await s.execute(
                select(
                    Entity.name,
                    Entity.external_id,
                    Entity.stix_id,
                    func.count(func.distinct(Relationship.src_ref)),
                )
                .join(Relationship, Relationship.dst_ref == Entity.stix_id)
                .where(Relationship.origin == "feed", Relationship.rel_type == "indicates")
                .group_by(Entity.name, Entity.external_id, Entity.stix_id)
                .order_by(func.count(func.distinct(Relationship.src_ref)).desc())
            )
        ).all()
    return page(request, "attack.html", {"me": me, "m": m, "fams": fams})


@router.get("/sources", response_class=HTMLResponse)
async def sources(request: Request) -> HTMLResponse:
    me = await who(request)
    rows = await v1_api.list_sources(me, request)
    async with _sm(request)() as s:
        runs = await data.last_runs(s)
    return page(request, "sources.html", {"me": me, "rows": rows, "runs": runs})
