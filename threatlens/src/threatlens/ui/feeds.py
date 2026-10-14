"""Feed catalog pages (ADR 0012): every source with an on/off switch, "Pull
now" and "Sync all feeds"; a page per source (provenance, terms, pull
history, what it contributed); and the form to add or edit a custom feed.

Anyone signed in can read; changes need the admin role and come by POST from
this site. A stored feed key is never sent back to the browser.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from typing import Annotated, Any

from fastapi import APIRouter, BackgroundTasks, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import select

from threatlens import catalog
from threatlens.api import v1 as v1_api
from threatlens.api.catalog import enabled_sources, forget_enabled, queue_runs, rescore_ids
from threatlens.auth import Principal
from threatlens.connectors import REGISTRY
from threatlens.connectors.custom import FORMATS
from threatlens.kb import KB_REGISTRY
from threatlens.models import TLP_LEVELS, CustomFeed, Source
from threatlens.ui import data
from threatlens.ui.respond import _need
from threatlens.ui.routes import _settings, _sm, page, who
from threatlens.vault import VaultError
from threatlens.verify import TYPE

router = APIRouter(prefix="/ui", include_in_schema=False)

# Fixed notices picked by a code in the redirect, so no request text is echoed.
NOTICES = {
    "queued": "Pull queued. The page shows the result once the worker has run it.",
    "busy": "Already queued: it runs as soon as the worker gets to it.",
    "synced": "Every enabled source is queued. Sources that ran recently wait for their minimum gap.",
    "on": "Switched on: it pulls on the next scheduler tick.",
    "off": "Switched off: it won't pull until switched on again. What it reported stays.",
    "saved": "Saved.",
    "added": "Feed added. It pulls on the next scheduler tick, or press Pull now.",
    "removed": "Feed removed. Indicators only it reported are revoked and re-scored.",
}
TYPE_CHOICES = [("auto", "Detect each value"), ("ip", "IP addresses / ranges"), ("domain", "Domains"),
                ("url", "URLs"), ("hash", "File hashes")]  # fmt: skip
FORMAT_CHOICES = [("text", "Plain text, one per line"), ("csv", "CSV"), ("json", "JSON")]
GRADE_CHOICES = [
    ("A", "A · completely reliable"), ("B", "B · usually reliable"), ("C", "C · fairly reliable"),
    ("D", "D · not usually reliable"), ("E", "E · unreliable"), ("F", "F · can't be judged"),
]  # fmt: skip


SHOW: dict[str, Callable[[v1_api.SourceOut], bool]] = {
    "all": lambda r: True,
    "on": lambda r: r.enabled,
    "off": lambda r: not r.enabled,
    "failing": lambda r: r.enabled and r.health in ("failing", "degraded"),
    "custom": lambda r: r.custom,
}


def _back(name: str | None, code: str) -> RedirectResponse:
    where = f"/ui/sources/{name}" if name else "/ui/sources"
    return RedirectResponse(f"{where}?done={code}", status_code=303)


async def _ensure_providers(request: Request) -> None:
    """Lookup providers get their rows on the first lookup; make sure they
    are listed (and can be switched off) before anyone has looked anything up."""
    svc = getattr(request.app.state, "enrich", None)
    if svc is not None:
        await svc.ensure_sources()


async def _rows(request: Request, me: Principal) -> list[v1_api.SourceOut]:
    return await v1_api.list_sources(me, request)


@router.get("/sources", response_class=HTMLResponse)
async def sources(
    request: Request,
    done: Annotated[str, Query(max_length=10)] = "",
    show: Annotated[str, Query(max_length=10)] = "all",
) -> HTMLResponse:
    me = await who(request)
    await _ensure_providers(request)
    rows = await _rows(request, me)
    async with _sm(request)() as s:
        runs = await data.last_runs(s)
    show = show if show in SHOW else "all"
    keep = SHOW[show]
    groups = {
        "feeds": [r for r in rows if r.name in REGISTRY and keep(r)],
        "custom": [r for r in rows if r.custom and keep(r)],
        "knowledge": [r for r in rows if r.name in KB_REGISTRY and keep(r)],
        "enrichers": [r for r in rows if r.kind == "enricher" and keep(r)],
    }
    on = sum(1 for r in rows if r.enabled and r.kind != "enricher")
    failing = sum(1 for r in rows if SHOW["failing"](r))
    return page(request, "sources.html", {
        "me": me, "rows": rows, "runs": runs, "groups": groups, "notice": NOTICES.get(done),
        "show": show,
        "counts": {"on": on, "off": sum(1 for r in rows if not r.enabled), "failing": failing,
                   "custom": sum(1 for r in rows if r.custom), "all": len(rows)},
    })  # fmt: skip


@router.post("/sources/sync", response_model=None)
async def sync_all(request: Request) -> Response:
    me = await who(request)
    _need(request, me, "admin")
    await queue_runs(request, await enabled_sources(_sm(request)), me.name)
    return _back(None, "synced")


@router.get("/sources/new", response_class=HTMLResponse)
async def new_feed(request: Request) -> HTMLResponse:
    me = await who(request)
    _need_admin_page(me)
    return page(request, "source_form.html", _form_ctx(me, catalog.FeedForm(title="", url=""), None, None))


@router.post("/sources/new", response_model=None)
async def create_feed(request: Request) -> Response:
    me = await who(request)
    _need(request, me, "admin")
    f = await _read_form(request)
    try:
        async with _sm(request)() as s, s.begin():
            src = await catalog.create(s, f, actor=me.name, settings=_settings(request))
            name = src.name
    except (catalog.CatalogError, VaultError) as e:
        f.secret = ""  # never sent back  # nosec B105
        return page(request, "source_form.html", _form_ctx(me, f, None, str(e)), 422)
    return _back(name, "added")


@router.get("/sources/{name}", response_class=HTMLResponse)
async def source_page(
    request: Request, name: str, done: Annotated[str, Query(max_length=10)] = ""
) -> HTMLResponse:
    me = await who(request)
    async with _sm(request)() as s:
        src = await s.scalar(select(Source).where(Source.name == name))
        if src is None:
            raise HTTPException(404, "unknown source")
        feed = await s.scalar(select(CustomFeed).where(CustomFeed.source_id == src.id))
        history = await catalog.runs(s, src.id, 60)
        contrib = await catalog.contribution(s, src.id, me.clearance) if src.kind != "enricher" else None
        custom = await catalog.custom_names(s)
    out = v1_api._source_out(src, _settings(request))
    chrono = list(reversed(history[:30]))
    bins = [(r.started_at.strftime("%d %b"), float(r.items_new)) for r in chrono]
    ok = sum(1 for r in history if r.status in ("success", "not_modified", "unchanged"))
    form = _form_of(src, feed) if feed is not None else None
    return page(request, "source.html", {
        "me": me, "s": out, "src": src, "feed": feed, "history": history, "bins": bins, "contrib": contrib,
        "ok_rate": round(100 * ok / len(history)) if history else None, "notice": NOTICES.get(done),
        "collectable": catalog.collectable(src, custom), "every": _every(src.interval_minutes),
        "type_rows": [(TYPE.get(t, t), float(n), f"/ui/indicators?source={src.name}&type={t}")
                      for t, n in (contrib or {}).get("by_type", {}).items()],
        "edit": form is not None, **(_form_ctx(me, form, src.name, None) if form else {}),
    })  # fmt: skip


@router.post("/sources/{name}/edit", response_model=None)
async def edit_feed(request: Request, name: str) -> Response:
    me = await who(request)
    _need(request, me, "admin")
    f = await _read_form(request)
    try:
        async with _sm(request)() as s, s.begin():
            await catalog.edit(s, name, f, actor=me.name, settings=_settings(request))
    except (catalog.CatalogError, VaultError) as e:
        if "no such" in str(e):
            raise HTTPException(404, str(e)) from None
        f.secret = ""  # never sent back  # nosec B105
        return page(request, "source_form.html", _form_ctx(me, f, name, str(e)), 422)
    return _back(name, "saved")


@router.post("/sources/{name}/delete", response_model=None)
async def delete_feed(request: Request, tasks: BackgroundTasks, name: str) -> Response:
    me = await who(request)
    _need(request, me, "admin")
    try:
        async with _sm(request)() as s, s.begin():
            ids = await catalog.remove(s, name, actor=me.name)
    except catalog.CatalogError as e:
        raise HTTPException(404, str(e)) from None
    tasks.add_task(rescore_ids, _sm(request), _settings(request), ids)
    return _back(None, "removed")


@router.post("/sources/{name}/toggle", response_model=None)
async def toggle(
    request: Request,
    name: str,
    enabled: Annotated[bool, Form()],
    nxt: Annotated[str, Form(alias="next", max_length=20)] = "",
) -> Response:
    me = await who(request)
    _need(request, me, "admin")
    try:
        async with _sm(request)() as s, s.begin():
            await catalog.set_enabled(s, name, enabled, actor=me.name)
    except catalog.CatalogError as e:
        raise HTTPException(404, str(e)) from None
    forget_enabled(request)
    return _back(name if nxt == "source" else None, "on" if enabled else "off")


@router.post("/sources/{name}/pull", response_model=None)
async def pull_now(
    request: Request, name: str, nxt: Annotated[str, Form(alias="next", max_length=20)] = ""
) -> Response:
    me = await who(request)
    _need(request, me, "admin")
    async with _sm(request)() as s:
        src = await s.scalar(select(Source).where(Source.name == name))
        custom = await catalog.custom_names(s)
    if src is None or not catalog.collectable(src, custom):
        raise HTTPException(404, "unknown source")
    if not src.enabled:
        raise HTTPException(409, "switch it on first")
    queued = await queue_runs(request, [name], me.name)
    return _back(name if nxt == "source" else None, "queued" if queued else "busy")


# ── the add / edit form ──────────────────────────────────────────────────────


def _need_admin_page(me: Principal) -> None:
    if not me.can("admin"):
        raise HTTPException(403, "this needs the admin role")


def _every(minutes: int) -> str:
    d = timedelta(minutes=minutes)
    if minutes % 1440 == 0:
        return f"{d.days} day{'s' if d.days != 1 else ''}"
    if minutes % 60 == 0:
        return f"{minutes // 60} h"
    return f"{minutes} min"


def _form_of(src: Source, feed: CustomFeed) -> catalog.FeedForm:
    return catalog.FeedForm(
        title=src.title, url=feed.url, format=feed.format, ioc_type=feed.ioc_type, verdict=feed.verdict,
        confidence=feed.confidence, interval_minutes=src.interval_minutes, tlp=src.tlp_default,
        reliability=src.reliability, comment_char=feed.comment_char, value_column=feed.value_column,
        json_path=feed.json_path or "", auth_header=feed.auth_header or "",
        upstream="" if src.upstream.startswith("custom:") else src.upstream,
    )  # fmt: skip


def _form_ctx(me: Principal, f: catalog.FeedForm, name: str | None, error: str | None) -> dict[str, Any]:
    return {
        "me": me, "f": f, "name": name, "error": error, "types": TYPE_CHOICES, "formats": FORMAT_CHOICES,
        "grades": GRADE_CHOICES, "tlps": TLP_LEVELS, "min_minutes": catalog.MIN_MINUTES,
        "max_minutes": catalog.MAX_MINUTES, "known_formats": FORMATS,
    }  # fmt: skip


def _int(v: Any, default: int) -> int:
    try:
        return int(str(v).strip())
    except ValueError:
        return default


async def _read_form(request: Request) -> catalog.FeedForm:
    """Read the form leniently (a bad number becomes a validation message, not a 422 page)."""
    fd = await request.form()

    def t(k: str, n: int, default: str = "") -> str:
        v = fd.get(k)
        return (v if isinstance(v, str) else default)[:n]

    return catalog.FeedForm(
        title=t("title", 200), url=t("url", 2100), format=t("format", 8, "text"),
        ioc_type=t("ioc_type", 8, "auto"), verdict=t("verdict", 16, "malicious"),
        confidence=_int(t("confidence", 4), -1), interval_minutes=_int(t("interval_minutes", 6), -1),
        tlp=t("tlp", 20, "TLP:CLEAR"), reliability=t("reliability", 1, "C"),
        comment_char=t("comment_char", 8), value_column=_int(t("value_column", 4) or "0", -1),
        json_path=t("json_path", 210), auth_header=t("auth_header", 70), secret=t("secret", 4100),
        clear_secret=t("clear_secret", 5) == "true", upstream=t("upstream", 70),
    )  # fmt: skip
