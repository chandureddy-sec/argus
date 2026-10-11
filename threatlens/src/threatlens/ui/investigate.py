"""Verify an indicator and Bulk check, live (step 2 of the response work).

* ``/ui/verify``: one value, full analysis. Without JavaScript the page waits
  for every provider and renders the result; with it, the page streams:
  local knowledge first, then each provider's card as it answers, then the
  verdict and the actions.
* ``/ui/verify/stream`` and ``/ui/lookup/stream``: newline-delimited JSON.
  Each line carries ``ops`` (replace or append a piece of server-rendered
  HTML by element id) and, for bulk, ``progress``. The browser script only
  places HTML; every piece is rendered here from the same templates as the
  no-JavaScript pages, so both paths show the same thing.
* ``/ui/verify/flag``: Flag malicious / Not malicious for one or many values.
* Blocking reuses ``/ui/blocklist``; Bulk check can also block malicious
  results as they arrive (``autoblock``, monitor mode, audited like any block).

Same rules as every UI page: signed session, TLP clearance on every read,
POST only from this site, analyst role to write. Lookups are rate-limited per
account. A stream whose reader goes away cancels the providers still running.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Annotated, Any, Literal
from urllib.parse import urlencode

from fastapi import APIRouter, BackgroundTasks, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from markupsafe import Markup

from threatlens import blocking, verify
from threatlens.api.enrich import NOT_LOOKUPS
from threatlens.auth import Principal
from threatlens.enrich.service import Budget, EnrichmentService
from threatlens.ioc.defang import defang
from threatlens.ioc.extract import defang_text
from threatlens.ioc.types import Observable
from threatlens.logs import get_logger
from threatlens.scoring.feedback import rescore_sources
from threatlens.ui.routes import BLOCKABLE, _same_origin, _settings, _sm, page, templates, who
from threatlens.ui.work import BULK_MAX, TLPS, _open_cases, gather_text, observables

router = APIRouter(prefix="/ui", include_in_schema=False)
log = get_logger("threatlens.ui")
templates.env.globals.update(headline=verify.headline, fields=verify.fields, titles=verify.CARD_TITLE)
VERIFY_PER_MINUTE = 60
BULK_PER_MINUTE = 20
BULK_CONCURRENCY = 8
ORDER = {"malicious": 0, "suspicious": 1, "unknown": 2, "benign": 3}


def _svc(request: Request) -> EnrichmentService:
    svc = getattr(request.app.state, "enrich", None)
    if svc is None:
        raise HTTPException(503, "lookups are not configured")
    return svc  # type: ignore[no-any-return]


def _macros() -> Any:
    return templates.env.get_template("_verify.html").module


def _writer(request: Request, me: Principal) -> None:
    if not _same_origin(request):
        raise HTTPException(403, "cross-site request refused")
    if not me.can("analyst"):
        raise HTTPException(403, "this needs the analyst role")


def _wants_json(request: Request) -> bool:
    return "application/json" in request.headers.get("accept", "")


def _local_next(nxt: str) -> str | None:
    return nxt if nxt.startswith("/ui") and not nxt.startswith("//") and "\\" not in nxt else None


def _verify_url(q: str, tlp: str, providers: bool, **extra: Any) -> str:
    return "/ui/verify?" + urlencode(
        {"q": q, "tlp": tlp, "providers": "true" if providers else "false", **extra}
    )


async def _parse(q: str) -> Observable:
    obs = verify.parse(q)
    if obs.type in NOT_LOOKUPS:
        raise verify.FlagError(f"a {obs.type.value} can't be looked up")
    return obs


async def _limit(request: Request, me: Principal, bucket: str, n: int) -> None:
    if await request.app.state.limiter.hit(f"{bucket}:{me.kind}:{me.key_id}", n):
        raise HTTPException(429, "too many lookups; wait a minute")


# ── verify one value ─────────────────────────────────────────────────────────


@router.get("/verify", response_class=HTMLResponse)
async def verify_page(
    request: Request,
    q: Annotated[str, Query(max_length=2000)] = "",
    tlp: TLPS = "TLP:GREEN",
    providers: bool = True,
    live: bool = False,
) -> HTMLResponse:
    """The whole analysis of one value. ``live`` pages render empty and fill
    from the stream (the browser script adds it); without it the server waits
    for every provider."""
    me = await who(request)
    ctx: dict[str, Any] = {"me": me, "q": q, "tlp": tlp, "providers": providers, "error": None,
                           "live": False, "stream": None, "full": None, "body": None}  # fmt: skip
    if not q.strip():
        return page(request, "verify.html", ctx)
    try:
        obs = await _parse(q)
    except verify.FlagError as e:
        ctx["error"] = str(e)
        return page(request, "verify.html", ctx, 422)
    shown = defang(obs.value, obs.type)  # URLs we put in the page carry the defanged value
    ctx["full"] = _verify_url(shown, tlp, providers)
    if live:
        ctx["live"] = True
        ctx["stream"] = "/ui/verify/stream?" + urlencode(
            {"q": shown, "tlp": tlp, "providers": "true" if providers else "false"}
        )
        return page(request, "verify.html", ctx)
    await _limit(request, me, "verify", VERIFY_PER_MINUTE)
    r = await _svc(request).lookup(obs, actor=me.name, tlp=tlp, clearance=me.clearance, providers=providers)
    ctx["body"] = await _body(request, me, r, back=ctx["full"])
    return page(request, "verify.html", ctx)


async def _body(request: Request, me: Principal, r: dict[str, Any], *, back: str) -> Markup:
    async with _sm(request)() as s:
        block = await blocking.live_block(s, r["query"]["canonical_key"])
    q = r["query"]
    links = verify.second_opinion(q["type"], q["value"], r["tlp"])
    html: Markup = _macros().body(
        q, r, [], me, r=r, block=block, links=links, back=back, blockable=q["type"] in BLOCKABLE
    )
    return html


def _line(ops: list[dict[str, Any]], **extra: Any) -> bytes:
    return (json.dumps({"ops": ops, **extra}, default=str) + "\n").encode()


@router.get("/verify/stream")
async def verify_stream(
    request: Request,
    q: Annotated[str, Query(max_length=2000)],
    tlp: TLPS = "TLP:GREEN",
    providers: bool = True,
) -> Response:
    me = await who(request)
    try:
        obs = await _parse(q)
    except verify.FlagError as e:
        raise HTTPException(422, str(e)) from None
    await _limit(request, me, "verify", VERIFY_PER_MINUTE)
    svc = _svc(request)
    m = _macros()
    back = _verify_url(defang(obs.value, obs.type), tlp, providers)

    async def gen() -> AsyncIterator[bytes]:
        try:
            async for kind, data in svc.lookup_stream(
                obs, actor=me.name, tlp=tlp, clearance=me.clearance, providers=providers
            ):
                if kind == "start":
                    html = m.body(data["query"], data, data["pending"], me)
                    yield _line([{"op": "replace", "id": "verify-body", "html": str(html)}])
                elif kind == "enricher":
                    yield _line(
                        [{"op": "replace", "id": f"vc-{data['enricher']}", "html": str(m.card(data))}]
                    )
                else:
                    async with _sm(request)() as s:
                        block = await blocking.live_block(s, data["query"]["canonical_key"])
                    qq = data["query"]
                    links = verify.second_opinion(qq["type"], qq["value"], data["tlp"])
                    ops = [
                        {"op": "replace", "id": "v-head", "html": str(m.head(qq, data))},
                        {"op": "replace", "id": "vc-local", "html": str(m.card_local(data))},
                        {"op": "replace", "id": "vc-links", "html": str(m.links_card(links))},
                        {"op": "replace", "id": "vc-actions",
                         "html": str(m.actions(qq, data, me, block, back, qq["type"] in BLOCKABLE))},
                    ]  # fmt: skip
                    yield _line(ops, done=True)
        except Exception as e:  # the page must learn the stream failed, not hang on "checking"
            log.exception("ui.verify_stream_failed", error=str(e))
            yield _line([], error="The lookup failed; reload to try again.")

    return StreamingResponse(gen(), media_type="application/x-ndjson", headers=_STREAM_HEADERS)


_STREAM_HEADERS = {"Cache-Control": "no-store", "X-Accel-Buffering": "no"}


# ── flag malicious / not malicious ───────────────────────────────────────────


@router.post("/verify/flag", response_model=None)
async def verify_flag(
    request: Request,
    tasks: BackgroundTasks,
    verdict: Annotated[Literal["tp", "fp"], Form()],
    values: Annotated[list[str] | None, Form(max_length=BULK_MAX)] = None,
    tlp: Annotated[TLPS, Form()] = "TLP:GREEN",
    note: Annotated[str, Form(max_length=500)] = "",
    nxt: Annotated[str, Form(alias="next", max_length=2000)] = "",
) -> Response:
    me = await who(request)
    _writer(request, me)
    done: list[dict[str, Any]] = []
    refused: list[dict[str, str]] = []
    weights: set[str] = set()
    for raw in dict.fromkeys(v.strip() for v in (values or []) if v.strip()):
        try:
            why = note or ("flagged malicious" if verdict == "tp" else "marked not malicious")
            f = await verify.flag(
                _sm(request),
                _settings(request),
                raw,
                verdict,
                actor=me.name,
                clearance=me.clearance,
                tlp=tlp,
                note=why,
            )
        except verify.FlagError as e:
            refused.append({"value": raw, "why": defang_text(str(e))})
            continue
        done.append({"input": raw, "value": f.value, "indicator_id": f.indicator_id, "created": f.created})
        weights |= {c.source for c in f.changes}
    if weights:
        tasks.add_task(rescore_sources, _sm(request), _settings(request), sorted(weights))
    if _wants_json(request):
        return JSONResponse({"verdict": verdict, "done": done, "refused": refused})
    if (target := _local_next(nxt)) and done and not refused:
        return RedirectResponse(target, status_code=303)
    ctx = {
        "me": me,
        "verdict": verdict,
        "done": done,
        "refused": refused,
        "back": _local_next(nxt) or "/ui/lookup",
    }
    return page(request, "flagged.html", ctx, 200 if done else 422)


# ── bulk check, live ─────────────────────────────────────────────────────────


@router.post("/lookup/stream")
async def bulk_stream(
    request: Request,
    text: Annotated[str, Form(max_length=1_000_000)] = "",
    files: Annotated[list[UploadFile] | None, File()] = None,
    tlp: Annotated[TLPS, Form()] = "TLP:GREEN",
    providers: Annotated[bool, Form()] = False,
    autoblock: Annotated[bool, Form()] = False,
) -> Response:
    me = await who(request)
    _writer(request, me)
    await _limit(request, me, "bulk", BULK_PER_MINUTE)
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
    m = _macros()
    cases = await _open_cases(request, me)
    total = len(obs)

    async def gen() -> AsyncIterator[bytes]:
        counts = dict.fromkeys(ORDER, 0)
        budget = Budget(svc.settings.enrich_budget)
        start = budget.left
        sem = asyncio.Semaphore(BULK_CONCURRENCY)
        blocked: list[str] = []
        refused: list[str] = []

        async def one(o: Observable) -> dict[str, Any]:
            async with sem:
                return await svc.lookup(
                    o, actor=me.name, tlp=tlp, budget=budget, clearance=me.clearance, providers=providers
                )

        head: Any = templates.env.get_template("_bulk.html").module
        opened = head.results(total, counts, cases, me, notes, autoblock, tlp=tlp)
        yield _line([{"op": "replace", "id": "bulk-results", "html": str(opened)}], progress=[0, total])
        tasks = [asyncio.ensure_future(one(o)) for o in obs]
        done = 0
        try:
            for fut in asyncio.as_completed(tasks):
                try:
                    r = await fut
                except Exception as e:  # one bad value must not end the whole check
                    log.warning("ui.bulk_item_failed", error=str(e))
                    done += 1
                    yield _line([], progress=[done, total])
                    continue
                done += 1
                counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
                block = None
                async with _sm(request)() as s, s.begin():
                    if autoblock and r["verdict"] == "malicious" and r["query"]["type"] in BLOCKABLE:
                        try:
                            block = await blocking.create_block(
                                s, r["query"]["value"], actor=me.name, clearance=me.clearance,
                                origin="lookup", note="auto-blocked from a bulk check",
                            )  # fmt: skip
                            blocked.append(r["query"]["defanged"])
                        except blocking.BlockError as e:
                            refused.append(str(e))
                    if block is None:
                        block = await blocking.live_block(s, r["query"]["canonical_key"])
                yield _line(
                    [{"op": "append", "id": "bulk-rows", "html": str(m.bulk_row(r, block, me))},
                     {"op": "replace", "id": "bulk-counts", "html": str(head.counts(counts, total))}],
                    progress=[done, total],
                )  # fmt: skip
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
        yield _line(
            [{"op": "replace", "id": "bulk-summary",
              "html": str(head.summary(total, counts, start - budget.left, providers, blocked, refused))}],
            progress=[total, total], done=True,
        )  # fmt: skip

    return StreamingResponse(gen(), media_type="application/x-ndjson", headers=_STREAM_HEADERS)
