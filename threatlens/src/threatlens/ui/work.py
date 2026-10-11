"""Analyst workflow pages (Phase 5, ADR 0009): search and saved searches,
bulk lookup with CSV export, cases with evidence and exports, indicator notes.

Same rules as every UI page: a signed session, TLP clearance on every read,
state changes only by POST from this site (``Sec-Fetch-Site``/``Origin``),
analyst role for anything that writes.
"""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime
from typing import Annotated, Any, Literal
from urllib.parse import quote

from fastapi import APIRouter, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import String, cast, func, or_, select

from threatlens import blocking
from threatlens import cases as case_store
from threatlens import tlp as tlp_rules
from threatlens.api import v1 as v1_api
from threatlens.api.enrich import NOT_LOOKUPS
from threatlens.auth import Principal
from threatlens.ioc.extract import extract
from threatlens.ioc.types import Observable
from threatlens.kb import graph
from threatlens.kb.ids import alias_key
from threatlens.models import AuditLog, Case, Entity, EntityAlias, Indicator, Vulnerability
from threatlens.models import Observable as ObsRow
from threatlens.ui import data
from threatlens.ui.routes import BLOCKABLE, _same_origin, _sm, page, who

router = APIRouter(prefix="/ui", include_in_schema=False)
BULK_MAX = 500
MAX_FILES, MAX_FILE_BYTES = 10, 5 * 1024 * 1024
CSV_HEADER = [
    "value_defanged",
    "type",
    "verdict",
    "priority",
    "action",
    "known_sources",
    "indicator_id",
    "top_evidence",
]
TLPS = Literal["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"]


def _owner(me: Principal) -> str:
    return case_store.owner_key(me.kind, me.key_id)


def _writer(request: Request, me: Principal) -> None:
    if not _same_origin(request):
        raise HTTPException(403, "cross-site request refused")
    if not me.can("analyst"):
        raise HTTPException(403, "this needs the analyst role")


def _like(q: str) -> str:
    return "%" + q.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


async def _open_cases(request: Request, me: Principal) -> list[tuple[Case, int]]:
    async with _sm(request)() as s:
        return await case_store.list_cases(s, me.clearance, status="open", limit=50)


# ── search ───────────────────────────────────────────────────────────────────


@router.get("/search", response_model=None)
async def search(
    request: Request,
    q: Annotated[str, Query(max_length=300)] = "",
    show: Annotated[str, Query(max_length=8)] = "",
) -> Response:
    """One box for everything. An exact hit (an indicator value, a CVE id, an
    ATT&CK id or an entity name) opens its page; anything else lists matches
    by value, tag, entity, CVE and case. ``show=all`` always lists."""
    me = await who(request)
    q = q.strip()
    tag = q[4:].strip().lower() if q.lower().startswith("tag:") else None
    async with _sm(request)() as s:
        saved = await case_store.saved_searches(s, _owner(me))
        if q and tag is None and show != "all":
            node = await graph.resolve(s, q, clearance=me.clearance)
            if node is not None:
                if node.kind == "vulnerability":
                    return RedirectResponse(f"/ui/vulnerabilities/{quote(node.label)}", status_code=303)
                if node.kind == "indicator":
                    return RedirectResponse(f"/ui/indicators/{node.extra.get('id')}", status_code=303)
                return RedirectResponse(
                    f"/ui/entities/{quote(node.external_id or node.ref)}", status_code=303
                )
        res: dict[str, Any] = {}
        if q and (tag or len(q) >= 2):
            vis = Indicator.tlp.in_(tlp_rules.readable(me.clearance))
            base = select(Indicator, ObsRow).join(ObsRow, ObsRow.id == Indicator.observable_id).where(vis)
            if tag:
                stmt = base.where(cast(Indicator.labels, String).like(f'%"{tag.replace(chr(34), "")}"%'))
            else:
                stmt = base.where(
                    or_(
                        func.lower(ObsRow.value).like(_like(q), escape="\\"),
                        cast(Indicator.labels, String).like(_like(q), escape="\\"),
                    )
                )
            res["indicators_total"] = await data._count(s, stmt)
            res["indicators"] = (
                await s.execute(stmt.order_by(Indicator.priority_score.desc().nulls_last()).limit(25))
            ).all()
            if not tag:
                key = alias_key(q) or q.lower()
                ent_ids = select(EntityAlias.entity_id).where(
                    EntityAlias.alias_key.like(_like(key), escape="\\")
                )
                res["entities"] = (
                    await s.scalars(
                        select(Entity)
                        .where(
                            Entity.revoked.is_(False),
                            or_(
                                Entity.id.in_(ent_ids),
                                func.lower(Entity.name).like(_like(q), escape="\\"),
                                func.lower(Entity.external_id).like(_like(q), escape="\\"),
                            ),
                        )
                        .order_by(Entity.type, Entity.name)
                        .limit(25)
                    )
                ).all()
                res["cves"] = (
                    await s.scalars(
                        select(Vulnerability)
                        .where(
                            or_(
                                func.lower(Vulnerability.cve_id).like(_like(q), escape="\\"),
                                func.lower(Vulnerability.description).like(_like(q), escape="\\"),
                            )
                        )
                        .order_by(Vulnerability.patch_score.desc().nulls_last())
                        .limit(15)
                    )
                ).all()
                res["cases"] = await case_store.list_cases(s, me.clearance, q=q, limit=10)
    here = "/ui/search" + (f"?q={quote(q)}&show=all" if q else "")
    return page(request, "search.html", {"me": me, "q": q, "tag": tag, "res": res, "saved": saved,
                                         "here": here, "types": data.TYPE_LABELS})  # fmt: skip


@router.post("/searches", response_model=None)
async def save_search(
    request: Request,
    name: Annotated[str, Form(max_length=100)],
    query: Annotated[str, Form(max_length=2000)],
) -> Response:
    me = await who(request)
    if not _same_origin(request):
        raise HTTPException(403, "cross-site request refused")
    try:
        async with _sm(request)() as s, s.begin():
            await case_store.save_search(s, _owner(me), name, query)
    except case_store.CaseError as e:
        raise HTTPException(422, str(e)) from e
    return RedirectResponse("/ui/search#saved", status_code=303)


@router.post("/searches/{search_id}/delete", response_model=None)
async def delete_search(request: Request, search_id: int) -> Response:
    me = await who(request)
    if not _same_origin(request):
        raise HTTPException(403, "cross-site request refused")
    async with _sm(request)() as s, s.begin():
        await case_store.delete_search(s, _owner(me), search_id)
    return RedirectResponse("/ui/search#saved", status_code=303)


# ── bulk lookup ──────────────────────────────────────────────────────────────


def _csv_cell(v: object) -> str:
    """CSV cell safe to open in a spreadsheet (no formula injection)."""
    t = "" if v is None else str(v)
    return "'" + t if t[:1] in ("=", "+", "-", "@", "\t", "\r") else t


@router.get("/lookup", response_class=HTMLResponse)
async def lookup_form(request: Request) -> HTMLResponse:
    me = await who(request)
    return page(request, "lookup.html", {"me": me, "text": "", "results": None, "error": None, "notes": [],
                                         "tlp": "TLP:GREEN", "providers": False, "autoblock": False,
                                         "cases": []})  # fmt: skip


async def gather_text(text: str, files: list[UploadFile] | None) -> tuple[str, list[str]]:
    """The pasted text plus every uploaded file's text; returns (text, notes)."""
    parts, notes = [text], []
    for f in (files or [])[:MAX_FILES]:
        if not f.filename:
            continue
        data = await f.read(MAX_FILE_BYTES + 1)
        if len(data) > MAX_FILE_BYTES:
            notes.append(f"{f.filename}: only the first {MAX_FILE_BYTES // (1024 * 1024)} MB were read")
            data = data[:MAX_FILE_BYTES]
        if b"\x00" in data[:4096]:
            notes.append(f"{f.filename}: skipped, not a text file")
            continue
        parts.append(data.decode("utf-8", errors="replace"))
    if files and len(files) > MAX_FILES:
        notes.append(f"only the first {MAX_FILES} files were read")
    return "\n".join(parts), notes


def observables(text: str) -> list[Observable]:
    return list(
        {o.key: o for o in extract(text) if isinstance(o, Observable) and o.type not in NOT_LOOKUPS}.values()
    )


@router.post("/lookup", response_model=None)
async def lookup(
    request: Request,
    text: Annotated[str, Form(max_length=1_000_000)] = "",
    files: Annotated[list[UploadFile] | None, File()] = None,
    tlp: Annotated[TLPS, Form()] = "TLP:GREEN",
    providers: Annotated[bool, Form()] = False,
    autoblock: Annotated[bool, Form()] = False,
    fmt: Annotated[Literal["html", "csv"], Form(alias="format")] = "html",
) -> Response:
    """Paste anything (an alert, a log excerpt, a list): every IOC in it is
    looked up. By default only what ThreatLens already knows is used (no
    provider is asked, so 500 values cost no quota); ``providers`` also asks
    them, within the bulk budget."""
    me = await who(request)
    _writer(request, me)
    svc = getattr(request.app.state, "enrich", None)
    if svc is None:
        raise HTTPException(503, "lookups are not configured")
    if await request.app.state.limiter.hit(f"bulk:{me.kind}:{me.key_id}", 20):
        raise HTTPException(429, "too many bulk lookups; wait a minute")
    body, notes = await gather_text(text, files)
    obs = observables(body)
    ctx: dict[str, Any] = {"me": me, "text": text, "tlp": tlp, "providers": providers, "results": None,
                           "error": None, "cases": [], "notes": notes, "autoblock": autoblock}  # fmt: skip
    if not obs:
        ctx["error"] = (
            "No indicators found in the text (IPs, domains, URLs, hashes and emails; defanged is fine)."
        )
        return page(request, "lookup.html", ctx, 422)
    if len(obs) > BULK_MAX:
        ctx["error"] = f"Found {len(obs):,} indicators; at most {BULK_MAX} per lookup. Split the list."
        return page(request, "lookup.html", ctx, 422)
    started = datetime.now(UTC)
    results, spent = await svc.lookup_many(
        obs, actor=me.name, tlp=tlp, clearance=me.clearance, providers=providers, concurrency=8
    )
    took = (datetime.now(UTC) - started).total_seconds()
    order = {"malicious": 0, "suspicious": 1, "unknown": 2, "benign": 3}
    results.sort(key=lambda r: (order.get(r["verdict"], 9), -r.get("priority", 0)))
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(CSV_HEADER)
        for r in results:
            known = r.get("known") or {}
            ev = next((e["text"] for e in r["evidence"] if e["kind"] != "info"), "")
            row = (
                r["query"]["defanged"],
                r["query"]["type"],
                r["verdict"],
                r.get("priority"),
                r["recommended_action"],
                ";".join(known.get("sources", [])),
                known.get("indicator_id", ""),
                ev,
            )
            w.writerow([_csv_cell(x) for x in row])
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M")
        return Response(
            buf.getvalue(),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="threatlens-lookup-{stamp}.csv"'},
        )
    counts = {k: sum(1 for r in results if r["verdict"] == k) for k in order}
    blocked: list[str] = []
    refused: list[str] = []
    async with _sm(request)() as s, s.begin():
        if autoblock:
            guard = await blocking.load_guard(s)
            for r in results:
                if r["verdict"] == "malicious" and r["query"]["type"] in BLOCKABLE:
                    try:
                        await blocking.create_block(
                            s, r["query"]["value"], actor=me.name, clearance=me.clearance, origin="lookup",
                            note="auto-blocked from a bulk check", guard=guard,
                        )  # fmt: skip
                        blocked.append(r["query"]["defanged"])
                    except blocking.BlockError as e:
                        refused.append(str(e))
        blocks = await blocking.blocks_for(s, [r["query"]["canonical_key"] for r in results])
    ctx.update(results=results, counts=counts, spent=spent, took=took, cases=await _open_cases(request, me),
               blocks=blocks, blocked=blocked, refused=refused)  # fmt: skip
    return page(request, "lookup.html", ctx)


# ── cases ────────────────────────────────────────────────────────────────────


@router.get("/cases", response_class=HTMLResponse)
async def cases_page(
    request: Request,
    status: Annotated[str, Query(max_length=8)] = "open",
    q: Annotated[str, Query(max_length=200)] = "",
) -> HTMLResponse:
    me = await who(request)
    async with _sm(request)() as s:
        rows = await case_store.list_cases(
            s, me.clearance, status=status if status in ("open", "closed") else None, q=q or None
        )
    return page(request, "cases.html", {"me": me, "rows": rows, "status": status, "q": q})


@router.post("/cases", response_model=None)
async def create_case(
    request: Request,
    title: Annotated[str, Form(max_length=200)],
    severity: Annotated[Literal["low", "medium", "high", "critical"], Form()] = "medium",
    tlp: Annotated[TLPS, Form()] = "TLP:AMBER",
    summary: Annotated[str, Form(max_length=20_000)] = "",
    indicator_id: Annotated[int | None, Form()] = None,
) -> Response:
    me = await who(request)
    _writer(request, me)
    try:
        async with _sm(request)() as s, s.begin():
            c = await case_store.create_case(
                s,
                title=title,
                severity=severity,
                tlp=tlp,
                summary=summary,
                actor=me.name,
                clearance=me.clearance,
            )
            if indicator_id is not None:
                ev = await case_store.indicator_evidence(s, indicator_id, me.clearance)
                if ev is not None:
                    ref, label, snap, item_tlp = ev
                    await case_store.add_item(s, c, kind="indicator", ref=ref, label=label, snapshot=snap,
                                              tlp=item_tlp, actor=me.name)  # fmt: skip
            case_id = c.id
    except case_store.CaseError as e:
        raise HTTPException(422, str(e)) from e
    return RedirectResponse(f"/ui/cases/{case_id}", status_code=303)


async def _case_or_404(request: Request, me: Principal, case_id: int) -> Case:
    async with _sm(request)() as s:
        c = await case_store.get_case(s, case_id, me.clearance)
    if c is None:
        raise HTTPException(404, "no such case")
    return c


@router.get("/cases/{case_id:int}", response_class=HTMLResponse)
async def case_page(request: Request, case_id: int) -> HTMLResponse:
    me = await who(request)
    c = await _case_or_404(request, me, case_id)
    return page(request, "case.html", {"me": me, "c": c, "summary": case_store.item_summary,
                                       "levels": tlp_rules.LEVELS})  # fmt: skip


@router.post("/cases/{case_id:int}", response_model=None)
async def update_case(
    request: Request,
    case_id: int,
    status: Annotated[Literal["open", "closed"] | None, Form()] = None,
    severity: Annotated[Literal["low", "medium", "high", "critical"] | None, Form()] = None,
    summary: Annotated[str | None, Form(max_length=20_000)] = None,
    conclusion: Annotated[str | None, Form(max_length=20_000)] = None,
) -> Response:
    me = await who(request)
    _writer(request, me)
    async with _sm(request)() as s, s.begin():
        c = await case_store.get_case(s, case_id, me.clearance)
        if c is None:
            raise HTTPException(404, "no such case")
        await case_store.update_case(
            s, c, actor=me.name, status=status, severity=severity, summary=summary, conclusion=conclusion
        )
    return RedirectResponse(f"/ui/cases/{case_id}", status_code=303)


@router.post("/cases/{case_id:int}/items", response_model=None)
async def add_case_items(
    request: Request,
    case_id: int,
    kind: Annotated[
        Literal["indicator", "vulnerability", "entity", "observable", "note"], Form()
    ] = "observable",
    ref: Annotated[str, Form(max_length=300)] = "",
    note: Annotated[str, Form(max_length=5000)] = "",
    values: Annotated[list[str] | None, Form(max_length=BULK_MAX)] = None,
    back: Annotated[str, Form(max_length=300)] = "",
) -> Response:
    """Add evidence: one indicator/CVE/entity by ``ref``, a free note, or
    looked-up ``values`` (from bulk lookup), each with what ThreatLens says now."""
    me = await who(request)
    _writer(request, me)
    svc = getattr(request.app.state, "enrich", None)
    try:
        async with _sm(request)() as s, s.begin():
            c = await case_store.get_case(s, case_id, me.clearance)
            if c is None:
                raise HTTPException(404, "no such case")
            if kind == "note":
                await case_store.add_item(
                    s,
                    c,
                    kind="note",
                    ref="",
                    label="note",
                    snapshot={},
                    tlp="TLP:CLEAR",
                    actor=me.name,
                    note=note,
                )
            elif values:
                if svc is None:
                    raise HTTPException(503, "lookups are not configured")
                obs = [o for v in values[:BULK_MAX] for o in extract(v) if isinstance(o, Observable)]
                results, _ = await svc.lookup_many(
                    obs, actor=me.name, clearance=me.clearance, providers=False, concurrency=8
                )
                for r in results:
                    known = r.get("known") or {}
                    if known.get("indicator_id"):
                        ev = await case_store.indicator_evidence(s, known["indicator_id"], me.clearance)
                        if ev is not None:
                            iref, label, snap, tlp = ev
                            await case_store.add_item(
                                s, c, kind="indicator", ref=iref, label=label, snapshot=snap, tlp=tlp,
                                actor=me.name, note=note,
                            )  # fmt: skip
                            continue
                    oref, label, snap, tlp = case_store.lookup_evidence(r)
                    await case_store.add_item(s, c, kind="observable", ref=oref, label=label, snapshot=snap,
                                              tlp=tlp, actor=me.name, note=note)  # fmt: skip
            else:
                found: tuple[str, str, dict[str, Any], str] | None = None
                if kind == "indicator" and ref.isdigit():
                    found = await case_store.indicator_evidence(s, int(ref), me.clearance)
                elif kind == "vulnerability":
                    found = await case_store.vulnerability_evidence(s, ref)
                elif kind == "entity":
                    found = await case_store.entity_evidence(s, ref)
                if found is None:
                    raise HTTPException(404, "nothing to add: unknown or above your clearance")
                iref, label, snap, tlp = found
                await case_store.add_item(s, c, kind=kind, ref=iref, label=label, snapshot=snap, tlp=tlp,
                                          actor=me.name, note=note)  # fmt: skip
    except case_store.CaseError as e:
        raise HTTPException(422, str(e)) from e
    target = back if back.startswith("/ui/") and "//" not in back else f"/ui/cases/{case_id}"
    return RedirectResponse(target, status_code=303)


@router.post("/cases/add", response_model=None)
async def add_to_chosen_case(
    request: Request,
    case: Annotated[int, Form()],
    values: Annotated[list[str] | None, Form(max_length=BULK_MAX)] = None,
    note: Annotated[str, Form(max_length=5000)] = "",
) -> Response:
    """The bulk-lookup form: selected values into the case picked in the form."""
    if not values:
        raise HTTPException(422, "select at least one indicator")
    return await add_case_items(request, case, kind="observable", values=values, note=note, back="")


@router.post("/cases/{case_id:int}/items/{item_id:int}/delete", response_model=None)
async def remove_case_item(request: Request, case_id: int, item_id: int) -> Response:
    me = await who(request)
    _writer(request, me)
    async with _sm(request)() as s, s.begin():
        c = await case_store.get_case(s, case_id, me.clearance)
        if c is None:
            raise HTTPException(404, "no such case")
        await case_store.remove_item(s, c, item_id, actor=me.name)
    return RedirectResponse(f"/ui/cases/{case_id}", status_code=303)


@router.get("/cases/{case_id:int}/export.md", response_model=None)
async def export_case(request: Request, case_id: int) -> Response:
    me = await who(request)
    c = await _case_or_404(request, me, case_id)
    async with _sm(request)() as s, s.begin():
        s.add(
            AuditLog(
                actor=me.name, action="case.export", target=f"case:{c.id}", details={"format": "markdown"}
            )
        )
    body = case_store.to_markdown(c, exported_by=me.name)
    return Response(
        body,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="case-{c.id}.md"'},
    )


@router.get("/cases/{case_id:int}/print", response_class=HTMLResponse)
async def print_case(request: Request, case_id: int) -> HTMLResponse:
    """A clean page for the browser's Print → Save as PDF."""
    me = await who(request)
    c = await _case_or_404(request, me, case_id)
    return page(request, "case_print.html", {"me": me, "c": c, "summary": case_store.item_summary,
                                             "now": datetime.now(UTC)})  # fmt: skip


# ── indicator notes ──────────────────────────────────────────────────────────


@router.post("/indicators/{indicator_id}/notes", response_model=None)
async def add_note(
    request: Request, indicator_id: int, body: Annotated[str, Form(max_length=5000)]
) -> Response:
    me = await who(request)
    _writer(request, me)
    await v1_api.get_indicator(me, request, indicator_id)  # 404 when missing or above clearance
    try:
        async with _sm(request)() as s, s.begin():
            await case_store.add_note(s, indicator_id, author=me.name, body=body)
    except case_store.CaseError as e:
        raise HTTPException(422, str(e)) from e
    return RedirectResponse(f"/ui/indicators/{indicator_id}#notes", status_code=303)
