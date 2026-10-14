"""Argus attack-surface routes: ReconX scans, results and monitors (ADR 0014).

Session cookie only (like the rest of /app/api). Reading needs a sign-in;
starting a passive scan or saving one needs the analyst role; active scans
(they contact the target) and monitors need admin and, for active scans, the
explicit authorization confirmation. State changes need a same-site request
and are audited. Every id and file name is checked before it reaches the
engine, so nothing a browser sends becomes an arbitrary engine path.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Annotated, Any, Literal

from fastapi import APIRouter, BackgroundTasks, HTTPException, Path, Query, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, Field

from threatlens.auth import same_origin as _same_origin
from threatlens.models import AuditLog
from threatlens.recon import (
    JOB_ID,
    MONITOR_ID,
    REPORT_FILE,
    Engine,
    EngineError,
    import_report,
    imported_files,
    ref_path,
    valid_ref,
)
from threatlens.scoring.store import rescore
from threatlens.webapp import _me, _settings, _sm

router = APIRouter(prefix="/app/api/recon", include_in_schema=False)
DOWNLOADS = {
    "json": "application/json",
    "md": "text/markdown; charset=utf-8",
    "csv": "text/csv; charset=utf-8",
    "html": "text/html; charset=utf-8",
    "graphml": "application/graphml+xml",
}
Ref = Annotated[str, Query(max_length=200)]


def _engine(request: Request) -> Engine:
    engine: Engine | None = getattr(request.app.state, "recon", None)
    if engine is None:
        raise HTTPException(503, "the recon engine isn't configured (TL_RECONX_URL)")
    return engine


def _ref(ref: str) -> str:
    if not valid_ref(ref):
        raise HTTPException(400, "not a scan reference")
    return ref


async def _change(request: Request, role: str) -> Any:
    me = await _me(request)
    if not _same_origin(request):
        raise HTTPException(403, "cross-site request refused")
    if not me.can(role):
        raise HTTPException(403, f"this needs the {role} role")
    return me


def _fail(e: EngineError) -> HTTPException:
    status = e.status or 502
    return HTTPException(
        422 if status == 400 else 404 if status == 404 else 409 if status == 409 else 502, str(e)
    )


async def _audit(request: Request, actor: str, action: str, target: str, details: dict[str, Any]) -> None:
    async with _sm(request)() as s, s.begin():
        s.add(AuditLog(actor=actor[:100], action=action, target=target[:500], details=details))


# ── engine ───────────────────────────────────────────────────────────────────


@router.get("/status")
async def status(request: Request) -> dict[str, Any]:
    await _me(request)
    engine: Engine | None = getattr(request.app.state, "recon", None)
    if engine is None:
        return {"configured": False, "reachable": False}
    try:
        await engine.token(refresh=True)
        return {"configured": True, "reachable": True, "browser": False, "nmap": True}
    except EngineError:
        return {"configured": True, "reachable": False}


# ── scans ────────────────────────────────────────────────────────────────────


@router.get("/scans")
async def scans(request: Request) -> list[dict[str, Any]]:
    await _me(request)
    try:
        rows = await _engine(request).get_json("/api/scans")
    except EngineError as e:
        raise _fail(e) from None
    done = await imported_files(_sm(request))
    return [r | {"imported": bool(r.get("file") and r["file"] in done)} for r in rows if isinstance(r, dict)]


class ScanIn(BaseModel):
    target: str = Field(min_length=3, max_length=253)
    mode: Literal["passive", "active", "both"] = "passive"
    authorized: bool = False
    ports: bool = False
    nmap: bool = False
    nmap_profile: Literal["quick", "aggressive", "full"] = "quick"
    nmap_ports: str = Field(default="", max_length=100, pattern=r"^[0-9,\- ]*$")
    archive_raw: bool = False


@router.post("/scans")
async def start_scan(request: Request, body: ScanIn) -> dict[str, Any]:
    active = body.mode != "passive"
    me = await _change(request, "admin" if active else "analyst")
    if active and not body.authorized:
        raise HTTPException(422, "active scans contact the target: confirm you are authorised to test it")
    payload = body.model_dump() | {"browser": False}  # no browser in the engine image
    if not active:
        payload |= {"ports": False, "nmap": False}
    try:
        res = await _engine(request).post_json("/api/newscan", payload)
    except EngineError as e:
        raise _fail(e) from None
    details = {k: payload[k] for k in ("mode", "ports", "nmap", "nmap_profile", "archive_raw")} | {
        "job": res.get("job_id")
    }
    await _audit(request, me.name, "recon.scan", body.target.strip().lower(), details)
    return {"job_id": res.get("job_id")}


@router.get("/jobs/{job_id}")
async def job(request: Request, job_id: Annotated[str, Path(pattern=JOB_ID.pattern)]) -> dict[str, Any]:
    await _me(request)
    try:
        data: dict[str, Any] = await _engine(request).get_json(f"/api/job/{job_id}")
    except EngineError as e:
        raise _fail(e) from None
    return data


@router.get("/jobs/{job_id}/events")
async def job_events(
    request: Request, job_id: Annotated[str, Path(pattern=JOB_ID.pattern)]
) -> StreamingResponse:
    await _me(request)
    return StreamingResponse(
        _engine(request).stream(f"/api/job/{job_id}/events"),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


@router.post("/jobs/{job_id}/save")
async def save(
    request: Request, tasks: BackgroundTasks, job_id: Annotated[str, Path(pattern=JOB_ID.pattern)]
) -> dict[str, Any]:
    """Keep the scan (report files + history) and import its hosts and IPs as assets."""
    me = await _change(request, "analyst")
    engine = _engine(request)
    try:
        saved = await engine.post_json(f"/api/job/{job_id}/save")
        file = str(saved.get("file") or "")
        if not REPORT_FILE.match(file):
            raise EngineError("the engine returned an unexpected file name", 502)
        summary = await import_report(_sm(request), engine, file, me.name)
    except EngineError as e:
        raise _fail(e) from None
    await _audit(request, me.name, "recon.save", file, {"job": job_id, "new_assets": summary.new_assets})
    # Own assets change scores ("own asset" relevance): re-score what they match.
    tasks.add_task(rescore, _sm(request), _settings(request))
    return {"file": file, "import": jsonable_encoder(asdict(summary))}


# ── results ──────────────────────────────────────────────────────────────────


@router.get("/report")
async def report(request: Request, ref: Ref) -> Any:
    await _me(request)
    try:
        return await _engine(request).get_json(ref_path(_ref(ref)))
    except EngineError as e:
        raise _fail(e) from None


@router.get("/report/graph")
async def report_graph(request: Request, ref: Ref, historical: bool = False) -> Any:
    await _me(request)
    params = {"historical": "1"} if historical else {}
    try:
        return await _engine(request).get_json(ref_path(_ref(ref), "graph"), params | {"max": "400"})
    except EngineError as e:
        raise _fail(e) from None


@router.get("/report/geo")
async def report_geo(request: Request, ref: Ref) -> Any:
    await _me(request)
    try:
        return await _engine(request).get_json(ref_path(_ref(ref), "geo"))
    except EngineError as e:
        raise _fail(e) from None


@router.get("/report/download")
async def report_download(
    request: Request, ref: Ref, fmt: Annotated[str, Query(alias="format")] = "json"
) -> Response:
    await _me(request)
    if fmt not in DOWNLOADS:
        raise HTTPException(400, f"format must be one of {', '.join(DOWNLOADS)}")
    r = await _engine(request).get(ref_path(_ref(ref), "download"), {"format": fmt})
    if r.status_code != 200:
        raise HTTPException(404, "report not ready")
    base = ref.removeprefix("job:").removesuffix(".json")
    return Response(
        r.content,
        media_type=DOWNLOADS[fmt],
        headers={
            "Content-Disposition": f'attachment; filename="{base}.{fmt}"',
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.get("/compare")
async def compare(request: Request, a: Ref, b: Ref) -> Any:
    await _me(request)
    try:
        return await _engine(request).get_json("/api/compare", {"a": _ref(a), "b": _ref(b)})
    except EngineError as e:
        raise _fail(e) from None


@router.get("/worldmap")
async def worldmap(request: Request) -> Response:
    await _me(request)
    r = await _engine(request).get("/api/worldmap")
    return Response(r.text, media_type="text/plain", headers={"Cache-Control": "max-age=86400"})


# ── monitors ─────────────────────────────────────────────────────────────────


@router.get("/alerts")
async def alerts(request: Request, target: Annotated[str, Query(max_length=253)] = "") -> Any:
    await _me(request)
    try:
        return await _engine(request).get_json(
            "/api/alerts", {"target": target, "limit": "200"} if target else {"limit": "200"}
        )
    except EngineError as e:
        raise _fail(e) from None


@router.get("/monitors")
async def monitors(request: Request) -> Any:
    await _me(request)
    try:
        return await _engine(request).get_json("/api/monitors")
    except EngineError as e:
        raise _fail(e) from None


class MonitorIn(BaseModel):
    target: str = Field(min_length=3, max_length=253)
    every: str = Field(default="1d", pattern=r"^\d{1,4}[mhd]$")
    webhook: str = Field(default="", max_length=500, pattern=r"^(https://\S+)?$")
    min_severity: Literal["", "info", "low", "medium", "high", "critical"] = ""
    rules: list[str] = Field(default_factory=list, max_length=20)
    archive_raw: bool = False


@router.post("/monitors")
async def add_monitor(request: Request, body: MonitorIn) -> Any:
    me = await _change(request, "admin")
    try:
        out = await _engine(request).post_json("/api/monitors", body.model_dump())
    except EngineError as e:
        raise _fail(e) from None
    await _audit(
        request,
        me.name,
        "recon.monitor.add",
        body.target.lower(),
        {"every": body.every, "webhook": bool(body.webhook)},
    )
    return out


@router.post("/monitors/{monitor_id}/{action}")
async def monitor_action(
    request: Request,
    monitor_id: Annotated[str, Path(pattern=MONITOR_ID.pattern)],
    action: Literal["run", "pause", "resume", "delete", "test"],
) -> Any:
    me = await _change(request, "admin")
    try:
        out = await _engine(request).post_json(f"/api/monitors/{monitor_id}/{action}")
    except EngineError as e:
        raise _fail(e) from None
    await _audit(request, me.name, f"recon.monitor.{action}", monitor_id, {})
    return out
