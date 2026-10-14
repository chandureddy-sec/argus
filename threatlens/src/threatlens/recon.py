"""The ReconX engine as Argus uses it (ADR 0014).

ReconX's web server has no user accounts: a per-process token, readable by
anyone who can reach it, guards its POSTs. So it runs on the compose network
only, and every request reaches it through Argus, after Argus's sign-in, role
checks and audit. This module is the client; ``recon_api`` the routes.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import AsyncIterator
from typing import Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from threatlens import assets
from threatlens.logs import get_logger
from threatlens.models import AppSetting

log = get_logger("threatlens.recon")

JOB_ID = re.compile(r"^[0-9a-f]{12}$")
REPORT_FILE = re.compile(r"^recon_[A-Za-z0-9._-]{1,180}\.json$")
MONITOR_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
IMPORTED_KEY = "recon_imported_files"  # app_settings: report files already imported as assets
MAX_REMEMBERED = 5000


class EngineError(Exception):
    """The engine is unreachable or refused; ``status`` is its HTTP status, if any."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


def valid_ref(ref: str) -> bool:
    """A scan reference: ``job:<id>`` (an unsaved scan) or a saved report file name."""
    job = ref.removeprefix("job:")
    return bool(JOB_ID.match(job)) if ref.startswith("job:") else bool(REPORT_FILE.match(ref))


def ref_path(ref: str, action: str = "") -> str:
    """Engine path for a scan reference (validated by the caller)."""
    if ref.startswith("job:"):
        base = f"/api/job/{ref[4:]}"
        return base + (f"/{action}" if action else "/report")
    return f"/api/scan/{ref}" + (f"/{action}" if action else "")


class Engine:
    def __init__(self, base_url: str, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            transport=transport,
            timeout=httpx.Timeout(30.0, connect=5.0),
            follow_redirects=False,
        )
        self._token: str | None = None

    async def aclose(self) -> None:
        await self.client.aclose()

    async def _send(self, method: str, path: str, **kw: Any) -> httpx.Response:
        try:
            return await self.client.request(method, path, **kw)
        except httpx.HTTPError as e:
            raise EngineError(f"the recon engine isn't reachable ({type(e).__name__})") from e

    async def token(self, refresh: bool = False) -> str:
        if self._token is None or refresh:
            r = await self._send("GET", "/api/config")
            if r.status_code != 200:
                raise EngineError("the recon engine didn't answer", r.status_code)
            self._token = str(r.json().get("token") or "")
        return self._token

    async def get(self, path: str, params: dict[str, str] | None = None) -> httpx.Response:
        return await self._send("GET", path, params=params)

    async def get_json(self, path: str, params: dict[str, str] | None = None) -> Any:
        r = await self.get(path, params)
        if r.status_code != 200:
            raise EngineError(r.text.strip()[:300] or "engine error", r.status_code)
        return r.json()

    async def post_json(self, path: str, body: Any | None = None) -> Any:
        """POST with the engine's token; a restarted engine has a new one, so retry once."""
        for attempt in (0, 1):
            headers = {"X-ReconX-Token": await self.token(refresh=attempt == 1)}
            r = await self._send("POST", path, json=body if body is not None else {}, headers=headers)
            if r.status_code == 403 and "token" in r.text and attempt == 0:
                continue
            if r.status_code not in (200, 202):
                raise EngineError(r.text.strip()[:300] or "engine error", r.status_code)
            return r.json()
        raise EngineError("the recon engine refused the request", 403)

    async def stream(self, path: str) -> AsyncIterator[bytes]:
        """Relay a server-sent event stream, chunk by chunk."""
        try:
            async with self.client.stream("GET", path, timeout=httpx.Timeout(None, connect=5.0)) as r:
                if r.status_code != 200:
                    err = json.dumps(
                        {"step": "error", "message": "scan not found", "percent": 100, "level": "error"}
                    )
                    yield f"data: {err}\n\n".encode()
                    return
                async for chunk in r.aiter_bytes():
                    yield chunk
        except httpx.HTTPError:
            err = json.dumps(
                {"step": "error", "message": "lost the recon engine", "percent": 100, "level": "error"}
            )
            yield f"data: {err}\n\n".encode()


# ── scans → assets ───────────────────────────────────────────────────────────


async def import_report(
    sm: async_sessionmaker[AsyncSession], engine: Engine, file: str, actor: str
) -> assets.ImportSummary:
    """Import one saved report as own assets (idempotent: same file, same import)."""
    r = await engine.get(f"/api/scan/{file}")
    if r.status_code != 200:
        raise EngineError("report not found", r.status_code)
    body = r.content
    summary = await assets.import_reconx(sm, json.loads(body), hashlib.sha256(body).hexdigest(), actor)
    await _remember(sm, [file])
    return summary


async def _imported(s: AsyncSession) -> list[str]:
    row = await s.get(AppSetting, IMPORTED_KEY)
    return list((row.value or {}).get("files", [])) if row else []


async def _remember(sm: async_sessionmaker[AsyncSession], files: list[str]) -> None:
    async with sm() as s, s.begin():
        row = await s.get(AppSetting, IMPORTED_KEY)
        known = list((row.value or {}).get("files", [])) if row else []
        merged = list(dict.fromkeys([*known, *files]))[-MAX_REMEMBERED:]
        if row is None:
            s.add(AppSetting(key=IMPORTED_KEY, value={"files": merged}, updated_by="recon"))
        else:
            row.value = {"files": merged}


async def import_new_reports(sm: async_sessionmaker[AsyncSession], engine: Engine) -> dict[str, int]:
    """Import every saved report not imported yet: scheduled monitor runs save
    theirs without anyone pressing Save. Run by the worker."""
    scans = await engine.get_json("/api/scans")
    async with sm() as s:
        done = set(await _imported(s))
    files = [
        str(x["file"])
        for x in scans
        if isinstance(x, dict) and x.get("file") and REPORT_FILE.match(str(x["file"]))
    ]
    out = {"seen": len(files), "imported": 0, "failed": 0}
    for f in files:
        if f in done:
            continue
        try:
            await import_report(sm, engine, f, actor="recon-monitor")
            out["imported"] += 1
        except (EngineError, ValueError, KeyError) as e:
            out["failed"] += 1
            log.warning("recon.import_failed", file=f, error=str(e)[:200])
    return out


async def imported_files(sm: async_sessionmaker[AsyncSession]) -> set[str]:
    async with sm() as s:
        return set(await _imported(s))
