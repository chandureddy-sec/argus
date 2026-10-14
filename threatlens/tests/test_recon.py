"""Argus attack-surface routes in front of the ReconX engine (ADR 0014):
roles, same-site checks, audit, strict ids, streaming, save-and-import, and
the worker's import of monitor runs. The engine is a fake on a mock transport."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.test_assets import SCAN
from tests.test_enrich import seeded  # noqa: F401  # fixture
from threatlens import recon
from threatlens.api.app import create_app
from threatlens.auth import MemoryRateLimiter
from threatlens.models import Asset, AuditLog
from threatlens.settings import Settings
from threatlens.users import create_user

SM = async_sessionmaker[AsyncSession]
SAME = {"Sec-Fetch-Site": "same-origin"}
JOB = "abcdef012345"
FILE = "recon_example.com_20261014_120000.json"


class FakeEngine:
    """Just enough of ReconX's web API, with a token that can rotate."""

    def __init__(self) -> None:
        self.token = "t1"  # noqa: S105  # a fake engine token
        self.calls: list[tuple[str, str]] = []
        self.started: list[dict[str, Any]] = []
        self.saved = False
        self.report = SCAN.read_bytes()

    def handle(self, req: httpx.Request) -> httpx.Response:
        path, method = req.url.path, req.method
        self.calls.append((method, path))
        if method == "POST" and req.headers.get("x-reconx-token") != self.token:
            return httpx.Response(403, text="invalid session token — reload the page")
        match method, path:
            case "GET", "/api/config":
                return httpx.Response(200, json={"token": self.token})
            case "POST", "/api/newscan":
                self.started.append(json.loads(req.content))
                return httpx.Response(200, json={"job_id": JOB})
            case "GET", "/api/scans":
                rows = [
                    {
                        "job_id": JOB,
                        "target": "example.com",
                        "timestamp": "2026-10-14T12:00:00Z",
                        "mode": "passive",
                    }
                ]
                if self.saved:
                    rows = [
                        {
                            "file": FILE,
                            "target": "example.com",
                            "timestamp": "2026-10-14T12:00:00Z",
                            "mode": "passive",
                        }
                    ]
                return httpx.Response(200, json=rows)
            case "GET", "/api/job/abcdef012345":
                return httpx.Response(200, json={"id": JOB, "status": "done", "events": []})
            case "GET", "/api/job/abcdef012345/events":
                body = 'data: {"step":"dns","message":"Resolving","percent":20,"level":"info"}\n\n'
                body += 'data: {"step":"done","message":"Scan complete","percent":100,"level":"done"}\n\n'
                return httpx.Response(200, text=body, headers={"content-type": "text/event-stream"})
            case "GET", "/api/job/abcdef012345/report":
                return httpx.Response(200, content=self.report, headers={"content-type": "application/json"})
            case "POST", "/api/job/abcdef012345/save":
                self.saved = True
                return httpx.Response(200, json={"file": FILE})
            case "GET", "/api/scan/recon_example.com_20261014_120000.json":
                return httpx.Response(200, content=self.report, headers={"content-type": "application/json"})
            case "GET", "/api/scan/recon_example.com_20261014_120000.json/download":
                return httpx.Response(
                    200, text="# report", headers={"content-disposition": 'attachment; filename="x"'}
                )
            case "GET", "/api/compare":
                return httpx.Response(
                    200, json={"a": req.url.params["a"], "b": req.url.params["b"], "added": []}
                )
            case "GET", "/api/monitors":
                return httpx.Response(200, json={"monitors": [], "rules": [], "scheduler": True})
            case "POST", "/api/monitors":
                return httpx.Response(
                    200, json={"monitors": [json.loads(req.content)], "rules": [], "scheduler": True}
                )
            case "POST", "/api/monitors/m1/run":
                return httpx.Response(202, json={"status": "started"})
        return httpx.Response(404, text="404 page not found")


class Recon:
    def __init__(self, c: httpx.AsyncClient, sm: SM, fake: FakeEngine, engine: recon.Engine) -> None:
        self.c, self.sm, self.fake, self.engine = c, sm, fake, engine

    async def login(self, user: str) -> None:
        await self.c.post("/ui/logout", headers=SAME)
        creds = {"username": user, "password": user + "-password"}
        assert (await self.c.post("/ui/login", data=creds, headers=SAME)).status_code == 303


@pytest.fixture
async def rx(seeded: SM) -> AsyncIterator[Recon]:  # noqa: F811
    async with seeded() as s, s.begin():
        for name, role in (("ada", "admin"), ("anna", "analyst"), ("vera", "viewer")):
            await create_user(s, name, name + "-password", role)
    fake = FakeEngine()
    engine = recon.Engine("http://reconx:8787", transport=httpx.MockTransport(fake.handle))
    settings = Settings(rate_limit_analyst=1000, rate_limit_viewer=1000, rate_limit_admin=1000)
    a = create_app(settings, checks={}, sessionmaker=seeded, limiter=MemoryRateLimiter(), recon=engine)
    async with (
        a.router.lifespan_context(a),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=a), base_url="http://test") as c,
    ):
        yield Recon(c, seeded, fake, engine)
    await engine.aclose()


async def audit(sm: SM, action: str) -> list[AuditLog]:
    async with sm() as s:
        return list((await s.scalars(select(AuditLog).where(AuditLog.action == action))).all())


async def test_roles_decide_who_scans_what(rx: Recon) -> None:
    assert (await rx.c.get("/app/api/recon/scans")).status_code == 401
    await rx.login("vera")
    assert (await rx.c.get("/app/api/recon/scans")).status_code == 200
    r = await rx.c.post("/app/api/recon/scans", json={"target": "example.com"}, headers=SAME)
    assert r.status_code == 403  # viewers read only

    await rx.login("anna")
    r = await rx.c.post("/app/api/recon/scans", json={"target": "example.com", "nmap": True}, headers=SAME)
    assert r.json() == {"job_id": JOB}
    sent = rx.fake.started[-1]
    assert sent["browser"] is False  # no browser in the engine image
    assert sent["nmap"] is False  # passive scans never run nmap
    assert "nmap_args" not in sent  # raw flags never pass through
    rows = await audit(rx.sm, "recon.scan")
    assert rows[-1].actor == "anna"
    assert rows[-1].target == "example.com"
    active = {"target": "example.com", "mode": "both", "nmap": True, "authorized": True}
    assert (await rx.c.post("/app/api/recon/scans", json=active, headers=SAME)).status_code == 403  # analyst

    await rx.login("ada")
    r = await rx.c.post("/app/api/recon/scans", json=active | {"authorized": False}, headers=SAME)
    assert r.status_code == 422
    assert "authorised" in r.json()["detail"]
    assert (await rx.c.post("/app/api/recon/scans", json=active, headers=SAME)).status_code == 200
    assert rx.fake.started[-1]["nmap"] is True
    cross = await rx.c.post("/app/api/recon/scans", json=active, headers={"Sec-Fetch-Site": "cross-site"})
    assert cross.status_code == 403
    bad = await rx.c.post("/app/api/recon/scans", json=active | {"nmap_ports": "80;rm -rf"}, headers=SAME)
    assert bad.status_code == 422


async def test_ids_and_refs_never_become_arbitrary_engine_paths(rx: Recon) -> None:
    await rx.login("vera")
    for ref in ("../../etc/passwd", "recon_../x.json", "job:../x", "job:ABCDEF012345", "notes.txt"):
        assert (await rx.c.get("/app/api/recon/report", params={"ref": ref})).status_code == 400, ref
    assert (await rx.c.get("/app/api/recon/jobs/..%2Fconfig")).status_code in (404, 422)
    assert (
        await rx.c.get("/app/api/recon/report/download", params={"ref": FILE, "format": "exe"})
    ).status_code == 400
    touched = {p for _, p in rx.fake.calls}
    assert not any(".." in p for p in touched)


async def test_live_progress_is_relayed(rx: Recon) -> None:
    await rx.login("vera")
    r = await rx.c.get(f"/app/api/recon/jobs/{JOB}/events")
    assert r.headers["content-type"].startswith("text/event-stream")
    events = [json.loads(line[6:]) for line in r.text.splitlines() if line.startswith("data: ")]
    assert [e["step"] for e in events] == ["dns", "done"]
    assert (await rx.c.get(f"/app/api/recon/jobs/{JOB}")).json()["status"] == "done"


async def test_saving_a_scan_imports_its_assets(rx: Recon) -> None:
    await rx.login("vera")
    assert (await rx.c.post(f"/app/api/recon/jobs/{JOB}/save", headers=SAME)).status_code == 403
    await rx.login("anna")
    r = await rx.c.post(f"/app/api/recon/jobs/{JOB}/save", headers=SAME)
    assert r.status_code == 200
    body = r.json()
    assert body["file"] == FILE
    assert body["import"]["target"] == "example.com"
    assert body["import"]["new_assets"] > 0
    async with rx.sm() as s:
        assert (await s.scalar(select(func.count()).select_from(Asset))) == body["import"]["new_assets"]
    scans = (await rx.c.get("/app/api/recon/scans")).json()
    assert scans[0]["imported"] is True
    assert (await audit(rx.sm, "recon.save"))[-1].target == FILE
    dl = await rx.c.get("/app/api/recon/report/download", params={"ref": FILE, "format": "md"})
    assert dl.headers["content-disposition"] == f'attachment; filename="{FILE.removesuffix(".json")}.md"'
    cmp = (await rx.c.get("/app/api/recon/compare", params={"a": FILE, "b": f"job:{JOB}"})).json()
    assert cmp["b"] == f"job:{JOB}"


async def test_a_restarted_engine_gets_a_new_token(rx: Recon) -> None:
    await rx.login("anna")
    assert (
        await rx.c.post("/app/api/recon/scans", json={"target": "example.com"}, headers=SAME)
    ).status_code == 200
    rx.fake.token = "t2"  # noqa: S105  # the engine restarted
    assert (
        await rx.c.post("/app/api/recon/scans", json={"target": "example.com"}, headers=SAME)
    ).status_code == 200


async def test_monitors_need_admin(rx: Recon) -> None:
    await rx.login("anna")
    assert (await rx.c.get("/app/api/recon/monitors")).json()["scheduler"] is True
    mon = {"target": "example.com", "every": "1d"}
    assert (await rx.c.post("/app/api/recon/monitors", json=mon, headers=SAME)).status_code == 403
    await rx.login("ada")
    assert (
        await rx.c.post("/app/api/recon/monitors", json=mon | {"webhook": "http://x"}, headers=SAME)
    ).status_code == 422
    assert (await rx.c.post("/app/api/recon/monitors", json=mon, headers=SAME)).status_code == 200
    assert (await rx.c.post("/app/api/recon/monitors/m1/run", headers=SAME)).json() == {"status": "started"}
    assert (await rx.c.post("/app/api/recon/monitors/m1/explode", headers=SAME)).status_code == 422


async def test_the_worker_imports_monitor_runs_once(rx: Recon) -> None:
    rx.fake.saved = True  # a monitor run saved a report on its own
    first = await recon.import_new_reports(rx.sm, rx.engine)
    assert first == {"seen": 1, "imported": 1, "failed": 0}
    again = await recon.import_new_reports(rx.sm, rx.engine)
    assert again == {"seen": 1, "imported": 0, "failed": 0}


async def test_without_an_engine_the_routes_say_so(seeded: SM) -> None:  # noqa: F811
    async with seeded() as s, s.begin():
        await create_user(s, "vera", "vera-password", "viewer")
    a = create_app(Settings(), checks={}, sessionmaker=seeded, limiter=MemoryRateLimiter())
    async with (
        a.router.lifespan_context(a),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=a), base_url="http://test") as c,
    ):
        creds = {"username": "vera", "password": "vera-password"}
        await c.post("/ui/login", data=creds, headers=SAME)
        assert (await c.get("/app/api/recon/status")).json() == {"configured": False, "reachable": False}
        assert (await c.get("/app/api/recon/scans")).status_code == 503
