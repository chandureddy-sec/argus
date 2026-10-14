"""Argus (the unified front end) as the API serves it: the app behind the
session, its static files, and the JSON it reads, within TLP clearance."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.test_enrich import seeded  # noqa: F401  # fixture
from threatlens.api.app import create_app
from threatlens.auth import MemoryRateLimiter
from threatlens.models import Indicator
from threatlens.models import Observable as ObsRow
from threatlens.settings import Settings
from threatlens.users import create_user

SM = async_sessionmaker[AsyncSession]
SAME = {"Sec-Fetch-Site": "same-origin"}


class Web:
    def __init__(self, c: httpx.AsyncClient, sm: SM) -> None:
        self.c, self.sm = c, sm

    async def login(self, user: str) -> None:
        await self.c.post("/ui/logout", headers=SAME)
        r = await self.c.post(
            "/ui/login", data={"username": user, "password": user + "-password"}, headers=SAME
        )
        assert r.status_code == 303


@pytest.fixture
def dist(tmp_path: Path) -> Path:
    d = tmp_path / "dist"
    (d / "assets").mkdir(parents=True)
    (d / "fonts").mkdir()
    (d / "index.html").write_text(
        '<!doctype html><div id="root"></div><script src="/app/assets/app.js"></script>'
    )
    (d / "assets" / "app.js").write_text("console.log('argus')")
    (d / "fonts" / "inter.woff2").write_bytes(b"wOF2")
    (tmp_path / "secret.txt").write_text("not served")
    return d


@pytest.fixture
async def web(seeded: SM, dist: Path) -> AsyncIterator[Web]:  # noqa: F811
    async with seeded() as s, s.begin():
        await create_user(s, "chandu reddy", "chandu reddy-password", "admin")
        await create_user(s, "gina", "gina-password", "analyst", clearance="TLP:GREEN")
    settings = Settings(web_dist=dist, rate_limit_analyst=1000, rate_limit_viewer=1000)
    a = create_app(settings, checks={}, sessionmaker=seeded, limiter=MemoryRateLimiter())
    async with (
        a.router.lifespan_context(a),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=a), base_url="http://test") as c,
    ):
        yield Web(c, seeded)


async def test_the_app_needs_a_session_but_its_files_do_not(web: Web) -> None:
    r = await web.c.get("/app/")
    assert r.status_code == 303
    assert r.headers["location"] == "/ui/login?next=/app/"
    js = await web.c.get("/app/assets/app.js")
    assert js.status_code == 200
    assert "immutable" in js.headers["cache-control"]
    assert (await web.c.get("/app/fonts/inter.woff2")).content == b"wOF2"
    assert (await web.c.get("/app/assets/missing.js")).status_code == 404
    assert (await web.c.get("/app/..%2Fsecret.txt")).status_code in (303, 404)
    assert "not served" not in (await web.c.get("/app/%2E%2E/secret.txt")).text
    assert (await web.c.get("/app")).headers["location"] == "/app/"
    assert (await web.c.get("/")).headers["location"] == "/app/"

    r = await web.c.post(
        "/ui/login",
        data={"username": "chandu reddy", "password": "chandu reddy-password", "next": "/app/"},
        headers=SAME,
    )
    assert r.headers["location"] == "/app/"  # sign-in comes back to Argus
    page = await web.c.get("/app/")
    assert page.status_code == 200
    assert 'id="root"' in page.text
    assert "script-src 'self'" in page.headers["content-security-policy"]
    assert page.headers["cache-control"] == "no-store"
    deep = await web.c.get("/app/scans/42")  # app routes all serve the page
    assert deep.status_code == 200
    assert 'id="root"' in deep.text


async def test_an_unbuilt_app_says_how_to_build_it(seeded: SM, tmp_path: Path) -> None:  # noqa: F811
    a = create_app(Settings(web_dist=tmp_path / "nope"), checks={}, sessionmaker=seeded)
    async with (
        a.router.lifespan_context(a),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=a), base_url="http://test") as c,
    ):
        r = await c.get("/app/")
    assert r.status_code == 503
    assert "npm run build" in r.text


async def test_the_api_answers_only_a_signed_in_session(web: Web) -> None:
    for path in ("me", "kpis", "activity", "types", "collection", "indicators"):
        assert (await web.c.get(f"/app/api/{path}")).status_code == 401, path
    assert (await web.c.get("/app/api/nope")).status_code in (401, 404)
    await web.login("chandu reddy")
    me = (await web.c.get("/app/api/me")).json()
    assert me == {"name": "Chandu Reddy", "role": "admin", "clearance": "TLP:RED", "initials": "CR"}
    assert (await web.c.get("/app/api/nope")).status_code == 404


async def test_dashboard_figures_come_from_the_store(web: Web) -> None:
    await web.login("chandu reddy")
    kpis = {k["key"]: k for k in (await web.c.get("/app/api/kpis")).json()}
    async with web.sm() as s:
        active = len((await s.scalars(select(Indicator).where(Indicator.status == "active"))).all())
    assert kpis["active"]["value"] == active
    assert kpis["assets"]["value"] == 0
    assert kpis["assets"]["hint"] == "run or import a ReconX scan"
    assert kpis["feeds"]["of"] >= 1

    for rng, n in (("Year", 12), ("Month", 30), ("Week", 7), ("Day", 24)):
        a = (await web.c.get("/app/api/activity", params={"range": rng})).json()
        assert len(a["points"]) == n, rng
        assert a["range"] == rng
    year = (await web.c.get("/app/api/activity", params={"range": "Year"})).json()
    assert year["total"] >= sum(p["malicious"] + p["suspicious"] for p in year["points"])
    assert (await web.c.get("/app/api/activity", params={"range": "Decade"})).json()["range"] == "Year"

    types = (await web.c.get("/app/api/types", params={"scope": "All"})).json()
    assert types["total"] == sum(i["value"] for i in types["items"])
    assert {i["name"] for i in types["items"]} >= {"IP addresses"}

    col = (await web.c.get("/app/api/collection")).json()
    assert [d["day"] for d in col["days"]] == ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


async def test_indicators_are_filtered_paged_and_defanged(web: Web) -> None:
    await web.login("chandu reddy")
    page = (await web.c.get("/app/api/indicators", params={"size": 2})).json()
    assert len(page["items"]) <= 2
    assert page["total"] >= 2
    first = page["items"][0]
    assert {"id", "value", "type", "sources", "status", "score", "tlp", "country"} <= set(first)
    one = (await web.c.get("/app/api/indicators", params={"q": "162.243.103[.]246"})).json()
    assert one["total"] == 1
    row = one["items"][0]
    assert row["value"] == "162[.]243[.]103[.]246"  # never the live value
    assert len(row["sources"]) == 1
    assert "Feodo" in row["sources"][0]
    assert row["type"] == "ip"
    ips = (await web.c.get("/app/api/indicators", params={"type": "ip", "status": "expired"})).json()
    assert all(i["type"] == "ip" and i["status"] == "expired" for i in ips["items"])
    assert (await web.c.get("/app/api/indicators", params={"q": "%"})).json()["total"] == 0  # no wildcards


async def test_everything_respects_tlp_clearance(web: Web) -> None:
    async with web.sm() as s, s.begin():
        obs_id = await s.scalar(select(ObsRow.id).where(ObsRow.value == "162.243.103.246"))
        await s.execute(update(Indicator).where(Indicator.observable_id == obs_id).values(tlp="TLP:AMBER"))
    await web.login("chandu reddy")
    red = (await web.c.get("/app/api/types", params={"scope": "All"})).json()["total"]
    assert (await web.c.get("/app/api/indicators", params={"q": "162.243.103.246"})).json()["total"] == 1
    await web.login("gina")  # cleared for TLP:GREEN only
    green = (await web.c.get("/app/api/types", params={"scope": "All"})).json()["total"]
    assert green == red - 1
    assert (await web.c.get("/app/api/indicators", params={"q": "162.243.103.246"})).json()["total"] == 0
    assert (await web.c.get("/app/api/me")).json()["clearance"] == "TLP:GREEN"
