"""Analyst UI: sign-in, session cookies and their guards, and every page
rendering against a graph built from recorded fixtures."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.test_kb import build_graph
from threatlens.api.app import create_app
from threatlens.auth import MemoryRateLimiter, create_key, revoke_key
from threatlens.models import ApiKey, Indicator, Observable
from threatlens.net.http import SafeHttp
from threatlens.settings import Settings
from threatlens.ui import session
from threatlens.ui.routes import _target, ago, plain, safe_url

SM = async_sessionmaker[AsyncSession]
MakeHttp = Callable[[Callable[[httpx.Request], httpx.Response]], SafeHttp]
SETTINGS = Settings(secret_key="test-secret-key-0123456789")  # type: ignore[arg-type]  # noqa: S106


class Ui:
    def __init__(self, client: httpx.AsyncClient, key: str, sm: SM) -> None:
        self.client = client
        self.key = key
        self.sm = sm

    async def login(self, key: str | None = None, nxt: str = "/ui", **headers: str) -> httpx.Response:
        return await self.client.post(
            "/ui/login", data={"key": key or self.key, "next": nxt}, headers=headers
        )


@pytest.fixture
async def ui(sm: SM, mock_http: MakeHttp, tmp_path: Path) -> AsyncIterator[Ui]:
    await build_graph(sm, mock_http, tmp_path)
    async with sm() as s, s.begin():
        _, key = await create_key(s, "alice", "analyst")
    app = create_app(SETTINGS, checks={}, sessionmaker=sm, limiter=MemoryRateLimiter())
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c,
    ):
        yield Ui(c, key, sm)


# ── sign-in ──────────────────────────────────────────────────────────────────


async def test_pages_redirect_to_login_keeping_the_target(ui: Ui) -> None:
    r = await ui.client.get("/ui/indicators?type=ipv4")
    assert r.status_code == 303
    assert r.headers["location"] == "/ui/login?next=/ui/indicators?type=ipv4"
    form = await ui.client.get("/ui/login?next=/ui/indicators")
    assert form.status_code == 200
    assert 'name="next" value="/ui/indicators"' in form.text
    assert "script-src" not in form.headers["content-security-policy"]  # default-src 'none' covers it
    assert "default-src 'none'" in form.headers["content-security-policy"]


async def test_login_sets_a_strict_session_cookie(ui: Ui) -> None:
    r = await ui.login(nxt="/ui/sources", **{"Sec-Fetch-Site": "same-origin"})
    assert r.status_code == 303
    assert r.headers["location"] == "/ui/sources"
    cookie = r.headers["set-cookie"]
    assert cookie.startswith(f"{session.COOKIE}=")
    assert "HttpOnly" in cookie
    assert "SameSite=strict" in cookie
    assert ui.key not in cookie  # only a signed key id, never the key
    assert (await ui.client.get("/ui/sources")).status_code == 200


async def test_bad_key_is_refused(ui: Ui) -> None:
    r = await ui.login("tl_not-a-real-key")
    assert r.status_code == 401
    assert "not valid" in r.text
    assert "set-cookie" not in r.headers


async def test_cross_site_login_and_logout_are_refused(ui: Ui) -> None:
    assert (await ui.login(**{"Sec-Fetch-Site": "cross-site"})).status_code == 403
    assert (await ui.login(Origin="https://evil.example")).status_code == 403
    assert (await ui.login(Origin="null")).status_code == 403
    assert (await ui.login(Origin="http://test")).status_code == 303
    r = await ui.client.post("/ui/logout", headers={"Sec-Fetch-Site": "cross-site"})
    assert r.status_code == 403
    assert (await ui.client.get("/ui")).status_code == 200  # still signed in


@pytest.mark.parametrize(
    ("nxt", "ok"),
    [
        ("/ui/attack", True),
        ("/ui/indicators?q=x", True),
        ("https://evil.example/ui", False),
        ("//evil.example/ui", False),
        ("/ui//evil.example", False),
        ("/ui\\..\\evil", False),
        ("/api/v1/indicators", False),
    ],
)
def test_post_login_target_stays_inside_the_ui(nxt: str, ok: bool) -> None:
    assert _target(nxt) == (nxt if ok else "/ui")


async def test_login_is_rate_limited(ui: Ui) -> None:
    for _ in range(10):
        assert (await ui.login("tl_wrong")).status_code == 401
    r = await ui.login()  # even the right key, once the bucket is full
    assert r.status_code == 429
    assert "set-cookie" not in r.headers


async def test_logout_ends_the_session(ui: Ui) -> None:
    await ui.login()
    r = await ui.client.post("/ui/logout", headers={"Sec-Fetch-Site": "same-origin"})
    assert r.status_code == 303
    assert r.headers["location"] == "/ui/login"
    assert (await ui.client.get("/ui")).status_code == 303


async def test_revoking_or_expiring_the_key_ends_its_sessions(ui: Ui) -> None:
    await ui.login()
    assert (await ui.client.get("/ui")).status_code == 200
    async with ui.sm() as s, s.begin():
        await s.execute(update(ApiKey).values(expires_at=datetime.now(UTC) - timedelta(seconds=1)))
    assert (await ui.client.get("/ui")).status_code == 303
    async with ui.sm() as s, s.begin():
        await s.execute(update(ApiKey).values(expires_at=None))
    assert (await ui.client.get("/ui")).status_code == 200
    async with ui.sm() as s, s.begin():
        assert await revoke_key(s, "alice")
    assert (await ui.client.get("/ui")).status_code == 303


def test_session_tokens_are_signed_and_expire() -> None:
    tok = session.issue(SETTINGS, 7, now=1000.0)
    assert session.parse(SETTINGS, tok, now=1001.0) == 7
    assert session.parse(SETTINGS, tok, now=1000.0 + session.LIFETIME_S + 1) is None
    key_id, exp, sig = tok.split(".")
    assert session.parse(SETTINGS, f"8.{exp}.{sig}", now=1001.0) is None  # forged id
    assert session.parse(SETTINGS, f"{key_id}.{int(exp) + 10**6}.{sig}", now=1001.0) is None
    other = Settings(secret_key="another-secret-key-987654321")  # type: ignore[arg-type]  # noqa: S106
    assert session.parse(other, tok, now=1001.0) is None
    for junk in ("", "a.b.c", "1.2", "1.2.3.4", "1.2." + "f" * 300):
        assert session.parse(SETTINGS, junk) is None


# ── pages ────────────────────────────────────────────────────────────────────


async def test_every_page_renders(ui: Ui) -> None:
    await ui.login()
    async with ui.sm() as s:
        ind_id = await s.scalar(select(Indicator.id).order_by(Indicator.id))
    pages = [
        "/ui",
        "/ui/indicators",
        "/ui/indicators?type=ipv4-addr&status=active&q=1.&page=2",
        f"/ui/indicators/{ind_id}",
        "/ui/vulnerabilities",
        "/ui/vulnerabilities?kev=true&sort=cvss&q=cve",
        "/ui/vulnerabilities?stack=true",
        "/ui/vulnerabilities/CVE-2026-88779",
        "/ui/entities/S0367",
        "/ui/attack",
        "/ui/sources",
    ]
    for path in pages:
        r = await ui.client.get(path)
        assert r.status_code == 200, path
        assert r.headers["content-security-policy"].startswith("default-src 'none'"), path
        assert "<script" not in r.text, path
    assert "Emotet" in (await ui.client.get("/ui/entities/S0367")).text
    assert (await ui.client.get("/ui/entities/S9999")).status_code == 404
    assert (await ui.client.get("/ui/vulnerabilities/CVE-1999-0001")).status_code == 404


async def test_indicators_are_shown_defanged(ui: Ui) -> None:
    await ui.login()
    async with ui.sm() as s:
        row = (
            await s.execute(
                select(Indicator.id, Observable.value, Observable.defanged)
                .join(Observable, Observable.id == Indicator.observable_id)
                .where(Observable.type == "ipv4-addr")
                .order_by(Indicator.id)
            )
        ).first()
    assert row is not None
    ind_id, value, defanged = row
    assert value != defanged
    r = await ui.client.get(f"/ui/indicators/{ind_id}")
    assert defanged in r.text
    assert value not in r.text


async def test_search_routes_to_the_right_page(ui: Ui) -> None:
    await ui.login()
    cases = {
        "": "/ui",
        "CVE-2026-88779": "/ui/vulnerabilities/CVE-2026-88779",
        "Emotet": "/ui/entities/S0367",
        "no such thing at all": "/ui/indicators?q=no%20such%20thing%20at%20all",
    }
    for q, where in cases.items():
        r = await ui.client.get("/ui/search", params={"q": q})
        assert r.status_code == 303, q
        assert r.headers["location"] == where, q


async def test_static_files_and_root_redirect(ui: Ui) -> None:
    assert (await ui.client.get("/ui/static/app.css")).status_code == 200
    r = await ui.client.get("/")
    assert r.status_code == 307
    assert r.headers["location"] == "/ui"


def test_template_filters() -> None:
    assert plain("Uses [WMI](https://x.example/a) (Citation: Foo 2020) to run.") == "Uses WMI to run."
    assert safe_url("javascript:alert(1)") is None
    assert safe_url("https://attack.mitre.org/") == "https://attack.mitre.org/"
    now = datetime.now(UTC)
    assert ago(None) == "never"
    assert ago(now) == "just now"
    assert ago(now - timedelta(hours=3, minutes=5)) == "3h ago"
    assert ago(now - timedelta(days=2)) == "2d ago"
