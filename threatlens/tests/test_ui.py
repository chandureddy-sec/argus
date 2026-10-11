"""Analyst UI: sign-in, session cookies and their guards, and every page
rendering against a graph built from recorded fixtures."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.test_enrich import Upstream
from tests.test_kb import build_graph
from tests.uihelp import only_our_script
from threatlens.api.app import create_app
from threatlens.auth import MemoryRateLimiter, create_key
from threatlens.enrich.quota import MemoryQuotaStore
from threatlens.enrich.service import EnrichmentService
from threatlens.models import Indicator, Observable
from threatlens.net.http import SafeHttp
from threatlens.settings import Settings
from threatlens.ui import session
from threatlens.ui.routes import _target, ago, plain, safe_url
from threatlens.users import create_user, set_disabled, set_password

SM = async_sessionmaker[AsyncSession]
MakeHttp = Callable[[Callable[[httpx.Request], httpx.Response]], SafeHttp]
SETTINGS = Settings(secret_key="test-secret-key-0123456789")  # type: ignore[arg-type]  # noqa: S106


PASSWORD = "correct horse battery"  # noqa: S105  # test account
NEW_PASSWORD = "a brand new password"  # noqa: S105


class Ui:
    def __init__(self, client: httpx.AsyncClient, sm: SM) -> None:
        self.client = client
        self.sm = sm

    async def login(
        self, user: str = "Alice", password: str = PASSWORD, nxt: str = "/ui", **headers: str
    ) -> httpx.Response:
        return await self.client.post(
            "/ui/login", data={"username": user, "password": password, "next": nxt}, headers=headers
        )


@pytest.fixture
async def ui(sm: SM, mock_http: MakeHttp, tmp_path: Path) -> AsyncIterator[Ui]:
    await build_graph(sm, mock_http, tmp_path)
    async with sm() as s, s.begin():
        await create_user(s, "Alice", PASSWORD, "analyst")
    upstream = mock_http(Upstream())  # every enrichment provider, from recorded answers
    svc = EnrichmentService(sm, upstream, MemoryQuotaStore(), SETTINGS)
    # A frozen clock: a test's requests must not straddle a rate-limit window (that reset the count).
    limiter = MemoryRateLimiter(clock=lambda: 1_000.0)
    app = create_app(SETTINGS, checks={}, sessionmaker=sm, limiter=limiter, enrich=svc)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c,
    ):
        yield Ui(c, sm)


# ── sign-in ──────────────────────────────────────────────────────────────────


async def test_pages_redirect_to_login_keeping_the_target(ui: Ui) -> None:
    r = await ui.client.get("/ui/indicators?type=ipv4")
    assert r.status_code == 303
    assert r.headers["location"] == "/ui/login?next=/ui/indicators?type=ipv4"
    form = await ui.client.get("/ui/login?next=/ui/indicators")
    assert form.status_code == 200
    assert 'name="next" value="/ui/indicators"' in form.text
    assert "script-src 'self'" in form.headers["content-security-policy"]  # our app.js only
    assert "default-src 'none'" in form.headers["content-security-policy"]


async def test_login_sets_a_strict_session_cookie(ui: Ui) -> None:
    r = await ui.login(nxt="/ui/sources", **{"Sec-Fetch-Site": "same-origin"})
    assert r.status_code == 303
    assert r.headers["location"] == "/ui/sources"
    cookie = r.headers["set-cookie"]
    assert cookie.startswith(f"{session.COOKIE}=")
    assert "HttpOnly" in cookie
    assert "SameSite=strict" in cookie
    assert PASSWORD.split()[0] not in cookie  # a signed user id, never the password
    assert (await ui.client.get("/ui/sources")).status_code == 200
    page = (await ui.client.get("/ui/sources")).text
    assert "<b>Alice</b>" in page
    assert "analyst" in page


async def test_username_is_case_and_space_insensitive(ui: Ui) -> None:
    assert (await ui.login("  ALICE ")).status_code == 303


@pytest.mark.parametrize(("user", "password"), [("Alice", "wrong password"), ("mallory", PASSWORD), ("", "")])
async def test_wrong_username_or_password_is_refused(ui: Ui, user: str, password: str) -> None:
    r = await ui.login(user, password)
    assert r.status_code in (401, 422)
    assert "set-cookie" not in r.headers
    if r.status_code == 401:
        assert "Wrong username or password." in r.text  # same message: no username probing


async def test_api_keys_no_longer_sign_in_to_the_ui(ui: Ui) -> None:
    async with ui.sm() as s, s.begin():
        _, key = await create_key(s, "reconx", "admin")
    r = await ui.client.post("/ui/login", data={"key": key}, headers={"Sec-Fetch-Site": "same-origin"})
    assert r.status_code == 422
    assert (await ui.login("reconx", key)).status_code == 401


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
        assert (await ui.login("Alice", "wrong-password")).status_code == 401
    r = await ui.login()  # even the right password, once the bucket is full
    assert r.status_code == 429
    assert "set-cookie" not in r.headers


async def test_logout_ends_the_session(ui: Ui) -> None:
    await ui.login()
    r = await ui.client.post("/ui/logout", headers={"Sec-Fetch-Site": "same-origin"})
    assert r.status_code == 303
    assert r.headers["location"] == "/ui/login"
    assert (await ui.client.get("/ui")).status_code == 303


async def test_disabling_the_account_or_changing_its_password_ends_its_sessions(ui: Ui) -> None:
    await ui.login()
    assert (await ui.client.get("/ui")).status_code == 200
    async with ui.sm() as s, s.begin():
        await set_disabled(s, "alice", True)
    assert (await ui.client.get("/ui")).status_code == 303
    assert (await ui.login()).status_code == 401  # disabled accounts can't sign in either
    async with ui.sm() as s, s.begin():
        await set_disabled(s, "alice", False)
    assert (await ui.client.get("/ui")).status_code == 200  # the old session is valid again
    async with ui.sm() as s, s.begin():
        await set_password(s, "alice", NEW_PASSWORD)
    assert (await ui.client.get("/ui")).status_code == 303
    assert (await ui.login()).status_code == 401
    assert (await ui.login("Alice", NEW_PASSWORD)).status_code == 303


def test_session_tokens_are_signed_and_expire() -> None:
    tok = session.issue(SETTINGS, 7, "abc123", now=1000.0)
    assert session.parse(SETTINGS, tok, now=1001.0) == (7, "abc123")
    assert session.parse(SETTINGS, tok, now=1000.0 + session.LIFETIME_S + 1) is None
    _, uid, exp, tag, sig = tok.split(".")
    assert session.parse(SETTINGS, f"u.8.{exp}.{tag}.{sig}", now=1001.0) is None  # forged id
    assert session.parse(SETTINGS, f"u.{uid}.{int(exp) + 10**6}.{tag}.{sig}", now=1001.0) is None
    assert session.parse(SETTINGS, f"u.{uid}.{exp}.zzz.{sig}", now=1001.0) is None
    other = Settings(secret_key="another-secret-key-987654321")  # type: ignore[arg-type]  # noqa: S106
    assert session.parse(other, tok, now=1001.0) is None
    for junk in ("", "a.b.c", "1.2", "1.2.3.4", f"7.{exp}.{sig}", "u.1.2.t." + "f" * 300):
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
        assert only_our_script(r.text), path
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
        "CVE-2026-88779": "/ui/vulnerabilities/CVE-2026-88779",
        "Emotet": "/ui/entities/S0367",
    }
    for q, where in cases.items():
        r = await ui.client.get("/ui/search", params={"q": q})
        assert r.status_code == 303, q
        assert r.headers["location"] == where, q
    # No exact hit: a results page (indicators, tags, entities, CVEs, cases) instead.
    for q in ("", "no such thing at all", "emot"):
        r = await ui.client.get("/ui/search", params={"q": q})
        assert r.status_code == 200, q
    listing = await ui.client.get("/ui/search", params={"q": "Emotet", "show": "all"})
    assert "Malware, actors, techniques" in listing.text
    assert "S0367" in listing.text


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


async def test_indicator_enrichment_panel(ui: Ui) -> None:
    await ui.login()
    async with ui.sm() as s:
        ind_id = await s.scalar(
            select(Indicator.id)
            .join(Observable, Observable.id == Indicator.observable_id)
            .where(Observable.value == "162.243.103.246")
        )
    page = f"/ui/indicators/{ind_id}"
    assert "Not enriched yet" in (await ui.client.get(page)).text
    url = f"{page}/enrich"
    assert (await ui.client.post(url, headers={"Sec-Fetch-Site": "cross-site"})).status_code == 403
    r = await ui.client.post(url, headers={"Sec-Fetch-Site": "same-origin"})
    assert r.status_code == 303
    assert r.headers["location"] == f"{page}#enrichment"
    html = (await ui.client.get(page)).text
    assert "DIGITALOCEAN-162-243-0-0" in html  # RDAP network name
    assert "Secaucus" in html  # RIPEstat location
    assert "162.243.103.246" not in html  # provider text is defanged too
    assert only_our_script(html)
    assert (
        await ui.client.post("/ui/indicators/999999/enrich", headers={"Sec-Fetch-Site": "same-origin"})
    ).status_code == 404


async def test_viewers_cannot_trigger_enrichment(ui: Ui) -> None:
    async with ui.sm() as s, s.begin():
        await create_user(s, "vic", "viewer-password", "viewer")
    await ui.login("vic", "viewer-password")
    r = await ui.client.post("/ui/indicators/1/enrich", headers={"Sec-Fetch-Site": "same-origin"})
    assert r.status_code == 403
    assert "Enrich now" not in (await ui.client.get("/ui/indicators/1")).text
