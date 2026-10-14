"""Argus sign-in and sessions (ADR 0007, 0016), the old /ui addresses, and
the landscape, ATT&CK and search JSON against a graph built from recorded
fixtures."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.test_enrich import Upstream
from tests.test_kb import build_graph
from threatlens import session
from threatlens.api.app import create_app
from threatlens.auth import MemoryRateLimiter, create_key
from threatlens.enrich.quota import MemoryQuotaStore
from threatlens.enrich.service import EnrichmentService
from threatlens.models import Indicator, Observable
from threatlens.net.http import SafeHttp
from threatlens.settings import Settings
from threatlens.users import create_user, set_disabled, set_password
from threatlens.webapp import safe_next

SM = async_sessionmaker[AsyncSession]
MakeHttp = Callable[[Callable[[httpx.Request], httpx.Response]], SafeHttp]
SECRET = "test-secret-key-0123456789"  # noqa: S105
PASSWORD = "correct horse battery"  # noqa: S105  # test account
NEW_PASSWORD = "a brand new password"  # noqa: S105
SAME = {"Sec-Fetch-Site": "same-origin"}


class Argus:
    def __init__(self, client: httpx.AsyncClient, sm: SM) -> None:
        self.client = client
        self.sm = sm

    async def login(self, user: str = "Alice", password: str = PASSWORD, **headers: str) -> httpx.Response:
        return await self.client.post(
            "/app/api/session", json={"username": user, "password": password}, headers=headers or SAME
        )


@pytest.fixture
def dist(tmp_path: Path) -> Path:
    d = tmp_path / "dist"
    d.mkdir()
    (d / "index.html").write_text('<!doctype html><div id="root"></div>')
    return d


@pytest.fixture
async def ar(sm: SM, mock_http: MakeHttp, tmp_path: Path, dist: Path) -> AsyncIterator[Argus]:
    await build_graph(sm, mock_http, tmp_path)
    async with sm() as s, s.begin():
        await create_user(s, "Alice", PASSWORD, "analyst")
    settings = Settings(secret_key=SECRET, web_dist=dist)  # type: ignore[arg-type]
    svc = EnrichmentService(sm, mock_http(Upstream()), MemoryQuotaStore(), settings)
    # A frozen clock: a test's requests must not straddle a rate-limit window (that resets the count).
    limiter = MemoryRateLimiter(clock=lambda: 1_000.0)
    app = create_app(settings, checks={}, sessionmaker=sm, limiter=limiter, enrich=svc)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c,
    ):
        yield Argus(c, sm)


# ── sign-in ──────────────────────────────────────────────────────────────────


async def test_pages_send_you_to_sign_in_keeping_the_target(ar: Argus) -> None:
    r = await ar.client.get("/app/indicators?type=ipv4-addr")
    assert r.status_code == 303
    assert r.headers["location"] == "/app/login?next=/app/indicators%3Ftype%3Dipv4-addr"
    page = await ar.client.get("/app/login")  # the sign-in page needs no session
    assert page.status_code == 200
    assert "script-src 'self'" in page.headers["content-security-policy"]
    assert (await ar.client.get("/app/api/me")).status_code == 401


async def test_login_sets_a_strict_session_cookie(ar: Argus) -> None:
    r = await ar.login()
    assert r.status_code == 200
    cookie = r.headers["set-cookie"]
    assert cookie.startswith(f"{session.COOKIE}=")
    assert "HttpOnly" in cookie
    assert "SameSite=strict" in cookie
    assert PASSWORD.split()[0] not in cookie  # a signed user id, never the password
    assert (await ar.client.get("/app/api/me")).json()["name"] == "Alice"
    assert (await ar.client.get("/app/indicators")).status_code == 200


async def test_username_is_case_and_space_insensitive(ar: Argus) -> None:
    assert (await ar.login("  ALICE ")).status_code == 200


@pytest.mark.parametrize(("user", "password"), [("Alice", "wrong password"), ("mallory", PASSWORD), ("", "")])
async def test_wrong_username_or_password_is_refused(ar: Argus, user: str, password: str) -> None:
    r = await ar.login(user, password)
    assert r.status_code in (401, 422)
    assert "set-cookie" not in r.headers
    if r.status_code == 401:
        assert r.json()["detail"] == "Wrong username or password."  # same message: no username probing


async def test_api_keys_do_not_sign_in(ar: Argus) -> None:
    async with ar.sm() as s, s.begin():
        _, key = await create_key(s, "reconx", "admin")
    assert (await ar.login("reconx", key)).status_code == 401
    assert (await ar.client.get("/app/api/me", headers={"X-API-Key": key})).status_code == 401


async def test_cross_site_login_and_logout_are_refused(ar: Argus) -> None:
    assert (await ar.login(**{"Sec-Fetch-Site": "cross-site"})).status_code == 403
    assert (await ar.login(Origin="https://evil.example")).status_code == 403
    assert (await ar.login(Origin="null")).status_code == 403
    assert (await ar.login(Origin="http://test")).status_code == 200
    r = await ar.client.delete("/app/api/session", headers={"Sec-Fetch-Site": "cross-site"})
    assert r.status_code == 403
    assert (await ar.client.get("/app/api/me")).status_code == 200  # still signed in


@pytest.mark.parametrize(
    ("nxt", "ok"),
    [
        ("/app/attack", True),
        ("/app/indicators?q=x", True),
        ("https://evil.example/app/", False),
        ("//evil.example/app/", False),
        ("/app//evil.example", False),
        ("/app/\\..\\evil", False),
        ("/api/v1/indicators", False),
    ],
)
def test_post_login_target_stays_inside_argus(nxt: str, ok: bool) -> None:
    assert safe_next(nxt) == (nxt if ok else "/app/")


async def test_login_is_rate_limited(ar: Argus) -> None:
    for _ in range(10):
        assert (await ar.login("Alice", "wrong-password")).status_code == 401
    r = await ar.login()  # even the right password, once the bucket is full
    assert r.status_code == 429
    assert "set-cookie" not in r.headers


async def test_logout_ends_the_session(ar: Argus) -> None:
    await ar.login()
    r = await ar.client.delete("/app/api/session", headers=SAME)
    assert r.status_code == 200
    assert (await ar.client.get("/app/api/me")).status_code == 401


async def test_disabling_the_account_or_changing_its_password_ends_its_sessions(ar: Argus) -> None:
    await ar.login()
    assert (await ar.client.get("/app/api/me")).status_code == 200
    async with ar.sm() as s, s.begin():
        await set_disabled(s, "alice", True)
    assert (await ar.client.get("/app/api/me")).status_code == 401
    assert (await ar.login()).status_code == 401  # disabled accounts can't sign in either
    async with ar.sm() as s, s.begin():
        await set_disabled(s, "alice", False)
    assert (await ar.client.get("/app/api/me")).status_code == 200  # the old session is valid again
    async with ar.sm() as s, s.begin():
        await set_password(s, "alice", NEW_PASSWORD)
    assert (await ar.client.get("/app/api/me")).status_code == 401
    assert (await ar.login()).status_code == 401
    assert (await ar.login("Alice", NEW_PASSWORD)).status_code == 200


def test_session_tokens_are_signed_and_expire() -> None:
    settings = Settings(secret_key=SECRET)  # type: ignore[arg-type]
    tok = session.issue(settings, 7, "abc123", now=1000.0)
    assert session.parse(settings, tok, now=1001.0) == (7, "abc123")
    assert session.parse(settings, tok, now=1000.0 + session.LIFETIME_S + 1) is None
    _, uid, exp, tag, sig = tok.split(".")
    assert session.parse(settings, f"u.8.{exp}.{tag}.{sig}", now=1001.0) is None  # forged id
    assert session.parse(settings, f"u.{uid}.{int(exp) + 10**6}.{tag}.{sig}", now=1001.0) is None
    assert session.parse(settings, f"u.{uid}.{exp}.zzz.{sig}", now=1001.0) is None
    other = Settings(secret_key="another-secret-key-987654321")  # type: ignore[arg-type]  # noqa: S106
    assert session.parse(other, tok, now=1001.0) is None
    for junk in ("", "a.b.c", "1.2", "1.2.3.4", f"7.{exp}.{sig}", "u.1.2.t." + "f" * 300):
        assert session.parse(settings, junk) is None


async def test_old_addresses_open_the_argus_page(ar: Argus) -> None:
    for old, new in (
        ("/ui", "/app/"),
        ("/ui/indicators?type=url", "/app/indicators?type=url"),
        ("/ui/lookup", "/app/bulk"),
        ("/ui/sources/feodo", "/app/feeds/feodo"),
        ("/ui/vulnerabilities/CVE-2026-88779", "/app/vulnerabilities/CVE-2026-88779"),
        ("/ui/login?next=/ui", "/app/login?next=/ui"),
    ):
        r = await ar.client.get(old)
        assert r.status_code == 301, old
        assert r.headers["location"] == new, old
    assert (await ar.client.get("/")).headers["location"] == "/app/"


# ── landscape, ATT&CK, search ────────────────────────────────────────────────


async def test_landscape_and_attack_matrix(ar: Argus) -> None:
    assert (await ar.client.get("/app/api/landscape")).status_code == 401
    await ar.login()
    d = (await ar.client.get("/app/api/landscape")).json()
    assert {k["label"] for k in d["kpis"]} >= {"Active indicators", "Known exploited CVEs"}
    assert any(f["name"] == "Emotet" for f in d["families"])
    assert all(f["href"].startswith("/entities/") for f in d["families"])
    assert {p["priority"] for p in d["patch"]} == {"P1", "P2", "P3", "P4"}
    for q in d["queue"]:
        assert "[.]" in q["value"] or q["type"] not in ("IPv4 address", "Domain")  # defanged
    m = (await ar.client.get("/app/api/attack")).json()
    assert m["columns"]
    assert m["peak"] >= 1
    assert any(c["count"] for col in m["columns"] for c in col["cells"])


async def test_search_opens_exact_hits_and_lists_the_rest(ar: Argus) -> None:
    await ar.login()
    for q, where in (("CVE-2026-88779", "/vulnerabilities/CVE-2026-88779"), ("Emotet", "/entities/S0367")):
        assert (await ar.client.get("/app/api/search", params={"q": q})).json()["open"] == where, q
    listing = (await ar.client.get("/app/api/search", params={"q": "Emotet", "all": "true"})).json()
    assert listing["open"] is None
    assert any(e["id"] == "S0367" for e in listing["entities"])
    async with ar.sm() as s:
        row = (
            await s.execute(
                select(Indicator.id, Observable.value, Observable.defanged)
                .join(Observable, Observable.id == Indicator.observable_id)
                .where(Observable.type == "ipv4-addr")
                .order_by(Indicator.id)
            )
        ).first()
    assert row is not None
    _, value, defanged = row
    found = (await ar.client.get("/app/api/search", params={"q": value[:6], "all": "true"})).json()
    assert defanged in [i["value"] for i in found["indicators"]]
    assert value not in str(found)
    empty = (await ar.client.get("/app/api/search", params={"q": "x"})).json()
    assert empty["indicators"] == []
