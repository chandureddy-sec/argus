"""AED Slice 6 — the analyst-facing /app/api/aed proxy (tests first).

Reading the endpoint registry and alerts needs a sign-in; revoking an agent
needs the admin role and a same-site request, and is audited. The proxy holds
the admin token server-side and returns 503 (never fake data) when the gateway
is not configured.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
from sqlalchemy import select

from tests.test_cases import SM, App
from tests.test_enrich import KEYS, Upstream, http, seeded, upstream  # noqa: F401  # fixtures
from threatlens.aed_admin import AedAdminClient, AedAdminError
from threatlens.api.app import create_app
from threatlens.auth import MemoryRateLimiter
from threatlens.models import AuditLog
from threatlens.settings import Settings
from threatlens.users import create_user

SAME = {"Sec-Fetch-Site": "same-origin"}
CROSS = {"Sec-Fetch-Site": "cross-site"}


class FakeAdmin:
    """Stands in for AedAdminClient: records calls, no network."""

    def __init__(self) -> None:
        self.revoked: list[str] = []
        self.raise_on: set[str] = set()

    async def endpoints(self) -> list[dict[str, object]]:
        if "endpoints" in self.raise_on:
            raise AedAdminError("boom")
        return [{"agent_id": "lab-vm-1", "status": "online", "last_seen": "2026-11-05T00:00:00Z"}]

    async def alerts(self) -> list[dict[str, object]]:
        if "alerts" in self.raise_on:
            raise AedAdminError("boom")
        return [{"rule": "ssh_bruteforce", "agent_id": "lab-vm-1", "src_ip": "10.0.0.9", "count": 12}]

    async def revoke(self, agent_id: str) -> None:
        if "revoke" in self.raise_on:
            raise AedAdminError("boom")
        self.revoked.append(agent_id)


@pytest.fixture
async def aed_app(
    seeded: SM,  # noqa: F811
    http,  # noqa: F811
    upstream: Upstream,  # noqa: F811
) -> AsyncIterator[tuple[App, FakeAdmin]]:
    async with seeded() as s, s.begin():
        await create_user(s, "vera", "vera-password", "viewer")
        await create_user(s, "anna", "anna-password", "analyst")
        await create_user(s, "ada", "ada-password", "admin")
    settings = Settings(
        rate_limit_analyst=1000,
        rate_limit_viewer=1000,
        rate_limit_admin=1000,
        secret_key="test-vault-key-for-the-app-fixture-0123",  # noqa: S106
        **KEYS,
    )  # type: ignore[arg-type]
    fake = FakeAdmin()
    a = create_app(
        settings,
        checks={},
        sessionmaker=seeded,
        limiter=MemoryRateLimiter(),
        aed_admin=fake,  # type: ignore[arg-type]
    )
    async with (
        a.router.lifespan_context(a),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=a), base_url="http://test") as c,
    ):
        yield App(c, seeded, {}, upstream.calls), fake


async def test_endpoints_and_alerts_need_sign_in(aed_app: tuple[App, FakeAdmin]) -> None:
    app, _ = aed_app
    assert (await app.c.get("/app/api/aed/endpoints")).status_code == 401
    assert (await app.c.get("/app/api/aed/alerts")).status_code == 401


async def test_signed_in_viewer_reads_endpoints_and_alerts(aed_app: tuple[App, FakeAdmin]) -> None:
    app, _ = aed_app
    await app.login("vera")
    r = await app.c.get("/app/api/aed/endpoints")
    assert r.status_code == 200
    assert r.json()["agents"][0]["agent_id"] == "lab-vm-1"
    r2 = await app.c.get("/app/api/aed/alerts")
    assert r2.status_code == 200
    assert r2.json()["alerts"][0]["rule"] == "ssh_bruteforce"


async def test_revoke_requires_admin_and_same_origin(aed_app: tuple[App, FakeAdmin]) -> None:
    app, fake = aed_app
    # viewer -> 403
    await app.login("vera")
    assert (await app.c.post("/app/api/aed/agents/lab-vm-1/revoke", headers=SAME)).status_code == 403
    # analyst -> 403 (needs admin)
    await app.login("anna")
    assert (await app.c.post("/app/api/aed/agents/lab-vm-1/revoke", headers=SAME)).status_code == 403
    # admin cross-site -> 403
    await app.login("ada")
    assert (await app.c.post("/app/api/aed/agents/lab-vm-1/revoke", headers=CROSS)).status_code == 403
    assert fake.revoked == []


async def test_admin_revoke_calls_client_and_audits(aed_app: tuple[App, FakeAdmin]) -> None:
    app, fake = aed_app
    await app.login("ada")
    r = await app.c.post("/app/api/aed/agents/lab-vm-1/revoke", headers=SAME)
    assert r.status_code == 200
    assert r.json() == {"revoked": "lab-vm-1"}
    assert fake.revoked == ["lab-vm-1"]
    async with app.sm() as s:
        row = await s.scalar(select(AuditLog).where(AuditLog.action == "aed.revoke"))
    assert row is not None
    assert row.target == "lab-vm-1"
    assert row.actor == "ada"


async def test_revoke_rejects_bad_agent_id(aed_app: tuple[App, FakeAdmin]) -> None:
    app, fake = aed_app
    await app.login("ada")
    r = await app.c.post("/app/api/aed/agents/bad!id/revoke", headers=SAME)
    assert r.status_code == 400  # rejected before it reaches the gateway
    assert fake.revoked == []


async def test_upstream_error_is_502(aed_app: tuple[App, FakeAdmin]) -> None:
    app, fake = aed_app
    fake.raise_on = {"endpoints", "alerts", "revoke"}
    await app.login("ada")
    assert (await app.c.get("/app/api/aed/endpoints")).status_code == 502
    assert (await app.c.get("/app/api/aed/alerts")).status_code == 502
    assert (await app.c.post("/app/api/aed/agents/lab-vm-1/revoke", headers=SAME)).status_code == 502


async def test_503_when_gateway_not_configured(
    seeded: SM,  # noqa: F811
) -> None:
    async with seeded() as s, s.begin():
        await create_user(s, "ada", "ada-password", "admin")
    settings = Settings(
        secret_key="test-vault-key-for-the-app-fixture-0123",  # noqa: S106
        **KEYS,
    )  # type: ignore[arg-type]
    a = create_app(settings, checks={}, sessionmaker=seeded, limiter=MemoryRateLimiter())
    async with (
        a.router.lifespan_context(a),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=a), base_url="http://test") as c,
    ):
        app = App(c, seeded, {}, [])
        await app.login("ada")
        assert (await app.c.get("/app/api/aed/endpoints")).status_code == 503


# ---- the client itself (injected transport, no network) ----


async def test_client_sends_bearer_and_parses() -> None:
    seen: dict[str, object] = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["auth"] = req.headers.get("authorization")
        seen["url"] = str(req.url)  # raw (percent-encoded) wire form
        if req.url.path.endswith("/revoke"):
            return httpx.Response(200, json={"revoked": "x"})
        return httpx.Response(200, json={"agents": [{"agent_id": "a1"}], "alerts": []})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as http:  # noqa: F811
        client = AedAdminClient("https://gw.lab:8443", "tok-123", http=http)
        agents = await client.endpoints()
        assert agents == [{"agent_id": "a1"}]
        assert seen["auth"] == "Bearer tok-123"
        await client.revoke("lab vm/1")  # unsafe chars are percent-encoded
        assert str(seen["url"]).endswith("/aed/agents/lab%20vm%2F1/revoke")


async def test_client_raises_on_error_status() -> None:
    transport = httpx.MockTransport(lambda req: httpx.Response(401))
    async with httpx.AsyncClient(transport=transport) as http:  # noqa: F811
        client = AedAdminClient("https://gw.lab:8443", "tok", http=http)
        with pytest.raises(AedAdminError):
            await client.endpoints()
