"""API v1: authentication, role checks, rate limits and every route, against
a real (SQLite) database seeded by the collection pipeline."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.test_collect import Clock, collector, feed_handler
from threatlens.api.app import create_app
from threatlens.auth import MemoryRateLimiter, authenticate, create_key, hash_key, revoke_key
from threatlens.models import AllowlistEntry, ApiKey, AuditLog, Indicator
from threatlens.net.http import SafeHttp
from threatlens.settings import Settings

SM = async_sessionmaker[AsyncSession]
MakeHttp = Callable[[Callable[[httpx.Request], httpx.Response]], SafeHttp]


class Api:
    def __init__(
        self, client: httpx.AsyncClient, keys: dict[str, str], queued: list[tuple[str, bool]]
    ) -> None:
        self.client = client
        self.keys = keys
        self.queued = queued

    def h(self, role: str) -> dict[str, str]:
        return {"X-API-Key": self.keys[role]}


@pytest.fixture
async def api(sm: SM, mock_http: MakeHttp, tmp_path: Path) -> AsyncIterator[Api]:
    keys = {}
    async with sm() as s, s.begin():
        for role in ("viewer", "analyst", "admin"):
            _, keys[role] = await create_key(s, role, role)
    c = collector(sm, mock_http(feed_handler()), tmp_path, Clock())
    for name in ("cisa_kev", "urlhaus", "feodo"):
        await c.run(name)

    queued: list[tuple[str, bool]] = []

    async def enqueue(name: str, force: bool) -> bool:
        queued.append((name, force))
        return True

    settings = Settings(rate_limit_viewer=1000, rate_limit_analyst=1000, rate_limit_admin=1000)
    app = create_app(settings, checks={}, sessionmaker=sm, limiter=MemoryRateLimiter(), enqueue=enqueue)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        yield Api(client, keys, queued)


# ── authentication ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"X-API-Key": "tl_wrong"},
        {"X-API-Key": "not-even-the-prefix"},
        {"X-API-Key": "tl_" + "a" * 200},
        {"Authorization": "Basic dXNlcjpwYXNz"},
    ],
)
async def test_routes_need_a_valid_key(api: Api, headers: dict[str, str]) -> None:
    r = await api.client.get("/api/v1/sources", headers=headers)
    assert r.status_code == 401
    assert r.headers["WWW-Authenticate"] == "ApiKey"


async def test_bearer_header_is_accepted(api: Api) -> None:
    r = await api.client.get("/api/v1/sources", headers={"Authorization": f"Bearer {api.keys['viewer']}"})
    assert r.status_code == 200


async def test_health_endpoints_stay_open(api: Api) -> None:
    assert (await api.client.get("/healthz")).status_code == 200


async def test_only_the_hash_is_stored(sm: SM, api: Api) -> None:
    async with sm() as s:
        rows = (await s.scalars(select(ApiKey))).all()
    stored = {r.key_hash for r in rows}
    for key in api.keys.values():
        assert key not in stored
        assert hash_key(key) in stored
    assert all(len(r.prefix) == 10 for r in rows)


async def test_revoked_and_expired_keys_fail(sm: SM, api: Api) -> None:
    async with sm() as s, s.begin():
        assert await revoke_key(s, "viewer")
        assert not await revoke_key(s, "viewer")  # already revoked
        _, expired = await create_key(s, "old", "admin", expires_days=1)
        row = await s.scalar(select(ApiKey).where(ApiKey.name == "old"))
        assert row is not None
        row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    for key in (api.keys["viewer"], expired):
        assert (await api.client.get("/api/v1/sources", headers={"X-API-Key": key})).status_code == 401


async def test_create_key_validates(sm: SM, api: Api) -> None:
    async with sm() as s:
        with pytest.raises(ValueError, match="role must be"):
            await create_key(s, "x", "root")
        with pytest.raises(ValueError, match="already exists"):
            await create_key(s, "viewer", "viewer")


async def test_last_used_is_recorded_coarsely(sm: SM, api: Api) -> None:
    async with sm() as s:
        p = await authenticate(s, api.keys["analyst"])
        first = await s.scalar(select(ApiKey.last_used_at).where(ApiKey.name == "analyst"))
        await authenticate(s, api.keys["analyst"])
        second = await s.scalar(select(ApiKey.last_used_at).where(ApiKey.name == "analyst"))
    assert p is not None
    assert p.role == "analyst"
    assert first is not None
    assert first == second  # not rewritten on every request


# ── roles ────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("method", "path", "body", "minimum"),
    [
        ("GET", "/api/v1/sources", None, "viewer"),
        ("GET", "/api/v1/indicators", None, "viewer"),
        ("POST", "/api/v1/extract", {"text": "1.2.3.4"}, "analyst"),
        ("POST", "/api/v1/sources/feodo/run", None, "admin"),
        (
            "POST",
            "/api/v1/allowlist",
            {"kind": "domain", "value": "ok-partner.com", "reason": "test"},
            "admin",
        ),
    ],
)
async def test_role_hierarchy(api: Api, method: str, path: str, body: object, minimum: str) -> None:
    order = ["viewer", "analyst", "admin"]
    for role in order:
        r = await api.client.request(method, path, json=body, headers=api.h(role))
        if order.index(role) < order.index(minimum):
            assert r.status_code == 403, (role, path)
            assert minimum in r.json()["detail"]
        else:
            assert r.status_code in (200, 201, 202, 409), (role, path, r.text)


async def test_rate_limit_per_key(sm: SM) -> None:
    async with sm() as s, s.begin():
        _, key = await create_key(s, "busy", "viewer")
        _, other = await create_key(s, "calm", "viewer")
    t = [0.0]
    app = create_app(
        Settings(rate_limit_viewer=3), checks={}, sessionmaker=sm, limiter=MemoryRateLimiter(lambda: t[0])
    )
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c,
    ):
        codes = [(await c.get("/api/v1/sources", headers={"X-API-Key": key})).status_code for _ in range(4)]
        assert codes == [200, 200, 200, 429]
        r = await c.get("/api/v1/sources", headers={"X-API-Key": key})
        assert int(r.headers["Retry-After"]) == 60
        assert (await c.get("/api/v1/sources", headers={"X-API-Key": other})).status_code == 200
        t[0] = 61.0  # next window
        assert (await c.get("/api/v1/sources", headers={"X-API-Key": key})).status_code == 200


# ── sources ──────────────────────────────────────────────────────────────────


async def test_sources_list_shows_licence_and_health(api: Api) -> None:
    r = await api.client.get("/api/v1/sources", headers=api.h("viewer"))
    by_name = {s["name"]: s for s in r.json()}
    assert {"cisa_kev", "urlhaus", "feodo", "threatfox", "otx"} <= set(by_name)
    assert by_name["cisa_kev"]["health"] == "ok"
    assert by_name["cisa_kev"]["last_success_at"] is not None
    assert by_name["openphish"]["commercial_use"] is False
    assert by_name["otx"]["requires_key"] is True
    assert by_name["otx"]["key_configured"] is False
    assert "checkpoint" not in by_name["cisa_kev"]  # internal state stays internal


async def test_source_runs(api: Api) -> None:
    r = await api.client.get("/api/v1/sources/cisa_kev/runs", headers=api.h("viewer"))
    runs = r.json()
    assert len(runs) == 1
    assert runs[0]["status"] == "success"
    assert runs[0]["items_new"] == 3
    assert (await api.client.get("/api/v1/sources/nope/runs", headers=api.h("viewer"))).status_code == 404


async def test_trigger_run_is_queued_and_audited(sm: SM, api: Api) -> None:
    r = await api.client.post("/api/v1/sources/feodo/run?force=true", headers=api.h("admin"))
    assert r.status_code == 202
    assert r.json() == {"source": "feodo", "queued": True}
    assert api.queued == [("feodo", True)]
    assert (await api.client.post("/api/v1/sources/nope/run", headers=api.h("admin"))).status_code == 404
    async with sm() as s:
        audit = (await s.scalars(select(AuditLog).where(AuditLog.action == "source.run"))).all()
    assert [(a.actor, a.target) for a in audit] == [("admin", "feodo")]


# ── indicators ───────────────────────────────────────────────────────────────


async def test_indicator_listing_and_filters(api: Api) -> None:
    get = api.client.get
    allr = (await get("/api/v1/indicators", headers=api.h("viewer"))).json()
    assert allr["total"] > 0
    assert allr["limit"] == 50
    first = allr["items"][0]
    assert {"id", "type", "value", "defanged", "status", "confidence", "tlp", "sources"} <= set(first)

    cves = (await get("/api/v1/indicators?type=vulnerability", headers=api.h("viewer"))).json()
    assert cves["total"] == 3
    assert all(i["type"] == "vulnerability" for i in cves["items"])
    assert all(i["sources"] == ["cisa_kev"] for i in cves["items"])

    feodo = (await get("/api/v1/indicators?source=feodo", headers=api.h("viewer"))).json()
    assert feodo["total"] > 0
    assert all("feodo" in i["sources"] for i in feodo["items"])

    one = cves["items"][0]["value"]
    q = (await get(f"/api/v1/indicators?q={one.lower()}", headers=api.h("viewer"))).json()
    assert [i["value"] for i in q["items"]] == [one]

    page = (await get("/api/v1/indicators?limit=1&offset=1", headers=api.h("viewer"))).json()
    assert len(page["items"]) == 1
    assert page["total"] == allr["total"]


@pytest.mark.parametrize("q", ["%", "_", "\\"])
async def test_search_wildcards_are_literal(api: Api, q: str) -> None:
    r = await api.client.get("/api/v1/indicators", params={"q": q * 2}, headers=api.h("viewer"))
    assert r.status_code == 200
    assert r.json()["total"] == 0


@pytest.mark.parametrize(
    "query", ["type=nope", "status=bogus", "limit=0", "limit=501", "offset=-1", "q=x", "q=" + "a" * 201]
)
async def test_indicator_query_validation(api: Api, query: str) -> None:
    r = await api.client.get(f"/api/v1/indicators?{query}", headers=api.h("viewer"))
    assert r.status_code == 422


async def test_indicator_detail(sm: SM, api: Api) -> None:
    async with sm() as s:
        ind_id = await s.scalar(select(Indicator.id).limit(1))
    r = await api.client.get(f"/api/v1/indicators/{ind_id}", headers=api.h("viewer"))
    body = r.json()
    assert body["id"] == ind_id
    assert len(body["sightings"]) >= 1
    assert {"source", "first_seen", "times_reported", "context"} <= set(body["sightings"][0])
    assert (await api.client.get("/api/v1/indicators/999999", headers=api.h("viewer"))).status_code == 404


# ── extraction ───────────────────────────────────────────────────────────────


async def test_extract(api: Api) -> None:
    text = "C2 at hxxp://evil-c2[.]net/gate.php and 8.8.8.8, not 10.0.0.1; see CVE-2024-3400"
    r = await api.client.post(
        "/api/v1/extract", json={"text": text, "include_rejected": True}, headers=api.h("analyst")
    )
    body = r.json()
    got = {(o["type"], o["value"]) for o in body["observables"]}
    assert ("url", "http://evil-c2.net/gate.php") in got
    assert ("ipv4-addr", "8.8.8.8") in got
    assert ("vulnerability", "CVE-2024-3400") in got
    assert any(x["raw"] == "10.0.0.1" for x in body["rejected"])
    assert all("[.]" in o["defanged"] or o["type"] == "vulnerability" for o in body["observables"])


async def test_extract_size_cap(api: Api) -> None:
    r = await api.client.post("/api/v1/extract", json={"text": "a" * 1_000_001}, headers=api.h("analyst"))
    assert r.status_code == 422


# ── allowlist ────────────────────────────────────────────────────────────────


async def test_allowlist_add_reapplies_and_audits(sm: SM, api: Api) -> None:
    feodo = (
        await api.client.get("/api/v1/indicators?type=ipv4-addr&source=feodo", headers=api.h("viewer"))
    ).json()
    ip = feodo["items"][0]["value"]
    assert feodo["items"][0]["status"] != "false_positive"

    r = await api.client.post(
        "/api/v1/allowlist",
        json={"kind": "cidr", "value": f"{ip}/32", "reason": "our partner's scanner"},
        headers=api.h("admin"),
    )
    assert r.status_code == 201
    entry = r.json()
    assert entry["value"] == f"{ip}/32"
    assert entry["origin"] == "manual"
    assert entry["created_by"] == "admin"

    after = (await api.client.get(f"/api/v1/indicators?q={ip}", headers=api.h("viewer"))).json()["items"][0]
    assert after["allowlist_reason"]  # background re-evaluation ran

    dup = await api.client.post(
        "/api/v1/allowlist",
        json={"kind": "cidr", "value": f"{ip}/32", "reason": "again"},
        headers=api.h("admin"),
    )
    assert dup.status_code == 409

    listing = (await api.client.get("/api/v1/allowlist?origin=manual", headers=api.h("viewer"))).json()
    assert listing["total"] == 1

    d = await api.client.delete(f"/api/v1/allowlist/{entry['id']}", headers=api.h("admin"))
    assert d.status_code == 204
    restored = (await api.client.get(f"/api/v1/indicators?q={ip}", headers=api.h("viewer"))).json()
    assert restored["items"][0]["allowlist_reason"] is None
    assert (
        await api.client.delete(f"/api/v1/allowlist/{entry['id']}", headers=api.h("admin"))
    ).status_code == 404

    async with sm() as s:
        actions = (await s.scalars(select(AuditLog.action).where(AuditLog.action.like("allowlist.%")))).all()
    assert sorted(actions) == ["allowlist.add", "allowlist.delete"]


@pytest.mark.parametrize(
    ("kind", "value"), [("cidr", "not-a-range"), ("domain", "localhost"), ("domain", "-bad-.com")]
)
async def test_allowlist_rejects_bad_values(api: Api, kind: str, value: str) -> None:
    r = await api.client.post(
        "/api/v1/allowlist", json={"kind": kind, "value": value, "reason": "test"}, headers=api.h("admin")
    )
    assert r.status_code == 422


async def test_automatic_entries_cannot_be_deleted_by_hand(sm: SM, api: Api) -> None:
    async with sm() as s, s.begin():
        row = AllowlistEntry(
            kind="domain", value="google.com", effect="suppress", reason="t", origin="tranco"
        )
        s.add(row)
        await s.flush()
        rid = row.id
    r = await api.client.delete(f"/api/v1/allowlist/{rid}", headers=api.h("admin"))
    assert r.status_code == 403
