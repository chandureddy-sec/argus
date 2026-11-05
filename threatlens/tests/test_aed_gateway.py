"""AED gateway skeleton (Slice 1) — tests written first.

Scope: a separate gateway app (not mounted on the :8000 API), disabled until
explicitly enabled, with strict-auth hook, rate limit, payload-size cap and
JSON validation. mTLS client-cert auth arrives in Slice 2; here the auth
dependency denies by default and is overridden in tests to simulate an agent.
"""

import json

from fastapi.testclient import TestClient

from threatlens.aed.config import AedConfig
from threatlens.aed.gateway import RateLimiter, build_gateway, require_agent


class _Agent:
    agent_id = "agent-test"


def _client(cfg: AedConfig, limiter: RateLimiter | None = None, authed: bool = True) -> TestClient:
    app = build_gateway(cfg, limiter=limiter)
    if authed:
        app.dependency_overrides[require_agent] = lambda: _Agent()
    return TestClient(app)


def test_healthz_always_ok_and_reports_enabled_state() -> None:
    c = _client(AedConfig(enabled=False))
    r = c.get("/aed/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body["component"] == "aed-gateway"
    assert body["enabled"] is False


def test_ingest_disabled_by_default_returns_503() -> None:
    # Even with auth satisfied, a disabled gateway refuses ingest.
    c = _client(AedConfig(enabled=False))
    r = c.post("/aed/ingest", content=b'{"events":[]}')
    assert r.status_code == 503


def test_ingest_requires_auth_when_enabled() -> None:
    c = _client(AedConfig(enabled=True), authed=False)
    r = c.post("/aed/ingest", content=b'{"events":[]}')
    assert r.status_code == 401


def test_ingest_accepts_small_batch_when_enabled_and_authed() -> None:
    c = _client(AedConfig(enabled=True))
    r = c.post("/aed/ingest", content=json.dumps({"events": [{"a": 1}, {"a": 2}]}).encode())
    assert r.status_code == 202
    assert r.json()["events"] == 2


def test_ingest_oversized_body_returns_413() -> None:
    c = _client(AedConfig(enabled=True, max_batch_bytes=50))
    r = c.post("/aed/ingest", content=b'{"events":[' + b"0" * 200 + b"]}")
    assert r.status_code == 413


def test_ingest_malformed_json_returns_400() -> None:
    c = _client(AedConfig(enabled=True))
    r = c.post("/aed/ingest", content=b"{ not json")
    assert r.status_code == 400


def test_ingest_rate_limited_returns_429() -> None:
    c = _client(AedConfig(enabled=True), limiter=RateLimiter(per_min=2))
    body = b'{"events":[]}'
    assert c.post("/aed/ingest", content=body).status_code == 202
    assert c.post("/aed/ingest", content=body).status_code == 202
    assert c.post("/aed/ingest", content=body).status_code == 429


def test_gateway_is_isolated_from_main_api() -> None:
    # The agent-facing gateway must not be built/mounted into the main :8000 app.
    # (A read-only admin proxy router that talks to the gateway over HTTP is fine.)
    import inspect

    import threatlens.api.app as appmod

    src = inspect.getsource(appmod)
    bad_imports = (
        "build_gateway",
        "aed.gateway",
        "from threatlens.aed.gateway",
        "import threatlens.aed.gateway",
    )
    for bad in bad_imports:
        assert bad not in src, f"the gateway must not be wired into the :8000 app ({bad!r})"
    # The gateway owns its own /aed routes on its own app object.
    app = build_gateway(AedConfig(enabled=True))
    paths = {getattr(r, "path", "") for r in app.routes}
    assert "/aed/ingest" in paths
    assert "/aed/healthz" in paths
