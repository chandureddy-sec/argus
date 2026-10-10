from __future__ import annotations

import asyncio
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from threatlens.api.app import SECURITY_HEADERS, create_app
from threatlens.health import Check
from threatlens.settings import Environment, Settings


async def ok() -> None:
    return None


async def boom() -> None:
    # The message mimics a driver error that embeds a DSN; it must not leak.
    raise ConnectionRefusedError("connect to postgresql://threatlens:hunter2@db:5432 failed")


async def hang() -> None:
    await asyncio.sleep(10)


def client(checks: dict[str, Check], **settings: object) -> TestClient:
    s = Settings(readiness_timeout_s=0.2, log_json=True, **settings)  # type: ignore[arg-type]
    return TestClient(create_app(s, checks=checks))


@pytest.fixture
def healthy() -> Iterator[TestClient]:
    with client({"postgres": ok, "redis": ok}) as c:
        yield c


def test_healthz(healthy: TestClient) -> None:
    r = healthy.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_readyz_ready(healthy: TestClient) -> None:
    r = healthy.get("/readyz")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ready"
    assert set(body["checks"]) == {"postgres", "redis"}
    assert all(c["ok"] for c in body["checks"].values())


def test_readyz_reports_failures_without_leaking_details() -> None:
    with client({"postgres": boom, "redis": hang}) as c:
        r = c.get("/readyz")
    assert r.status_code == 503
    checks = r.json()["checks"]
    assert checks["postgres"] == {
        "ok": False,
        "latency_ms": checks["postgres"]["latency_ms"],
        "error": "ConnectionRefusedError",
    }
    assert checks["redis"]["error"] == "timed out after 0.2s"
    assert "hunter2" not in r.text


def test_liveness_ignores_dependencies() -> None:
    with client({"postgres": boom}) as c:
        assert c.get("/healthz").status_code == 200


def test_security_headers(healthy: TestClient) -> None:
    r = healthy.get("/healthz")
    for k, v in SECURITY_HEADERS.items():
        assert r.headers[k] == v


@pytest.mark.parametrize(
    ("sent", "echoed"),
    [("abc-123", True), ("x" * 65, False), ("evil\nInjected: 1", False), ("<script>", False)],
)
def test_request_id(healthy: TestClient, sent: str, echoed: bool) -> None:
    try:
        r = healthy.get("/healthz", headers={"X-Request-ID": sent})
    except Exception:  # httpx itself refuses header values with newlines
        assert not echoed
        return
    rid = r.headers["X-Request-ID"]
    assert (rid == sent) is echoed
    if not echoed:
        assert len(rid) == 32


def test_no_swagger_page_and_schema_only_outside_prod() -> None:
    with client({}) as c:
        assert c.get("/openapi.json").status_code == 200
        assert c.get("/docs").status_code == 404
        assert c.get("/redoc").status_code == 404
    with client({}, env=Environment.PROD) as c:
        assert c.get("/openapi.json").status_code == 404
        assert c.get("/docs").status_code == 404
