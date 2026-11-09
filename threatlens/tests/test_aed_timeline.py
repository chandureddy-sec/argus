"""AED endpoint detail timeline (tests first).

`events_for` returns one agent's recent events, newest first, as **normalized**
(redacted) fields only — the raw payload never leaves the store. The gateway
exposes them to admins.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi.testclient import TestClient

from threatlens.aed.config import AedConfig
from threatlens.aed.events import InMemoryEventStore
from threatlens.aed.gateway import build_gateway

ADMIN = "a" * 32


def _event(agent: str, user: str = "u1", ip: str = "10.0.0.9", status: str = "failure") -> dict[str, Any]:
    return {
        "class_uid": 3002,
        "time": "2026-11-09T00:00:00+00:00",
        "agent_id": agent,
        "fields": {"activity": "logon", "status": status, "src_ip": ip, "user": user, "hostname": "h"},
        "raw": "SECRET-RAW-LINE user=root password=hunter2",
    }


def test_events_for_newest_first_scoped_and_redacted() -> None:
    s = InMemoryEventStore()
    now = datetime.now(UTC)
    s.store([_event("vm1", user="a")], now)
    s.store([_event("vm1", user="b")], now)
    s.store([_event("vm2", user="c")], now)
    rows = s.events_for("vm1")
    assert [r["user"] for r in rows] == ["b", "a"]  # newest first, vm2 excluded
    assert "agent_id" not in rows[0]
    # the raw payload never reaches the timeline
    assert "raw" not in rows[0]
    assert "SECRET-RAW-LINE" not in str(rows)


def test_events_for_respects_limit() -> None:
    s = InMemoryEventStore()
    now = datetime.now(UTC)
    for i in range(5):
        s.store([_event("vm1", user=f"u{i}")], now)
    assert len(s.events_for("vm1", limit=2)) == 2


def _gw(store: InMemoryEventStore) -> TestClient:
    return TestClient(build_gateway(AedConfig(enabled=True, admin_token=ADMIN), event_store=store))


def test_gateway_endpoint_events_admin_gated() -> None:
    s = InMemoryEventStore()
    s.store([_event("vm1")], datetime.now(UTC))
    c = _gw(s)
    assert c.get("/aed/endpoints/vm1/events").status_code == 401
    r = c.get("/aed/endpoints/vm1/events", headers={"Authorization": f"Bearer {ADMIN}"})
    assert r.status_code == 200
    body = r.json()
    assert body["agent_id"] == "vm1"
    assert body["events"][0]["src_ip"] == "10.0.0.9"
