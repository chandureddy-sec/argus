"""AED Slice 3 — endpoint registry, heartbeat and the admin endpoints list (tests first)."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from threatlens.aed.certs import CA, new_agent_csr
from threatlens.aed.config import AedConfig
from threatlens.aed.enroll import InMemoryStore
from threatlens.aed.gateway import build_gateway

SECRET = "s" * 44
ADMIN = "admin-token-xyz"
NOW = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)


# ---- store registry ----


def test_registry_status_transitions() -> None:
    store = InMemoryStore()
    store.register_agent("a1", "fp1", now=NOW)
    rows = {r["agent_id"]: r for r in store.list_agents(now=NOW, stale_after_s=300)}
    assert rows["a1"]["status"] == "pending"  # enrolled, never heartbeated

    store.heartbeat("a1", now=NOW + timedelta(seconds=10))
    rows = {r["agent_id"]: r for r in store.list_agents(now=NOW + timedelta(seconds=20), stale_after_s=300)}
    assert rows["a1"]["status"] == "online"

    rows = {r["agent_id"]: r for r in store.list_agents(now=NOW + timedelta(seconds=400), stale_after_s=300)}
    assert rows["a1"]["status"] == "stale"

    store.revoke("a1")
    rows = {r["agent_id"]: r for r in store.list_agents(now=NOW, stale_after_s=300)}
    assert rows["a1"]["status"] == "revoked"


# ---- gateway heartbeat + endpoints ----


def _gateway() -> tuple[TestClient, CA, InMemoryStore]:
    ca = CA.generate()
    store = InMemoryStore()
    app = build_gateway(
        AedConfig(enabled=True, trust_cert_header=True, admin_token=ADMIN),
        ca=ca,
        store=store,
        enroll_secret=SECRET,
    )
    return TestClient(app), ca, store


def _cert(ca: CA, agent_id: str) -> bytes:
    _k, csr = new_agent_csr(agent_id)
    return ca.sign_csr(csr, agent_id)


def _hdr(cert: bytes, seq: int, nonce: str) -> dict[str, str]:
    return {
        "X-AED-Client-Cert": base64.b64encode(cert).decode(),
        "X-AED-Seq": str(seq),
        "X-AED-Nonce": nonce,
    }


def test_heartbeat_updates_last_seen_and_requires_auth() -> None:
    c, ca, store = _gateway()
    store.register_agent("agent-h1", "fp", now=datetime.now(UTC))
    cert = _cert(ca, "agent-h1")
    # No creds -> 401.
    assert c.post("/aed/heartbeat", json={"version": "0.1"}).status_code == 401
    # Authenticated heartbeat -> 200, and the agent shows online.
    r = c.post("/aed/heartbeat", json={"version": "0.1"}, headers=_hdr(cert, 1, "n1"))
    assert r.status_code == 200
    r2 = c.get("/aed/endpoints", headers={"Authorization": f"Bearer {ADMIN}"})
    assert r2.status_code == 200
    rows = {row["agent_id"]: row for row in r2.json()["agents"]}
    assert rows["agent-h1"]["status"] == "online"


def test_endpoints_requires_admin_token() -> None:
    c, _ca, _store = _gateway()
    assert c.get("/aed/endpoints").status_code == 401  # no token
    assert c.get("/aed/endpoints", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert c.get("/aed/endpoints", headers={"Authorization": f"Bearer {ADMIN}"}).status_code == 200


def test_endpoints_503_when_admin_token_unset() -> None:
    ca = CA.generate()
    store = InMemoryStore()
    app = build_gateway(
        AedConfig(enabled=True, trust_cert_header=True), ca=ca, store=store, enroll_secret=SECRET
    )
    c = TestClient(app)
    assert c.get("/aed/endpoints", headers={"Authorization": "Bearer anything"}).status_code == 503


# ---- admin revoke ----


def test_revoke_requires_admin_token() -> None:
    c, _ca, store = _gateway()
    store.register_agent("agent-r1", "fp", now=NOW)
    assert c.post("/aed/agents/agent-r1/revoke").status_code == 401
    assert c.post("/aed/agents/agent-r1/revoke", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert not store.is_revoked("agent-r1")


def test_revoke_marks_agent_revoked_and_shows_in_registry() -> None:
    c, ca, store = _gateway()
    store.register_agent("agent-r2", "fp", now=NOW)
    r = c.post("/aed/agents/agent-r2/revoke", headers={"Authorization": f"Bearer {ADMIN}"})
    assert r.status_code == 200
    assert r.json() == {"revoked": "agent-r2"}
    assert store.is_revoked("agent-r2")
    rows = c.get("/aed/endpoints", headers={"Authorization": f"Bearer {ADMIN}"}).json()["agents"]
    row = {x["agent_id"]: x for x in rows}["agent-r2"]
    assert row["status"] == "revoked"
    # A revoked agent's certificate no longer authenticates ingest.
    cert = _cert(ca, "agent-r2")
    assert c.post("/aed/ingest", content=b'{"events":[]}', headers=_hdr(cert, 1, "n")).status_code == 401
