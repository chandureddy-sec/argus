"""AED Slice 5 — redaction, event store, and the SSH-brute-force detection rule (tests first)."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from threatlens.aed.certs import CA, new_agent_csr
from threatlens.aed.config import AedConfig
from threatlens.aed.detect import SSHBruteForce
from threatlens.aed.enroll import InMemoryStore
from threatlens.aed.events import InMemoryEventStore
from threatlens.aed.gateway import build_gateway
from threatlens.aed.redact import redact_event

SECRET = "s" * 44
ADMIN = "admin-tok"
NOW = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)


def _ssh_fail(agent_id: str, src_ip: str, user: str = "root", raw_extra: str = "") -> dict:
    return {
        "class_uid": 3002,
        "time": NOW.isoformat(),
        "agent_id": agent_id,
        "ocsf_version": "1.1.0",
        "fields": {"activity": "logon", "status": "failure", "src_ip": src_ip, "user": user, "hostname": "h"},
        "raw": f'{{"MESSAGE":"Failed password for {user} from {src_ip} port 22{raw_extra}"}}',
    }


# ---- redaction ----


def test_redaction_hashes_username_and_strips_secrets() -> None:
    ev = _ssh_fail("a1", "203.0.113.5", user="alice", raw_extra=" token=SECRET123 Authorization: Bearer abc")
    out = redact_event(ev, SECRET)
    assert "user" not in out["fields"], "cleartext username must be removed"
    assert out["fields"]["user_hash"]
    assert out["fields"]["user_hash"] != "alice"
    assert "SECRET123" not in out["raw"], "secret in raw not redacted"
    assert "Bearer abc" not in out["raw"]
    assert "[REDACTED]" in out["raw"]
    # The same username always hashes the same (stable correlation).
    again = redact_event(_ssh_fail("a1", "x", user="alice"), SECRET)
    assert again["fields"]["user_hash"] == out["fields"]["user_hash"]


# ---- event store ----


def test_event_store_recent_failed_grouping_and_window() -> None:
    store = InMemoryEventStore()
    store.store([_ssh_fail("a1", "10.0.0.1") for _ in range(3)], now=NOW)
    store.store([_ssh_fail("a1", "10.0.0.2")], now=NOW)
    # Old event outside the window is excluded.
    store.store([_ssh_fail("a1", "10.0.0.1")], now=NOW - timedelta(seconds=1000))
    recent = store.recent_failed("a1", "10.0.0.1", now=NOW, window_s=300)
    assert len(recent) == 3


# ---- detection rule ----


def test_ssh_bruteforce_fires_above_threshold_with_evidence() -> None:
    store = InMemoryEventStore()
    rule = SSHBruteForce(threshold=10, window_s=300, cooldown_s=600)
    store.store([_ssh_fail("a1", "198.51.100.7") for _ in range(10)], now=NOW)
    alert = rule.evaluate(store, "a1", "198.51.100.7", now=NOW)
    assert alert is not None
    assert alert["rule"] == "ssh_bruteforce"
    assert alert["src_ip"] == "198.51.100.7"
    assert alert["count"] >= 10
    assert alert["severity"] in ("medium", "high")
    assert 0.0 <= alert["confidence"] <= 1.0
    assert alert["evidence"]
    assert alert["fp_guidance"]


def test_ssh_bruteforce_below_threshold_is_silent() -> None:
    store = InMemoryEventStore()
    rule = SSHBruteForce(threshold=10, window_s=300)
    store.store([_ssh_fail("a1", "198.51.100.8") for _ in range(9)], now=NOW)
    assert rule.evaluate(store, "a1", "198.51.100.8", now=NOW) is None


def test_ssh_bruteforce_cooldown_prevents_duplicate_alerts() -> None:
    store = InMemoryEventStore()
    rule = SSHBruteForce(threshold=10, window_s=300, cooldown_s=600)
    store.store([_ssh_fail("a1", "198.51.100.9") for _ in range(10)], now=NOW)
    assert rule.evaluate(store, "a1", "198.51.100.9", now=NOW) is not None
    store.store([_ssh_fail("a1", "198.51.100.9") for _ in range(10)], now=NOW + timedelta(seconds=60))
    # Within cooldown -> no second alert.
    assert rule.evaluate(store, "a1", "198.51.100.9", now=NOW + timedelta(seconds=60)) is None


# ---- gateway ingest -> store -> detect -> /aed/alerts ----


def _gateway() -> tuple[TestClient, CA, InMemoryStore, InMemoryEventStore]:
    ca = CA.generate()
    store = InMemoryStore()
    events = InMemoryEventStore()
    app = build_gateway(
        AedConfig(enabled=True, trust_cert_header=True, admin_token=ADMIN),
        ca=ca,
        store=store,
        enroll_secret=SECRET,
        event_store=events,
        rule=SSHBruteForce(threshold=10, window_s=300),
    )
    return TestClient(app), ca, store, events


def _hdr(ca: CA, agent_id: str, seq: int, nonce: str) -> dict[str, str]:
    _k, csr = new_agent_csr(agent_id)
    cert = ca.sign_csr(csr, agent_id)
    return {
        "X-AED-Client-Cert": base64.b64encode(cert).decode(),
        "X-AED-Seq": str(seq),
        "X-AED-Nonce": nonce,
    }


def test_ingest_stores_and_raises_alert() -> None:
    c, ca, _store, _events = _gateway()
    batch = {"events": [_ssh_fail("agent-s1", "192.0.2.50") for _ in range(10)]}
    r = c.post("/aed/ingest", json=batch, headers=_hdr(ca, "agent-s1", 1, "n1"))
    assert r.status_code == 202, r.text
    alerts = c.get("/aed/alerts", headers={"Authorization": f"Bearer {ADMIN}"})
    assert alerts.status_code == 200
    rows = alerts.json()["alerts"]
    assert len(rows) == 1
    assert rows[0]["src_ip"] == "192.0.2.50"
    assert rows[0]["agent_id"] == "agent-s1"


def test_ingest_tags_events_with_authenticated_agent_not_spoofed() -> None:
    c, ca, _store, events = _gateway()
    # The agent authenticates as agent-real but claims agent-spoof in the payload.
    spoof = [_ssh_fail("agent-spoof", "192.0.2.77")]
    r = c.post("/aed/ingest", json={"events": spoof}, headers=_hdr(ca, "agent-real", 1, "n1"))
    assert r.status_code == 202
    stored = events.recent_failed("agent-real", "192.0.2.77", now=datetime.now(UTC), window_s=300)
    assert len(stored) == 1, "event must be attributed to the authenticated agent"
    assert not events.recent_failed("agent-spoof", "192.0.2.77", now=datetime.now(UTC), window_s=300)


def test_alerts_requires_admin_token() -> None:
    c, _ca, _store, _events = _gateway()
    assert c.get("/aed/alerts").status_code == 401
    assert c.get("/aed/alerts", headers={"Authorization": f"Bearer {ADMIN}"}).status_code == 200
