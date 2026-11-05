"""AED Slice 2 — enrollment tokens, replay guard, revocation, enroll endpoint (tests first)."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from threatlens.aed.certs import CA, new_agent_csr
from threatlens.aed.config import AedConfig
from threatlens.aed.enroll import EnrollError, InMemoryStore, issue_token, redeem_token
from threatlens.aed.gateway import build_gateway

SECRET = "s" * 44
NOW = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)


# ---- tokens: single-use, expiry, unknown ----


def test_token_issue_then_redeem_once() -> None:
    store = InMemoryStore()
    tok = issue_token(store, SECRET, ttl_s=900, now=NOW)
    redeem_token(store, SECRET, tok, now=NOW)  # first use OK


def test_token_reuse_is_rejected() -> None:
    store = InMemoryStore()
    tok = issue_token(store, SECRET, ttl_s=900, now=NOW)
    redeem_token(store, SECRET, tok, now=NOW)
    with pytest.raises(EnrollError):
        redeem_token(store, SECRET, tok, now=NOW)  # reuse


def test_token_expired_is_rejected() -> None:
    store = InMemoryStore()
    tok = issue_token(store, SECRET, ttl_s=900, now=NOW)
    with pytest.raises(EnrollError):
        redeem_token(store, SECRET, tok, now=NOW + timedelta(seconds=901))


def test_token_unknown_is_rejected() -> None:
    store = InMemoryStore()
    with pytest.raises(EnrollError):
        redeem_token(store, SECRET, "not-a-real-token", now=NOW)


def test_token_wrong_secret_is_rejected() -> None:
    store = InMemoryStore()
    tok = issue_token(store, SECRET, ttl_s=900, now=NOW)
    with pytest.raises(EnrollError):
        redeem_token(store, "other-secret" + "x" * 30, tok, now=NOW)


# ---- replay guard: sequence + nonce ----


def test_replay_sequence_and_nonce() -> None:
    store = InMemoryStore()
    assert store.replay_accept("a1", seq=1, nonce="n1", now=NOW) is True
    assert store.replay_accept("a1", seq=1, nonce="n2", now=NOW) is False  # seq not advancing
    assert store.replay_accept("a1", seq=0, nonce="n3", now=NOW) is False  # lower seq
    assert store.replay_accept("a1", seq=2, nonce="n1", now=NOW) is False  # duplicate nonce
    assert store.replay_accept("a1", seq=2, nonce="n4", now=NOW) is True  # advance + new nonce
    # Per-agent isolation: a different agent starts fresh.
    assert store.replay_accept("a2", seq=1, nonce="n1", now=NOW) is True


# ---- revocation ----


def test_revocation() -> None:
    store = InMemoryStore()
    assert store.is_revoked("a1") is False
    store.revoke("a1")
    assert store.is_revoked("a1") is True


# ---- enroll endpoint ----


def _gateway(enabled: bool = True) -> tuple[TestClient, CA, InMemoryStore]:
    ca = CA.generate()
    store = InMemoryStore()
    app = build_gateway(AedConfig(enabled=enabled), ca=ca, store=store, enroll_secret=SECRET)
    return TestClient(app), ca, store


def test_enroll_endpoint_issues_cert_and_token_is_single_use() -> None:
    client, ca, store = _gateway()
    tok = issue_token(store, SECRET, ttl_s=900, now=datetime.now(UTC))
    _key, csr = new_agent_csr("agent-e1")
    body = {"token": tok, "csr_pem": csr.decode(), "agent_id": "agent-e1"}
    r = client.post("/aed/enroll", json=body)
    assert r.status_code == 200, r.text
    cert_pem = r.json()["cert_pem"].encode()
    assert ca.verify(cert_pem, now=datetime.now(UTC), is_revoked=store.is_revoked) == "agent-e1"
    # Same token cannot be used again.
    r2 = client.post("/aed/enroll", json=body)
    assert r2.status_code == 401


def test_enroll_disabled_returns_503() -> None:
    client, _ca, store = _gateway(enabled=False)
    tok = issue_token(store, SECRET, ttl_s=900, now=datetime.now(UTC))
    _key, csr = new_agent_csr("agent-e2")
    r = client.post("/aed/enroll", json={"token": tok, "csr_pem": csr.decode(), "agent_id": "agent-e2"})
    assert r.status_code == 503


def test_enroll_bad_token_returns_401() -> None:
    client, _ca, _store = _gateway()
    _key, csr = new_agent_csr("agent-e3")
    r = client.post("/aed/enroll", json={"token": "nope", "csr_pem": csr.decode(), "agent_id": "agent-e3"})
    assert r.status_code == 401


# ---- no secrets in logs ----


def test_no_token_or_key_in_logs(caplog: pytest.LogCaptureFixture) -> None:
    store = InMemoryStore()
    with caplog.at_level(logging.DEBUG):
        tok = issue_token(store, SECRET, ttl_s=900, now=NOW)
        redeem_token(store, SECRET, tok, now=NOW)
        ca = CA.generate()
        sealed = ca.seal_key(SECRET)
    text = caplog.text
    assert tok not in text, "enrollment token leaked into logs"
    assert SECRET not in text, "secret leaked into logs"
    assert "PRIVATE KEY" not in text, "key material leaked into logs"
    assert sealed.decode(errors="ignore") not in text
