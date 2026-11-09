"""AED onboarding — minting an enrollment token (tests first).

An admin asks the gateway for a single-use, short-lived (15 min) enrollment
token for a chosen OS. The gateway returns the token *once* (plaintext), the CA
fingerprint the agent will pin, and the expiry. Only the token's HMAC is stored;
the plaintext is never logged. The returned token redeems exactly once.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from threatlens.aed.certs import CA
from threatlens.aed.config import AedConfig
from threatlens.aed.enroll import EnrollError, InMemoryStore, redeem_token
from threatlens.aed.gateway import build_gateway

SECRET = "s" * 44
ADMIN = "a" * 32


def _client(
    *, with_ca: bool = True, with_secret: bool = True, admin: str = ADMIN
) -> tuple[TestClient, InMemoryStore]:
    store = InMemoryStore()
    ca = CA.generate() if with_ca else None
    app = build_gateway(
        AedConfig(enabled=True, admin_token=admin),
        ca=ca,
        store=store,
        enroll_secret=SECRET if with_secret else None,
    )
    return TestClient(app), store


def _h(token: str = ADMIN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_mint_requires_admin() -> None:
    c, _ = _client()
    assert c.post("/aed/enrollments", json={"os": "linux"}).status_code == 401
    assert c.post("/aed/enrollments", json={"os": "linux"}, headers=_h("wrong")).status_code == 401


def test_mint_503_when_admin_not_configured() -> None:
    c, _ = _client(admin="")
    assert c.post("/aed/enrollments", json={"os": "linux"}, headers=_h()).status_code == 503


def test_mint_503_when_enrollment_not_configured() -> None:
    c, _ = _client(with_ca=False)
    assert c.post("/aed/enrollments", json={"os": "linux"}, headers=_h()).status_code == 503
    c2, _ = _client(with_secret=False)
    assert c2.post("/aed/enrollments", json={"os": "linux"}, headers=_h()).status_code == 503


def test_mint_returns_single_use_15min_token_and_ca_fingerprint() -> None:
    c, store = _client()
    r = c.post("/aed/enrollments", json={"os": "linux", "name": "lab-vm-1", "group": "lab"}, headers=_h())
    assert r.status_code == 200
    body = r.json()
    token = body["token"]
    assert isinstance(token, str)
    assert token
    assert len(bytes.fromhex(body["ca_fingerprint"])) == 32  # sha-256 hex
    # expiry is ~15 min out
    exp = datetime.fromisoformat(body["expires_at"])
    secs = (exp - datetime.now(UTC)).total_seconds()
    assert 840 <= secs <= 900  # 15 min, minus test slack
    # single use: redeems once, then rejected
    redeem_token(store, SECRET, token)
    try:
        redeem_token(store, SECRET, token)
    except EnrollError:
        pass
    else:
        raise AssertionError("token redeemed twice")


def test_mint_rejects_unknown_os() -> None:
    c, _ = _client()
    assert c.post("/aed/enrollments", json={"os": "solaris"}, headers=_h()).status_code == 422


def test_mint_stores_only_hash_and_metadata() -> None:
    c, store = _client()
    r = c.post("/aed/enrollments", json={"os": "linux", "name": "lab-vm-9", "group": "red"}, headers=_h())
    token = r.json()["token"]
    # the plaintext token is not stored anywhere in the store
    assert token not in repr(store.__dict__)
    pend = store.pending_enrollments(datetime.now(UTC))
    assert len(pend) == 1
    assert pend[0]["os"] == "linux"
    assert pend[0]["name"] == "lab-vm-9"
    assert pend[0]["group"] == "red"


def test_mint_never_logs_the_token(caplog: pytest.LogCaptureFixture) -> None:
    c, _ = _client()
    with caplog.at_level(logging.DEBUG):
        token = c.post("/aed/enrollments", json={"os": "linux"}, headers=_h()).json()["token"]
    assert token not in caplog.text
