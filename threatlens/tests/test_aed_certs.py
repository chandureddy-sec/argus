"""AED Slice 2 — CA / client-cert issuance and verification (tests first)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from threatlens.aed.certs import CA, CertError, new_agent_csr


def test_ca_signs_csr_and_verify_returns_agent_id() -> None:
    ca = CA.generate()
    _key_pem, csr_pem = new_agent_csr("agent-001")
    cert_pem = ca.sign_csr(csr_pem, "agent-001", days=90)
    agent_id = ca.verify(cert_pem, now=datetime.now(UTC), is_revoked=lambda _a: False)
    assert agent_id == "agent-001"


def test_foreign_cert_is_rejected() -> None:
    ours = CA.generate()
    other = CA.generate()
    _k, csr = new_agent_csr("agent-x")
    foreign_cert = other.sign_csr(csr, "agent-x", days=90)
    with pytest.raises(CertError):
        ours.verify(foreign_cert, now=datetime.now(UTC), is_revoked=lambda _a: False)


def test_expired_cert_is_rejected() -> None:
    ca = CA.generate()
    _k, csr = new_agent_csr("agent-exp")
    # Issue a cert that is already expired.
    cert = ca.sign_csr(csr, "agent-exp", days=1)
    future = datetime.now(UTC) + timedelta(days=2)
    with pytest.raises(CertError):
        ca.verify(cert, now=future, is_revoked=lambda _a: False)


def test_not_yet_valid_cert_is_rejected() -> None:
    ca = CA.generate()
    _k, csr = new_agent_csr("agent-future")
    cert = ca.sign_csr(csr, "agent-future", days=90)
    past = datetime.now(UTC) - timedelta(days=1)
    with pytest.raises(CertError):
        ca.verify(cert, now=past, is_revoked=lambda _a: False)


def test_revoked_agent_is_rejected() -> None:
    ca = CA.generate()
    _k, csr = new_agent_csr("agent-revoked")
    cert = ca.sign_csr(csr, "agent-revoked", days=90)
    with pytest.raises(CertError):
        ca.verify(cert, now=datetime.now(UTC), is_revoked=lambda a: a == "agent-revoked")


def test_ca_key_seal_roundtrip_and_not_cleartext() -> None:
    # The CA private key must be storable encrypted (sealed) and unreadable raw.
    ca = CA.generate()
    secret = "a" * 44  # any non-empty secret
    sealed = ca.seal_key(secret)
    assert b"PRIVATE KEY" not in sealed  # sealed blob is not a raw PEM
    restored = CA.load(ca.cert_pem(), sealed, secret)
    # The restored CA signs a cert that the original verifies.
    _k, csr = new_agent_csr("agent-roundtrip")
    cert = restored.sign_csr(csr, "agent-roundtrip", days=90)
    assert ca.verify(cert, now=datetime.now(UTC), is_revoked=lambda _a: False) == "agent-roundtrip"
