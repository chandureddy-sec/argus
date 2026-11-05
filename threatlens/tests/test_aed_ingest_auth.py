"""AED Slice 2 — ingest authentication over the (terminator-forwarded) client cert."""

from __future__ import annotations

import base64

from fastapi.testclient import TestClient

from threatlens.aed.certs import CA, new_agent_csr
from threatlens.aed.config import AedConfig
from threatlens.aed.enroll import InMemoryStore
from threatlens.aed.gateway import build_gateway

SECRET = "s" * 44
BODY = b'{"events":[]}'


def _setup() -> tuple[TestClient, CA, InMemoryStore]:
    ca = CA.generate()
    store = InMemoryStore()
    app = build_gateway(
        AedConfig(enabled=True, trust_cert_header=True), ca=ca, store=store, enroll_secret=SECRET
    )
    return TestClient(app), ca, store


def _cert_for(ca: CA, agent_id: str) -> bytes:
    _key, csr = new_agent_csr(agent_id)
    return ca.sign_csr(csr, agent_id)


def _hdr(cert_pem: bytes, seq: int, nonce: str) -> dict[str, str]:
    return {
        "X-AED-Client-Cert": base64.b64encode(cert_pem).decode(),
        "X-AED-Seq": str(seq),
        "X-AED-Nonce": nonce,
    }


def test_ingest_with_valid_cert_accepted() -> None:
    c, ca, _store = _setup()
    r = c.post("/aed/ingest", content=BODY, headers=_hdr(_cert_for(ca, "agent-i1"), 1, "n1"))
    assert r.status_code == 202, r.text


def test_ingest_foreign_cert_rejected() -> None:
    c, _ca, _store = _setup()
    foreign = _cert_for(CA.generate(), "agent-i2")  # signed by a different CA
    r = c.post("/aed/ingest", content=BODY, headers=_hdr(foreign, 1, "n1"))
    assert r.status_code == 401


def test_ingest_revoked_agent_rejected() -> None:
    c, ca, store = _setup()
    cert = _cert_for(ca, "agent-i3")
    store.revoke("agent-i3")
    r = c.post("/aed/ingest", content=BODY, headers=_hdr(cert, 1, "n1"))
    assert r.status_code == 401


def test_ingest_replayed_sequence_rejected() -> None:
    c, ca, _store = _setup()
    cert = _cert_for(ca, "agent-i4")
    assert c.post("/aed/ingest", content=BODY, headers=_hdr(cert, 5, "n1")).status_code == 202
    assert c.post("/aed/ingest", content=BODY, headers=_hdr(cert, 5, "n2")).status_code == 409


def test_ingest_duplicate_nonce_rejected() -> None:
    c, ca, _store = _setup()
    cert = _cert_for(ca, "agent-i5")
    assert c.post("/aed/ingest", content=BODY, headers=_hdr(cert, 1, "dup")).status_code == 202
    assert c.post("/aed/ingest", content=BODY, headers=_hdr(cert, 2, "dup")).status_code == 409


def test_ingest_missing_credentials_rejected() -> None:
    c, _ca, _store = _setup()
    r = c.post("/aed/ingest", content=BODY)  # no cert/seq/nonce headers
    assert r.status_code == 401
