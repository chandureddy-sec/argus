"""AED gateway serve entrypoint (tests first).

The factory wires a working gateway with a persistent CA sealed by the secret,
and refuses to start without a secret.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from threatlens.aed.config import AedConfig
from threatlens.aed.serve import _load_or_create_ca, create_gateway_app

SECRET = "x" * 44
ADMIN = "a" * 32


def _cfg() -> AedConfig:
    return AedConfig(enabled=True, admin_token=ADMIN, advertise_url="https://10.0.0.5:8443")


def test_factory_builds_a_working_gateway(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("AED_SECRET_KEY", SECRET)
    monkeypatch.setenv("AED_CA_DIR", str(tmp_path / "ca"))
    app = create_gateway_app(_cfg())
    paths = {getattr(r, "path", "") for r in app.routes}
    assert {"/aed/healthz", "/aed/enrollments", "/aed/agent/linux", "/aed/ingest"} <= paths
    c = TestClient(app)
    assert c.get("/aed/healthz").status_code == 200
    # the wired enrollment path works end to end (admin mints a token)
    r = c.post("/aed/enrollments", json={"os": "linux"}, headers={"Authorization": f"Bearer {ADMIN}"})
    assert r.status_code == 200
    assert len(bytes.fromhex(r.json()["ca_fingerprint"])) == 32


def test_ca_persists_across_restarts(tmp_path: Path) -> None:
    ca_dir = str(tmp_path / "ca")
    first = _load_or_create_ca(ca_dir, SECRET)
    second = _load_or_create_ca(ca_dir, SECRET)  # "restart": load, don't regenerate
    assert first.fingerprint() == second.fingerprint()
    # the sealed key on disk is not the plaintext PEM
    sealed = (Path(ca_dir) / "ca.key.sealed").read_bytes()
    assert b"PRIVATE KEY" not in sealed


def test_factory_requires_a_secret(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("AED_SECRET_KEY", raising=False)
    monkeypatch.delenv("TL_SECRET_KEY", raising=False)
    monkeypatch.setenv("AED_CA_DIR", str(tmp_path / "ca"))
    with pytest.raises(RuntimeError):
        create_gateway_app(_cfg())
