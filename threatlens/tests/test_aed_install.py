"""AED install flow — gateway serves the agent, mint returns a safe install
command (tests first).

Safety rails the command must satisfy:
- download the agent to a file, then verify its SHA-256 before running it
  (no `curl | sh` / `curl | bash`);
- pin the CA fingerprint so the agent verifies the server;
- write config to a protected (0600) directory.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from fastapi.testclient import TestClient

from threatlens.aed.certs import CA
from threatlens.aed.config import AedConfig
from threatlens.aed.enroll import InMemoryStore
from threatlens.aed.gateway import build_gateway
from threatlens.aed.install import linux_install_command

SECRET = "s" * 44
ADMIN = "a" * 32
AGENT_BYTES = b"\x7fELF fake-agent-binary for tests"


def _setup(tmp_path: Path, *, serve: bool = True) -> tuple[TestClient, str]:
    binpath = tmp_path / "aed-agent"
    binpath.write_bytes(AGENT_BYTES)
    cfg = AedConfig(
        enabled=True,
        admin_token=ADMIN,
        advertise_url="https://10.0.0.5:8443",
        agent_path=str(binpath) if serve else "",
    )
    app = build_gateway(cfg, ca=CA.generate(), store=InMemoryStore(), enroll_secret=SECRET)
    return TestClient(app), str(binpath)


def _h() -> dict[str, str]:
    return {"Authorization": f"Bearer {ADMIN}"}


def test_gateway_serves_the_agent_binary(tmp_path: Path) -> None:
    c, _ = _setup(tmp_path)
    r = c.get("/aed/agent/linux")
    assert r.status_code == 200
    assert r.content == AGENT_BYTES


def test_agent_download_503_when_not_configured(tmp_path: Path) -> None:
    c, _ = _setup(tmp_path, serve=False)
    assert c.get("/aed/agent/linux").status_code == 503


def test_mint_returns_install_command_and_verified_sha(tmp_path: Path) -> None:
    c, _ = _setup(tmp_path)
    r = c.post("/aed/enrollments", json={"os": "linux", "name": "vm1"}, headers=_h())
    assert r.status_code == 200
    body = r.json()
    assert body["agent_sha256"] == hashlib.sha256(AGENT_BYTES).hexdigest()
    assert body["agent_url"] == "https://10.0.0.5:8443/aed/agent/linux"
    cmd = body["install"]
    # downloads to a file and checks the sha BEFORE running it
    assert "sha256sum -c" in cmd
    assert body["agent_sha256"] in cmd
    assert "/aed/agent/linux" in cmd
    # pins the CA fingerprint
    assert body["ca_fingerprint"] in cmd
    # no blind pipe-to-shell (|sha256sum is fine; |sh / |bash are not)
    assert re.search(r"\|\s*(sh|bash)\b", cmd) is None
    # single-use token present (used once to enroll)
    assert body["token"] in cmd


def test_install_command_writes_protected_config() -> None:
    cmd = linux_install_command(
        advertise_url="https://10.0.0.5:8443",
        token="tok123",  # noqa: S106
        ca_fingerprint="ab" * 32,
        agent_sha256="cd" * 32,
    )
    # a protected config dir/file (0600/0700) is created
    assert "0600" in cmd or "0700" in cmd or "chmod 600" in cmd
    assert "sha256sum -c" in cmd
    assert re.search(r"\|\s*(sh|bash)\b", cmd) is None
