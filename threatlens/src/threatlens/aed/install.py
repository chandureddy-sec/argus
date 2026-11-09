"""AED install-command generation (Linux).

Produces a self-contained command the operator pastes on a lab endpoint. It
downloads the agent to a file, verifies its SHA-256 and pins the CA fingerprint
before anything runs — never a blind ``curl | sh``. Config lands in a protected
(0700/0600) directory. The enrollment token is single-use and only exchanges for
a client certificate.
"""

from __future__ import annotations

import hashlib
from pathlib import Path


def agent_sha256(path: str) -> str:
    """SHA-256 (hex) of the agent binary the gateway serves."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def linux_install_command(*, advertise_url: str, token: str, ca_fingerprint: str, agent_sha256: str) -> str:
    """The paste-once Linux install command. Download → verify checksum → install
    the binary → the agent writes its own protected config + systemd unit and
    enrolls. No pipe-to-shell; HTTPS only."""
    url = advertise_url.rstrip("/")
    agent_url = f"{url}/aed/agent/linux"
    return "\n".join(
        [
            "set -eu",
            "umask 077",
            'D="$(mktemp -d)"',
            f'curl -fsSL --proto "=https" "{agent_url}" -o "$D/aed-agent"',
            f'echo "{agent_sha256}  $D/aed-agent" | sha256sum -c -',
            'sudo install -m 0755 -o root -g root "$D/aed-agent" /usr/local/bin/aed-agent',
            "sudo install -d -m 0700 /etc/aed-agent",
            (
                "sudo /usr/local/bin/aed-agent install"
                f' --gateway "{url}"'
                f' --ca-fingerprint "{ca_fingerprint}"'
                f' --token "{token}"'
                " --config /etc/aed-agent"
            ),
            "sudo chmod 600 /etc/aed-agent/agent.conf",
            'rm -rf "$D"',
        ]
    )
