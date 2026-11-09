"""AED gateway configuration (Slice 1).

Separate from the product settings so AED can be enabled/disabled on its own.
The gateway is disabled by default; it only listens for agents when
``AED_GATEWAY_ENABLED`` is explicitly true.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


def _bool(name: str, default: bool) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class AedConfig:
    """Gateway limits and the enable switch."""

    enabled: bool = False
    port: int = 8443
    max_batch_bytes: int = 1 * 1024 * 1024  # hard cap per ingest batch (1 MiB)
    rate_limit_per_min: int = 120  # per-agent ingest/enroll calls per minute
    request_timeout_s: float = 10.0  # read/write timeout the server enforces
    # Trust a TLS-terminating proxy to forward the *verified* client cert in the
    # X-AED-Client-Cert header (base64 PEM), e.g. nginx $ssl_client_escaped_cert.
    # SECURITY: only enable behind such a terminator; never expose the gateway
    # directly with this on, or a client could present any certificate.
    trust_cert_header: bool = False
    # Bearer token for the admin read endpoints (e.g. /aed/endpoints). Empty =
    # those endpoints return 503 (not configured). The analyst UI on :8000 holds
    # this token server-side; it is never exposed to agents.
    admin_token: str = ""
    # An agent is "online" if its last heartbeat is within this many seconds.
    heartbeat_stale_s: int = 300
    # The gateway address advertised to endpoints (e.g. https://10.0.0.5:8443) —
    # the lab IP endpoints reach the gateway on. Put in the install command.
    advertise_url: str = ""
    # Interface the gateway binds to. Default loopback; set to the lab interface
    # IP only. NEVER 0.0.0.0 on a company network — serve lab VMs only.
    bind_host: str = "127.0.0.1"
    # Filesystem path to the prebuilt Linux agent the gateway serves at
    # /aed/agent/linux. Empty = agent download disabled (503).
    agent_path: str = ""

    @classmethod
    def from_env(cls) -> AedConfig:
        return cls(
            enabled=_bool("AED_GATEWAY_ENABLED", False),
            port=int(os.environ.get("AED_GATEWAY_PORT", "8443")),
            max_batch_bytes=int(os.environ.get("AED_MAX_BATCH_BYTES", str(1 * 1024 * 1024))),
            rate_limit_per_min=int(os.environ.get("AED_RATE_LIMIT_PER_MIN", "120")),
            request_timeout_s=float(os.environ.get("AED_REQUEST_TIMEOUT_S", "10.0")),
            trust_cert_header=_bool("AED_TRUST_CERT_HEADER", False),
            admin_token=os.environ.get("AED_ADMIN_TOKEN", ""),
            heartbeat_stale_s=int(os.environ.get("AED_HEARTBEAT_STALE_S", "300")),
            advertise_url=os.environ.get("AED_ADVERTISE_URL", ""),
            bind_host=os.environ.get("AED_BIND_HOST", "127.0.0.1"),
            agent_path=os.environ.get("AED_AGENT_PATH", ""),
        )
