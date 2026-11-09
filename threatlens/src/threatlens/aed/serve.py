"""AED gateway serve entrypoint (lab only).

Builds the standalone gateway with a **persistent** CA (so the fingerprint the
agents pin is stable across restarts), an in-memory store, an in-memory event
store and the SSH brute-force rule, then runs uvicorn **bound to the lab
interface only**. Never mounted on the :8000 API.

Run: ``AED_GATEWAY_ENABLED=1 AED_SECRET_KEY=... python -m threatlens.aed.serve``
(usually via the opt-in ``aed-gateway`` compose service behind a TLS/mTLS
terminator — see ``docs/AED.md``).
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path

from fastapi import FastAPI

from .certs import CA
from .config import AedConfig
from .detect import SSHBruteForce
from .enroll import InMemoryStore
from .events import InMemoryEventStore
from .gateway import build_gateway


def _load_or_create_ca(ca_dir: str, secret: str) -> CA:
    """Load the CA from ``ca_dir`` or generate it on first run. The private key
    is sealed with ``secret`` and never written in clear; the cert is public."""
    d = Path(ca_dir)
    cert_p = d / "ca.crt"
    key_p = d / "ca.key.sealed"
    if cert_p.exists() and key_p.exists():
        return CA.load(cert_p.read_bytes(), key_p.read_bytes(), secret)
    d.mkdir(parents=True, exist_ok=True)
    ca = CA.generate()
    cert_p.write_bytes(ca.cert_pem())
    key_p.write_bytes(ca.seal_key(secret))
    for p in (key_p, cert_p):
        with contextlib.suppress(OSError):
            p.chmod(0o600)
    return ca


def create_gateway_app(config: AedConfig | None = None) -> FastAPI:
    """Wire a ready-to-serve gateway app. Needs ``AED_SECRET_KEY`` (or
    ``TL_SECRET_KEY``) to seal the CA key; raises if neither is set."""
    cfg = config or AedConfig.from_env()
    secret = os.environ.get("AED_SECRET_KEY") or os.environ.get("TL_SECRET_KEY")
    if not secret:
        raise RuntimeError("AED gateway needs AED_SECRET_KEY or TL_SECRET_KEY to seal the CA key")
    enroll_secret = os.environ.get("AED_ENROLL_SECRET") or secret
    ca = _load_or_create_ca(os.environ.get("AED_CA_DIR", "/var/lib/aed/ca"), secret)
    return build_gateway(
        cfg,
        ca=ca,
        store=InMemoryStore(),
        enroll_secret=enroll_secret,
        event_store=InMemoryEventStore(),
        rule=SSHBruteForce(),
    )


def main() -> None:  # pragma: no cover - thin uvicorn wrapper
    import uvicorn

    cfg = AedConfig.from_env()
    app = create_gateway_app(cfg)
    # Lab interface only. TLS + client-cert (mTLS) is terminated by a proxy in
    # front (docs/AED.md); set AED_TRUST_CERT_HEADER=1 behind it.
    uvicorn.run(app, host=cfg.bind_host, port=cfg.port, log_level="info")


if __name__ == "__main__":  # pragma: no cover
    main()
