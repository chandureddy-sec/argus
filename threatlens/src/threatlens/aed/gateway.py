"""AED gateway skeleton (Slice 1).

A standalone FastAPI app for agent traffic. It is **not** mounted on the main
ThreatLens API (:8000); it is built here and would be served as its own process
on :8443. Slice 1 provides the shape and the safety rails — disabled-by-default,
an auth hook, a rate limiter, a payload-size cap and JSON validation — but no
storage, schema or detection yet.

- **Auth:** ``require_agent`` denies by default. Mutual-TLS client-certificate
  auth lands in Slice 2; tests override this dependency to simulate an agent.
- **Enable switch:** ingest refuses with 503 until ``AedConfig.enabled`` is true.
- **Rate limit:** an in-memory token bucket per agent (Redis-backed later).
- **Size cap / validation:** oversized batches → 413; non-JSON → 400.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import time
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from . import install
from .certs import CA, CertError
from .config import AedConfig
from .detect import SSHBruteForce
from .enroll import EnrollError, EnrollmentStore, issue_token, redeem_token
from .events import EventStore
from .redact import redact_event


class EnrollRequest(BaseModel):
    token: str
    csr_pem: str
    agent_id: str


ENROLL_TTL_S = 900  # 15-minute single-use enrollment token


class EnrollMintRequest(BaseModel):
    """An admin's request to onboard an endpoint: which OS, optional label."""

    os: Literal["linux", "windows"]
    name: str | None = None
    group: str | None = None


class HeartbeatRequest(BaseModel):
    version: str = ""
    agent_time: str | None = None


class RateLimiter:
    """A simple per-key token bucket for Slice 1 (single-process, in-memory).

    Redis-backed limiting arrives when the gateway runs for real; the interface
    stays the same so callers do not change.
    """

    def __init__(self, per_min: int) -> None:
        self.capacity = float(per_min)
        self.rate = per_min / 60.0  # tokens per second
        self._tokens: dict[str, float] = defaultdict(lambda: float(per_min))
        self._last: dict[str, float] = defaultdict(time.monotonic)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        self._tokens[key] = min(self.capacity, self._tokens[key] + (now - self._last[key]) * self.rate)
        self._last[key] = now
        if self._tokens[key] >= 1.0:
            self._tokens[key] -= 1.0
            return True
        return False


class Agent:
    """The authenticated agent identity. Populated by mTLS in Slice 2."""

    def __init__(self, agent_id: str) -> None:
        self.agent_id = agent_id


class ReplayError(Exception):
    """A batch was replayed or arrived out of order (seq/nonce)."""


async def require_agent() -> Agent:
    """Strict auth hook. Denies by default; ``build_gateway`` replaces it with
    cert-based auth when a CA + store are configured. Tests may override it."""
    raise HTTPException(status_code=401, detail="agent authentication required")


def authenticate(
    ca: CA, store: EnrollmentStore, cert_pem: bytes, seq: int, nonce: str, now: datetime
) -> Agent:
    """Verify a client cert and enforce replay protection; return the Agent.

    Raises :class:`CertError` (bad/expired/revoked cert) or :class:`ReplayError`
    (replayed or out-of-order batch)."""
    agent_id = ca.verify(cert_pem, now, store.is_revoked)
    if not store.replay_accept(agent_id, seq, nonce, now):
        raise ReplayError("replayed or out-of-order batch")
    return Agent(agent_id)


async def _cert_agent(request: Request) -> Agent:
    """Dependency: authenticate the agent from the verified client cert forwarded
    by the TLS terminator (``X-AED-Client-Cert``, base64 PEM) plus seq/nonce."""
    cfg: AedConfig = request.app.state.aed_config
    ca: CA | None = getattr(request.app.state, "aed_ca", None)
    store: EnrollmentStore | None = getattr(request.app.state, "aed_store", None)
    if not (cfg.trust_cert_header and ca and store):
        raise HTTPException(status_code=401, detail="mTLS not configured")
    raw = request.headers.get("x-aed-client-cert")
    seq = request.headers.get("x-aed-seq")
    nonce = request.headers.get("x-aed-nonce")
    if not raw or seq is None or not nonce:
        raise HTTPException(status_code=401, detail="missing client credentials")
    try:
        cert_pem = base64.b64decode(raw)
        seq_i = int(seq)
    except (binascii.Error, ValueError) as e:
        raise HTTPException(status_code=400, detail="bad client credentials") from e
    try:
        return authenticate(ca, store, cert_pem, seq_i, nonce, datetime.now(UTC))
    except CertError as e:
        raise HTTPException(status_code=401, detail="client certificate rejected") from e
    except ReplayError as e:
        raise HTTPException(status_code=409, detail="replayed or out-of-order batch") from e


def build_gateway(
    config: AedConfig | None = None,
    *,
    ca: CA | None = None,
    store: EnrollmentStore | None = None,
    enroll_secret: str | None = None,
    event_store: EventStore | None = None,
    rule: SSHBruteForce | None = None,
    limiter: RateLimiter | None = None,
) -> FastAPI:
    """Build the standalone AED gateway app. Never mounted on the :8000 API.

    ``ca``/``store``/``enroll_secret`` enable enrollment; when absent, ``/aed/enroll``
    returns 503 ("not configured"). The real wiring reads ``TL_SECRET_KEY`` and a
    persistent store at the serve entrypoint.
    """
    cfg = config or AedConfig.from_env()
    rl = limiter or RateLimiter(cfg.rate_limit_per_min)
    # The served agent's checksum, computed once at startup (the binary is fixed),
    # so the async request handlers do no blocking filesystem work.
    agent_sha: str | None = (
        install.agent_sha256(cfg.agent_path) if cfg.agent_path and os.path.exists(cfg.agent_path) else None
    )

    # No docs/openapi surface for the agent-facing gateway.
    app = FastAPI(title="AED gateway", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.aed_config = cfg
    app.state.aed_ca = ca
    app.state.aed_store = store
    # When a CA + store are configured and a trusted TLS terminator forwards the
    # client cert, ingest authenticates with the real cert + replay check.
    if ca is not None and store is not None and cfg.trust_cert_header:
        app.dependency_overrides[require_agent] = _cert_agent

    @app.get("/aed/healthz")
    async def healthz() -> dict[str, object]:
        return {"status": "ok", "component": "aed-gateway", "enabled": cfg.enabled}

    @app.get("/aed/agent/linux")
    async def agent_linux() -> FileResponse:
        # Serve the prebuilt Linux agent. Integrity is the operator's to check:
        # the install command verifies this file's SHA-256 before running it.
        if agent_sha is None:
            raise HTTPException(status_code=503, detail="agent download not configured")
        return FileResponse(cfg.agent_path, media_type="application/octet-stream", filename="aed-agent")

    @app.post("/aed/enroll")
    async def enroll(req: EnrollRequest) -> JSONResponse:
        if not cfg.enabled:
            raise HTTPException(status_code=503, detail="AED gateway disabled")
        if ca is None or store is None or not enroll_secret:
            raise HTTPException(status_code=503, detail="AED enrollment not configured")
        try:
            redeem_token(store, enroll_secret, req.token)
        except EnrollError as e:
            raise HTTPException(status_code=401, detail="enrollment token rejected") from e
        try:
            cert_pem = ca.sign_csr(req.csr_pem.encode(), req.agent_id)
        except (CertError, ValueError) as e:
            raise HTTPException(status_code=400, detail="invalid CSR") from e
        store.register_agent(req.agent_id, hashlib.sha256(cert_pem).hexdigest(), datetime.now(UTC))
        return JSONResponse(
            status_code=200,
            content={"cert_pem": cert_pem.decode(), "ca_pem": ca.cert_pem().decode()},
        )

    @app.post("/aed/heartbeat")
    async def heartbeat_endpoint(
        _req: HeartbeatRequest,
        agent: Annotated[Agent, Depends(require_agent)],
    ) -> dict[str, object]:
        if not cfg.enabled:
            raise HTTPException(status_code=503, detail="AED gateway disabled")
        if store is None:
            raise HTTPException(status_code=503, detail="AED store not configured")
        store.heartbeat(agent.agent_id, datetime.now(UTC))
        return {"ok": True, "agent_id": agent.agent_id}

    async def require_admin(request: Request) -> None:
        if not cfg.admin_token:
            raise HTTPException(status_code=503, detail="AED admin endpoints not configured")
        auth = request.headers.get("authorization", "")
        token = auth[7:] if auth.lower().startswith("bearer ") else ""
        if not token or not hmac.compare_digest(token, cfg.admin_token):
            raise HTTPException(status_code=401, detail="admin token required")

    @app.post("/aed/enrollments", dependencies=[Depends(require_admin)])
    async def mint_enrollment(req: EnrollMintRequest) -> JSONResponse:
        # Onboard an endpoint: mint a single-use, 15-min token (stored hashed,
        # never logged) and return it once with the CA fingerprint the agent
        # pins. The token's plaintext leaves here only in this response body.
        if ca is None or store is None or not enroll_secret:
            raise HTTPException(status_code=503, detail="AED enrollment not configured")
        now = datetime.now(UTC)
        meta: dict[str, object] = {"os": req.os, "name": req.name, "group": req.group}
        token = issue_token(store, enroll_secret, ttl_s=ENROLL_TTL_S, meta=meta, now=now)
        fp = ca.fingerprint()
        content: dict[str, object] = {
            "token": token,
            "os": req.os,
            "expires_at": (now + timedelta(seconds=ENROLL_TTL_S)).isoformat(),
            "ca_fingerprint": fp,
        }
        # When the gateway serves the agent and knows its advertised address, hand
        # back the ready-to-paste install command (Linux) with the pinned checksum.
        if req.os == "linux" and cfg.advertise_url and agent_sha is not None:
            sha = agent_sha
            content["agent_sha256"] = sha
            content["agent_url"] = f"{cfg.advertise_url.rstrip('/')}/aed/agent/linux"
            content["install"] = install.linux_install_command(
                advertise_url=cfg.advertise_url, token=token, ca_fingerprint=fp, agent_sha256=sha
            )
        return JSONResponse(status_code=200, content=content)

    @app.get("/aed/endpoints", dependencies=[Depends(require_admin)])
    async def endpoints() -> dict[str, object]:
        if store is None:
            raise HTTPException(status_code=503, detail="AED store not configured")
        return {"agents": store.list_agents(datetime.now(UTC), cfg.heartbeat_stale_s)}

    @app.get("/aed/endpoints/{agent_id}/events", dependencies=[Depends(require_admin)])
    async def endpoint_events(agent_id: str) -> dict[str, object]:
        if event_store is None:
            raise HTTPException(status_code=503, detail="AED event store not configured")
        return {"agent_id": agent_id, "events": event_store.events_for(agent_id)}

    @app.get("/aed/alerts", dependencies=[Depends(require_admin)])
    async def alerts() -> dict[str, object]:
        if event_store is None:
            raise HTTPException(status_code=503, detail="AED event store not configured")
        return {"alerts": event_store.list_alerts()}

    @app.post("/aed/agents/{agent_id}/revoke", dependencies=[Depends(require_admin)])
    async def revoke_agent(agent_id: str) -> dict[str, object]:
        if store is None:
            raise HTTPException(status_code=503, detail="AED store not configured")
        store.revoke(agent_id)
        return {"revoked": agent_id}

    @app.post("/aed/ingest")
    async def ingest(
        request: Request,
        agent: Annotated[Agent, Depends(require_agent)],
    ) -> JSONResponse:
        if not cfg.enabled:
            raise HTTPException(status_code=503, detail="AED gateway disabled")
        if not rl.allow(agent.agent_id):
            raise HTTPException(status_code=429, detail="rate limit exceeded")
        body = await request.body()
        if len(body) > cfg.max_batch_bytes:
            raise HTTPException(status_code=413, detail="batch too large")
        try:
            payload = json.loads(body)
        except ValueError as e:
            raise HTTPException(status_code=400, detail="malformed JSON") from e
        events = payload.get("events", []) if isinstance(payload, dict) else []
        if event_store is not None:
            now = datetime.now(UTC)
            affected: set[str] = set()
            for ev in events:
                if not isinstance(ev, dict):
                    continue
                ev["agent_id"] = agent.agent_id  # the authenticated identity is authoritative
                red = redact_event(ev, enroll_secret or "")
                event_store.store([red], now)
                f = red.get("fields") or {}
                if red.get("class_uid") == 3002 and f.get("status") == "failure" and f.get("src_ip"):
                    affected.add(str(f["src_ip"]))
            if rule is not None:
                for src_ip in affected:
                    alert = rule.evaluate(event_store, agent.agent_id, src_ip, now)
                    if alert is not None:
                        event_store.add_alert(alert)
        return JSONResponse(status_code=202, content={"accepted": True, "events": len(events)})

    return app
