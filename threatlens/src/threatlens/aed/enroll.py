"""AED Slice 2 — enrollment tokens, replay guard, revocation (store + helpers).

Tokens are single-use and short-lived; only their HMAC is stored, never the
plaintext. The store is an interface with an in-memory implementation for the
lab; a Postgres-backed implementation lands with the storage slice. Nothing here
logs tokens, secrets or key material.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
from datetime import datetime, timedelta
from typing import Protocol


class EnrollError(Exception):
    """An enrollment token was invalid, expired, or already used."""


def _token_hash(secret: str, token: str) -> str:
    return hmac.new(secret.encode(), token.encode(), hashlib.sha256).hexdigest()


class EnrollmentStore(Protocol):
    def put_token(
        self, token_hash: str, expires_at: datetime, meta: dict[str, object] | None = None
    ) -> None: ...
    def consume_token(self, token_hash: str, now: datetime) -> bool: ...
    def pending_enrollments(self, now: datetime) -> list[dict[str, object]]: ...
    def revoke(self, agent_id: str) -> None: ...
    def is_revoked(self, agent_id: str) -> bool: ...
    def register_agent(self, agent_id: str, cert_fingerprint: str, now: datetime) -> None: ...
    def heartbeat(self, agent_id: str, now: datetime) -> None: ...
    def list_agents(self, now: datetime, stale_after_s: int) -> list[dict[str, object]]: ...
    def replay_accept(self, agent_id: str, seq: int, nonce: str, now: datetime) -> bool: ...


class InMemoryStore:
    """Lab/test store. Thread-safe single-use token consumption."""

    def __init__(self, nonce_window: int = 1024) -> None:
        self._lock = threading.Lock()
        # hash -> (expires_at, used, meta); meta carries the onboarding choices
        # (os/name/group) so a not-yet-enrolled endpoint can show as "pending".
        self._tokens: dict[str, tuple[datetime, bool, dict[str, object] | None]] = {}
        self._revoked: set[str] = set()
        # agent_id -> {fingerprint, first_seen, last_seen|None}
        self._agents: dict[str, dict[str, object]] = {}
        self._last_seq: dict[str, int] = {}
        self._nonces: dict[str, list[str]] = {}
        self._nonce_window = nonce_window

    def put_token(self, token_hash: str, expires_at: datetime, meta: dict[str, object] | None = None) -> None:
        with self._lock:
            self._tokens[token_hash] = (expires_at, False, meta)

    def consume_token(self, token_hash: str, now: datetime) -> bool:
        with self._lock:
            entry = self._tokens.get(token_hash)
            if entry is None:
                return False
            expires_at, used, meta = entry
            if used or now > expires_at:
                return False
            self._tokens[token_hash] = (expires_at, True, meta)  # mark used atomically
            return True

    def pending_enrollments(self, now: datetime) -> list[dict[str, object]]:
        """Minted tokens not yet redeemed and not expired, with their onboarding
        metadata — the "waiting for agent" endpoints. Token hashes are never
        returned."""
        with self._lock:
            out: list[dict[str, object]] = []
            for expires_at, used, meta in self._tokens.values():
                if used or now > expires_at or meta is None:
                    continue
                out.append({**meta, "expires_at": expires_at.isoformat()})
            return out

    def revoke(self, agent_id: str) -> None:
        with self._lock:
            self._revoked.add(agent_id)

    def is_revoked(self, agent_id: str) -> bool:
        with self._lock:
            return agent_id in self._revoked

    def register_agent(self, agent_id: str, cert_fingerprint: str, now: datetime) -> None:
        with self._lock:
            rec = self._agents.get(agent_id)
            if rec is None:
                self._agents[agent_id] = {
                    "fingerprint": cert_fingerprint,
                    "first_seen": now,
                    "last_seen": None,
                }
            else:
                rec["fingerprint"] = cert_fingerprint

    def heartbeat(self, agent_id: str, now: datetime) -> None:
        with self._lock:
            rec = self._agents.setdefault(agent_id, {"fingerprint": "", "first_seen": now, "last_seen": None})
            rec["last_seen"] = now

    def list_agents(self, now: datetime, stale_after_s: int) -> list[dict[str, object]]:
        with self._lock:
            out: list[dict[str, object]] = []
            for agent_id, rec in self._agents.items():
                last_seen = rec["last_seen"]
                if agent_id in self._revoked:
                    status = "revoked"
                elif last_seen is None:
                    status = "pending"
                elif isinstance(last_seen, datetime) and (now - last_seen).total_seconds() <= stale_after_s:
                    status = "online"
                else:
                    status = "stale"
                first_seen = rec["first_seen"]
                out.append(
                    {
                        "agent_id": agent_id,
                        "fingerprint": rec["fingerprint"],
                        "first_seen": first_seen.isoformat() if isinstance(first_seen, datetime) else None,
                        "last_seen": last_seen.isoformat() if isinstance(last_seen, datetime) else None,
                        "status": status,
                    }
                )
            return out

    def replay_accept(self, agent_id: str, seq: int, nonce: str, now: datetime) -> bool:
        with self._lock:
            if seq <= self._last_seq.get(agent_id, 0):
                return False
            seen = self._nonces.setdefault(agent_id, [])
            if nonce in seen:
                return False
            self._last_seq[agent_id] = seq
            seen.append(nonce)
            if len(seen) > self._nonce_window:
                del seen[: len(seen) - self._nonce_window]
            return True


def issue_token(
    store: EnrollmentStore,
    secret: str,
    ttl_s: int = 900,
    meta: dict[str, object] | None = None,
    now: datetime | None = None,
) -> str:
    """Create a single-use enrollment token; store only its HMAC and the
    onboarding metadata. Returns the plaintext token (shown to the admin once)."""
    from datetime import UTC

    now = now or datetime.now(UTC)
    token = secrets.token_urlsafe(32)
    store.put_token(_token_hash(secret, token), now + timedelta(seconds=ttl_s), meta)
    return token


def redeem_token(store: EnrollmentStore, secret: str, token: str, now: datetime | None = None) -> None:
    """Consume a token; raise :class:`EnrollError` if invalid, expired or used."""
    from datetime import UTC

    now = now or datetime.now(UTC)
    if not store.consume_token(_token_hash(secret, token), now):
        raise EnrollError("invalid, expired, or already-used enrollment token")
