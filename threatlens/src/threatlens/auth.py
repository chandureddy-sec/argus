"""API keys, role-based access control and per-key rate limiting.

* Keys look like ``tl_<43 url-safe chars>`` (256 bits of randomness). Only
  their SHA-256 is stored: with that much entropy a fast hash is enough, and a
  database leak doesn't reveal usable keys. The plaintext is shown once.
* Roles are ordered: ``viewer`` < ``analyst`` < ``admin``. A route declares
  the minimum role it needs.
* Each key gets a fixed-window request budget per minute (Redis in
  production, in-memory in tests and single-process use).
"""

from __future__ import annotations

import hashlib
import secrets
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol

from fastapi import HTTPException, Request
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from threatlens.models import ApiKey, AuditLog

ROLE_RANK = {"viewer": 0, "analyst": 1, "admin": 2}
KEY_PREFIX = "tl_"
_LAST_USED_RESOLUTION = timedelta(minutes=5)


def generate_key() -> str:
    return KEY_PREFIX + secrets.token_urlsafe(32)


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


@dataclass(frozen=True)
class Principal:
    key_id: int  # the API key's id, or the user's id when kind == "user"
    name: str
    role: str
    kind: str = "key"  # "key" (API, programs) or "user" (UI sign-in, see threatlens.users)

    def can(self, role: str) -> bool:
        return ROLE_RANK[self.role] >= ROLE_RANK[role]


async def create_key(
    s: AsyncSession, name: str, role: str, *, expires_days: int | None = None, actor: str = "cli"
) -> tuple[ApiKey, str]:
    if role not in ROLE_RANK:
        raise ValueError(f"role must be one of {', '.join(ROLE_RANK)}")
    if await s.scalar(select(ApiKey).where(ApiKey.name == name)):
        raise ValueError(f"an API key named {name!r} already exists")
    key = generate_key()
    row = ApiKey(
        name=name,
        prefix=key[:10],
        key_hash=hash_key(key),
        role=role,
        expires_at=datetime.now(UTC) + timedelta(days=expires_days) if expires_days else None,
    )
    s.add(row)
    s.add(
        AuditLog(
            actor=actor,
            action="api_key.create",
            target=name,
            details={"role": role, "expires_days": expires_days},
        )
    )
    await s.flush()
    return row, key


async def revoke_key(s: AsyncSession, name: str, *, actor: str = "cli") -> bool:
    row = await s.scalar(select(ApiKey).where(ApiKey.name == name, ApiKey.revoked_at.is_(None)))
    if row is None:
        return False
    row.revoked_at = datetime.now(UTC)
    s.add(AuditLog(actor=actor, action="api_key.revoke", target=name, details={}))
    return True


async def authenticate(s: AsyncSession, key: str) -> Principal | None:
    if not key.startswith(KEY_PREFIX) or len(key) > 100:
        return None
    row = await s.scalar(select(ApiKey).where(ApiKey.key_hash == hash_key(key)))
    now = datetime.now(UTC)
    if row is None or row.revoked_at is not None:
        return None
    expires = (
        row.expires_at.replace(tzinfo=UTC)
        if row.expires_at and row.expires_at.tzinfo is None
        else row.expires_at
    )
    if expires is not None and expires <= now:
        return None
    last = (
        row.last_used_at.replace(tzinfo=UTC)
        if row.last_used_at and row.last_used_at.tzinfo is None
        else row.last_used_at
    )
    if last is None or now - last > _LAST_USED_RESOLUTION:
        row.last_used_at = now  # coarse on purpose: not a write per request
        await s.commit()
    return Principal(row.id, row.name, row.role)


# ── rate limiting ────────────────────────────────────────────────────────────


class RateLimiter(Protocol):
    async def hit(self, bucket: str, limit: int, window_s: int = 60) -> int:
        """Count a request; return 0 if allowed, else seconds until reset."""
        ...


class MemoryRateLimiter:
    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._counts: dict[tuple[str, int], int] = {}
        self._clock = clock

    async def hit(self, bucket: str, limit: int, window_s: int = 60) -> int:
        now = self._clock()
        window = int(now // window_s)
        key = (bucket, window)
        self._counts = {k: v for k, v in self._counts.items() if k[1] >= window}  # drop old windows
        self._counts[key] = self._counts.get(key, 0) + 1
        if self._counts[key] > limit:
            return max(1, int((window + 1) * window_s - now))
        return 0


class RedisRateLimiter:
    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    async def hit(self, bucket: str, limit: int, window_s: int = 60) -> int:
        window = int(time.time() // window_s)
        key = f"threatlens:rl:{bucket}:{window}"
        pipe = self._redis.pipeline()
        pipe.incr(key)
        pipe.expire(key, window_s + 5)
        count, _ = await pipe.execute()
        if int(count) > limit:
            return max(1, int((window + 1) * window_s - time.time()))
        return 0


# ── FastAPI dependency ──────────────────────────────────────────────────────


def _presented_key(request: Request) -> str | None:
    key = request.headers.get("x-api-key")
    if key:
        return key
    auth = request.headers.get("authorization", "")
    scheme, _, value = auth.partition(" ")
    return value.strip() if scheme.lower() == "bearer" and value else None


def require(role: str) -> Callable[[Request], Awaitable[Principal]]:
    if role not in ROLE_RANK:
        raise ValueError(role)

    async def dependency(request: Request) -> Principal:
        key = _presented_key(request)
        sm: async_sessionmaker[AsyncSession] = request.app.state.sessionmaker
        principal = None
        if key:
            async with sm() as s:
                principal = await authenticate(s, key)
        if principal is None:
            raise HTTPException(401, "missing or invalid API key", headers={"WWW-Authenticate": "ApiKey"})
        if not principal.can(role):
            raise HTTPException(403, f"this action needs the {role} role")
        limits = request.app.state.rate_limits
        wait = await request.app.state.limiter.hit(f"key:{principal.key_id}", limits[principal.role])
        if wait:
            raise HTTPException(429, "rate limit exceeded", headers={"Retry-After": str(wait)})
        request.state.principal = principal
        return principal

    return dependency
