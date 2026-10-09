"""Browser sessions for the analyst UI.

An analyst signs in with an API key once. The key is checked like an API call
and then forgotten; the browser receives a signed, expiring session cookie
naming the key's id (``HttpOnly``, ``SameSite=Strict``). Every request
re-reads the key row, so revoking or expiring a key ends its sessions at once.
The key itself is never stored in the browser.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from datetime import UTC, datetime

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from threatlens.auth import Principal
from threatlens.logs import get_logger
from threatlens.models import ApiKey
from threatlens.settings import Settings

log = get_logger("threatlens.ui")

COOKIE = "tl_session"
LIFETIME_S = 12 * 3600
_EPHEMERAL = secrets.token_bytes(32)


def secret(settings: Settings) -> bytes:
    if settings.secret_key is not None:
        return settings.secret_key.get_secret_value().encode()
    # Without TL_SECRET_KEY sessions still work, but only until the process restarts.
    return _EPHEMERAL


def _sign(key: bytes, payload: str) -> str:
    return hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()


def issue(settings: Settings, key_id: int, now: float | None = None) -> str:
    payload = f"{key_id}.{int((now or time.time()) + LIFETIME_S)}"
    return f"{payload}.{_sign(secret(settings), payload)}"


def parse(settings: Settings, token: str, now: float | None = None) -> int | None:
    """Return the key id of a valid, unexpired token, else None."""
    parts = token.split(".")
    if len(parts) != 3 or not parts[0].isdigit() or not parts[1].isdigit() or len(token) > 200:
        return None
    payload = f"{parts[0]}.{parts[1]}"
    if not hmac.compare_digest(_sign(secret(settings), payload), parts[2]):
        return None
    if int(parts[1]) < (now or time.time()):
        return None
    return int(parts[0])


async def principal(request: Request, settings: Settings) -> Principal | None:
    token = request.cookies.get(COOKIE)
    key_id = parse(settings, token) if token else None
    if key_id is None:
        return None
    sm: async_sessionmaker[AsyncSession] = request.app.state.sessionmaker
    async with sm() as s:
        row = await s.get(ApiKey, key_id)
    if row is None or row.revoked_at is not None:
        return None
    expires = row.expires_at
    if expires is not None:
        expires = expires if expires.tzinfo else expires.replace(tzinfo=UTC)
        if expires <= datetime.now(UTC):
            return None
    return Principal(row.id, row.name, row.role)
