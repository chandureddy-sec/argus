"""Browser sessions for the analyst UI.

A person signs in with a username and password (``threatlens.users``). The
browser then receives a signed, expiring session cookie (``HttpOnly``,
``SameSite=Strict``) naming the user and a fingerprint of their current
password hash. Every request re-reads the user row, so disabling the account
or changing its password ends its sessions at once. The password is never
stored in the browser.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from threatlens.auth import Principal
from threatlens.logs import get_logger
from threatlens.models import User
from threatlens.settings import Settings

log = get_logger("threatlens.ui")

COOKIE = "tl_user"
LIFETIME_S = 12 * 3600
_EPHEMERAL = secrets.token_bytes(32)


def secret(settings: Settings) -> bytes:
    if settings.secret_key is not None:
        return settings.secret_key.get_secret_value().encode()
    # Without TL_SECRET_KEY sessions still work, but only until the process restarts.
    return _EPHEMERAL


def _sign(key: bytes, payload: str) -> str:
    return hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()


def password_tag(password_hash: str) -> str:
    """Changes whenever the password does; binds a session to the password it was opened with."""
    return hashlib.sha256(password_hash.encode()).hexdigest()[:16]


def issue(settings: Settings, user_id: int, tag: str, now: float | None = None) -> str:
    payload = f"u.{user_id}.{int((now or time.time()) + LIFETIME_S)}.{tag}"
    return f"{payload}.{_sign(secret(settings), payload)}"


def parse(settings: Settings, token: str, now: float | None = None) -> tuple[int, str] | None:
    """Return (user id, password tag) of a valid, unexpired token, else None."""
    parts = token.split(".")
    if len(token) > 200 or len(parts) != 5 or parts[0] != "u":
        return None
    _, uid, exp, tag, sig = parts
    if not uid.isdigit() or not exp.isdigit():
        return None
    if not hmac.compare_digest(_sign(secret(settings), ".".join(parts[:4])), sig):
        return None
    if int(exp) < (now or time.time()):
        return None
    return int(uid), tag


async def principal(request: Request, settings: Settings) -> Principal | None:
    token = request.cookies.get(COOKIE)
    parsed = parse(settings, token) if token else None
    if parsed is None:
        return None
    sm: async_sessionmaker[AsyncSession] = request.app.state.sessionmaker
    async with sm() as s:
        row = await s.get(User, parsed[0])
    if row is None or row.disabled_at is not None:
        return None
    if not hmac.compare_digest(password_tag(row.password_hash), parsed[1]):
        return None  # the password changed since this session began
    return Principal(row.id, row.name, row.role, kind="user")
