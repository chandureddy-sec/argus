"""Analyst UI accounts: usernames and passwords (ADR 0007).

* Passwords are hashed with scrypt from the standard library (N=2^14, r=8,
  p=1, 16-byte random salt), stored as ``scrypt$N$r$p$salt$hash``. Checking
  one takes tens of milliseconds, so it runs in a worker thread.
* Usernames are matched case-insensitively with runs of spaces collapsed:
  "Chandu  Reddy" and "chandu reddy" are the same account.
* An unknown username costs the same hash computation as a wrong password,
  so response times don't reveal which usernames exist.
* API keys (``threatlens.auth``) are unchanged and remain the credential for
  programs such as ReconX; people sign in to the UI with these accounts.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import re
import secrets
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from threatlens import tlp as tlp_rules
from threatlens.auth import ROLE_RANK
from threatlens.models import AuditLog, User

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**14, 8, 1
MIN_PASSWORD, MAX_PASSWORD = 6, 256
MAX_NAME = 64
_NAME = re.compile(r"[\w .@-]+")


class UserError(ValueError):
    """A request about an account that can't be honoured (shown to the operator)."""


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=32, maxmem=64 * 1024 * 1024)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = _scrypt(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, digest = stored.split("$")
        if algo != "scrypt" or int(n) > 2**17 or int(r) > 16 or int(p) > 4:
            return False
        want = base64.b64decode(salt), base64.b64decode(digest)
    except ValueError:
        return False
    return hmac.compare_digest(_scrypt(password, want[0], int(n), int(r), int(p)), want[1])


# Compared against when the username doesn't exist, to keep timing uniform.
_DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


def display_name(name: str) -> str:
    return " ".join(name.split())


def login_key(name: str) -> str:
    return display_name(name).casefold()


def check_name(name: str) -> str:
    shown = display_name(name)
    if not shown or len(shown) > MAX_NAME or not _NAME.fullmatch(shown):
        raise UserError(f"a username is 1-{MAX_NAME} letters, digits, spaces or . _ @ - (got {name!r})")
    return shown


def check_password(password: str) -> None:
    if len(password) < MIN_PASSWORD:
        raise UserError(f"the password must be at least {MIN_PASSWORD} characters")
    if len(password) > MAX_PASSWORD:
        raise UserError(f"the password must be at most {MAX_PASSWORD} characters")


def check_role(role: str) -> None:
    if role not in ROLE_RANK:
        raise UserError(f"role must be one of {', '.join(ROLE_RANK)}")


async def get_user(s: AsyncSession, name: str) -> User | None:
    return await s.scalar(select(User).where(User.login == login_key(name)))


def check_clearance(clearance: str | None) -> None:
    if clearance is not None and clearance not in tlp_rules.LEVELS:
        raise UserError(f"clearance must be one of {', '.join(tlp_rules.LEVELS)}")


async def create_user(
    s: AsyncSession, name: str, password: str, role: str, *, actor: str = "cli", clearance: str | None = None
) -> User:
    shown = check_name(name)
    check_password(password)
    check_role(role)
    check_clearance(clearance)
    if await get_user(s, shown):
        raise UserError(f"a user named {shown!r} already exists (change the password with: passwd)")
    row = User(
        login=login_key(shown),
        name=shown,
        password_hash=await asyncio.to_thread(hash_password, password),
        role=role,
        tlp_clearance=clearance,
    )
    s.add(row)
    s.add(
        AuditLog(
            actor=actor,
            action="user.create",
            target=shown,
            details={"role": role, "tlp_clearance": clearance},
        )
    )
    await s.flush()
    return row


async def _existing(s: AsyncSession, name: str) -> User:
    row = await get_user(s, name)
    if row is None:
        raise UserError(f"no user named {display_name(name)!r}")
    return row


async def set_password(s: AsyncSession, name: str, password: str, *, actor: str = "cli") -> User:
    """Change a password. Sessions signed in with the old one end at once."""
    check_password(password)
    row = await _existing(s, name)
    row.password_hash = await asyncio.to_thread(hash_password, password)
    row.password_changed_at = datetime.now(UTC)
    s.add(AuditLog(actor=actor, action="user.password", target=row.name, details={}))
    return row


async def set_role(s: AsyncSession, name: str, role: str, *, actor: str = "cli") -> User:
    check_role(role)
    row = await _existing(s, name)
    s.add(AuditLog(actor=actor, action="user.role", target=row.name, details={"from": row.role, "to": role}))
    row.role = role
    return row


async def set_clearance(s: AsyncSession, name: str, clearance: str | None, *, actor: str = "cli") -> User:
    """Set the most restricted TLP the account may read (None: its role's default)."""
    check_clearance(clearance)
    row = await _existing(s, name)
    s.add(
        AuditLog(
            actor=actor, action="user.clearance", target=row.name,
            details={"from": row.tlp_clearance, "to": clearance},
        )
    )  # fmt: skip
    row.tlp_clearance = clearance
    return row


async def set_disabled(s: AsyncSession, name: str, disabled: bool, *, actor: str = "cli") -> User:
    """Disable (ending every session) or re-enable an account."""
    row = await _existing(s, name)
    row.disabled_at = datetime.now(UTC) if disabled else None
    action = "user.disable" if disabled else "user.enable"
    s.add(AuditLog(actor=actor, action=action, target=row.name, details={}))
    return row


async def authenticate_user(s: AsyncSession, name: str, password: str) -> User | None:
    """The enabled account matching name and password, else None."""
    if len(password) > MAX_PASSWORD or len(name) > 200:
        return None
    row = await get_user(s, name)
    ok = await asyncio.to_thread(verify_password, password, row.password_hash if row else _DUMMY_HASH)
    if row is None or not ok or row.disabled_at is not None:
        return None
    row.last_login_at = datetime.now(UTC)
    s.add(AuditLog(actor=row.name, action="user.login", target=row.name, details={}))
    return row
