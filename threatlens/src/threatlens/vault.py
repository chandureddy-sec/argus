"""Secrets ThreatLens must send onward (a custom feed's API key), encrypted at
rest with a key derived from TL_SECRET_KEY (ADR 0012).

Unlike passwords and tokens, these can't be hashed: the worker needs the
plain value to send it. Without TL_SECRET_KEY nothing is stored, rather than
storing it in clear. Rotating TL_SECRET_KEY makes stored secrets unreadable;
the feed then reports that its key must be entered again.
"""

from __future__ import annotations

import base64

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from threatlens.settings import Settings

_INFO = b"threatlens/feed-credentials/v1"


class VaultError(Exception):
    """No key to encrypt with, or a stored secret can't be decrypted."""


def _fernet(settings: Settings) -> Fernet:
    if settings.secret_key is None:
        raise VaultError("set TL_SECRET_KEY in .env to store feed credentials (they are kept encrypted)")
    raw = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_INFO).derive(
        settings.secret_key.get_secret_value().encode()
    )
    return Fernet(base64.urlsafe_b64encode(raw))


def seal(settings: Settings, plaintext: str) -> str:
    return _fernet(settings).encrypt(plaintext.encode()).decode()


def unseal(settings: Settings, token: str) -> str:
    try:
        return _fernet(settings).decrypt(token.encode()).decode()
    except InvalidToken:
        raise VaultError(
            "the stored key can't be decrypted (TL_SECRET_KEY changed?): enter it again"
        ) from None
