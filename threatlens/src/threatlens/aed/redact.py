"""AED Slice 5 — redaction applied to every event before storage.

Usernames are replaced with a stable keyed hash (so repeated failures for one
account still correlate without storing the name), and secret-looking material
is scrubbed from the preserved raw record. Command-line fields are not collected
for the SSH use case; any that appear are dropped by the inventory allowlist.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from copy import deepcopy
from typing import Any

_SECRET_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)(authorization:\s*bearer\s+)\S+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\b(token|password|passwd|api[_-]?key|secret)(\s*[=:]\s*)\S+"), r"\1\2[REDACTED]"),
    (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
        "[REDACTED]",
    ),
]


def _hash_user(secret: str, user: str) -> str:
    return hmac.new(secret.encode(), user.encode(), hashlib.sha256).hexdigest()[:16]


def scrub_secrets(text: str) -> str:
    for rx, rep in _SECRET_RULES:
        text = rx.sub(rep, text)
    return text


def redact_event(event: dict[str, Any], secret: str) -> dict[str, Any]:
    """Return a redacted copy of ``event``: username hashed, secrets scrubbed."""
    out = deepcopy(event)
    fields = out.get("fields")
    if isinstance(fields, dict) and "user" in fields:
        fields["user_hash"] = _hash_user(secret, str(fields["user"]))
        del fields["user"]
    raw = out.get("raw")
    if isinstance(raw, str):
        out["raw"] = scrub_secrets(raw)
    return out
