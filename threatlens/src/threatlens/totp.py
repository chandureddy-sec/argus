"""Two-Factor Authentication: RFC 6238 TOTP (Time-Based One-Time Password).

* Uses standard HMAC-SHA1 with 30-second steps and 6 digits.
* Secrets are 160-bit random Base32 strings compatible with Google Authenticator,
  Microsoft Authenticator, 1Password, Bitwarden, etc.
* Verification supports clock drift tolerance (±1 step, i.e. ±30s).
* SVG QR code generation for scanning directly from mobile authenticator apps.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

import qrcode
import qrcode.image.svg


def generate_secret() -> str:
    """Generate a random 160-bit (20-byte) Base32 secret."""
    return base64.b32encode(secrets.token_bytes(20)).decode().replace("=", "")


def totp_code(secret: str, for_time: float | None = None, interval: int = 30, digits: int = 6) -> str:
    """Calculate the 6-digit TOTP code for the given time."""
    s = secret.strip().replace(" ", "").upper()
    missing_padding = (8 - len(s) % 8) % 8
    if missing_padding:
        s += "=" * missing_padding
    key = base64.b32decode(s)
    t = int(for_time if for_time is not None else time.time()) // interval
    msg = struct.pack(">Q", t)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code_int = struct.unpack(">I", h[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{code_int % (10**digits):0{digits}d}"


def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    """Verify a 6-digit code against secret with ±window steps drift."""
    cleaned = code.strip()
    if not (len(cleaned) == 6 and cleaned.isdigit()):
        return False
    now = time.time()
    for offset in range(-window, window + 1):
        if hmac.compare_digest(totp_code(secret, now + offset * 30), cleaned):
            return True
    return False


def otpauth_url(username: str, secret: str, issuer: str = "Argus") -> str:
    """Construct standard otpauth URI for authenticator apps."""
    clean_secret = secret.strip().replace(" ", "").upper()
    enc_user = quote(username.strip())
    enc_issuer = quote(issuer.strip())
    return f"otpauth://totp/{enc_issuer}:{enc_user}?secret={clean_secret}&issuer={enc_issuer}&algorithm=SHA1&digits=6&period=30"


def qr_svg(url: str) -> str:
    """Generate SVG XML string for a QR code representing the otpauth URI."""
    img = qrcode.make(url, image_factory=qrcode.image.svg.SvgPathImage)
    out: bytes = img.to_string()
    return out.decode("utf-8")
