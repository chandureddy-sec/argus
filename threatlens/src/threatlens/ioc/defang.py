"""Defang and refang.

Indicators are *displayed* defanged (``hxxp://evil[.]com``) so that a click or
a chat client's link preview can't reach them; copying the live form is an
explicit action. Feeds and reports often arrive defanged, so text is refanged
before extraction.
"""

from __future__ import annotations

import re

from threatlens.ioc.types import IOCType

_REFANG = [
    (re.compile(r"\bh[xX]{2}p(s?)(?=\[?:)", re.I), r"http\1"),
    (re.compile(r"\bfxp(?=\[?:)", re.I), "ftp"),
    (re.compile(r"\[(?:\.|dot)\]|\((?:\.|dot)\)|\{(?:\.|dot)\}", re.I), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[://\]"), "://"),
    (re.compile(r"\[(?:@|at)\]|\((?:@|at)\)", re.I), "@"),
    (re.compile(r"\\\."), "."),  # escaped dots: evil\.com
]


def refang(text: str) -> str:
    """Undo common defanging so indicators can be parsed."""
    for pattern, repl in _REFANG:
        text = pattern.sub(repl, text)
    return text


def defang(value: str, ioc_type: IOCType) -> str:
    """Make an indicator safe to display (not clickable, not resolvable)."""
    if ioc_type == IOCType.URL:
        scheme, sep, rest = value.partition("://")
        host, slash, path = rest.partition("/")
        scheme = {"http": "hxxp", "https": "hxxps", "ftp": "fxp"}.get(scheme, scheme)
        return f"{scheme}[://]{host.replace('.', '[.]')}{slash}{path}" if sep else value.replace(".", "[.]")
    if ioc_type in (IOCType.DOMAIN, IOCType.IPV4, IOCType.IPV4_NET):
        return value.replace(".", "[.]")
    if ioc_type in (IOCType.IPV6, IOCType.IPV6_NET):
        return value.replace(":", "[:]")
    if ioc_type == IOCType.EMAIL:
        local, _, domain = value.partition("@")
        return f"{local}[@]{domain.replace('.', '[.]')}"
    return value  # hashes, CVEs, file names, registry keys are inert
