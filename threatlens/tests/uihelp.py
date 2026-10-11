"""Shared UI assertions."""

from __future__ import annotations

import re

_SCRIPT = re.compile(r"<script\b[^>]*>(.*?)</script>", re.S | re.I)
_OURS = re.compile(r'^<script src="/ui/static/app\.js\?v=[\w.+-]+" defer>$')


def only_our_script(html: str) -> bool:
    """The page loads our own app.js and nothing else: no inline script, no
    other source, and nothing from the data (provider text, feed values)."""
    tags = re.findall(r"<script\b[^>]*>", html, re.I)
    if any(not _OURS.match(t) for t in tags):
        return False
    return all(not body.strip() for body in _SCRIPT.findall(html))
