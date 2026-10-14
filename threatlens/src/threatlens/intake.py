"""Reading what analysts paste or upload (Bulk check, case evidence).

Anything goes in (an alert, a log excerpt, an email, a list); every IP,
domain, URL, hash and email in it comes out once, defanged or not. Uploaded
files are read as text, with limits, and binaries are skipped with a note.
"""

from __future__ import annotations

from fastapi import UploadFile

from threatlens.api.enrich import NOT_LOOKUPS
from threatlens.ioc.extract import extract
from threatlens.ioc.types import Observable

BULK_MAX = 500  # values per Bulk check
MAX_FILES, MAX_FILE_BYTES = 10, 5 * 1024 * 1024
# Types that can go on the blocklist (and so on a firewall feed).
BLOCKABLE = frozenset({"ipv4-addr", "ipv6-addr", "ipv4-net", "ipv6-net", "domain-name", "url"})


async def gather_text(text: str, files: list[UploadFile] | None) -> tuple[str, list[str]]:
    """The pasted text plus every uploaded file's text; returns (text, notes)."""
    parts, notes = [text], []
    for f in (files or [])[:MAX_FILES]:
        if not f.filename:
            continue
        data = await f.read(MAX_FILE_BYTES + 1)
        if len(data) > MAX_FILE_BYTES:
            notes.append(f"{f.filename}: only the first {MAX_FILE_BYTES // (1024 * 1024)} MB were read")
            data = data[:MAX_FILE_BYTES]
        if b"\x00" in data[:4096]:
            notes.append(f"{f.filename}: skipped, not a text file")
            continue
        parts.append(data.decode("utf-8", errors="replace"))
    if files and len(files) > MAX_FILES:
        notes.append(f"only the first {MAX_FILES} files were read")
    return "\n".join(parts), notes


def observables(text: str) -> list[Observable]:
    """Every distinct value in the text that can be looked up."""
    return list(
        {o.key: o for o in extract(text) if isinstance(o, Observable) and o.type not in NOT_LOOKUPS}.values()
    )
