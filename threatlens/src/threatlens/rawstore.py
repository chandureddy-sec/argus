"""Content-addressed store for raw feed documents.

Each payload is written once, gzipped, at ``<data_dir>/raw/<source>/<sha256[:2]>/<sha256>.gz``.
Identical payloads (an unchanged feed) share one file. Reading verifies the
SHA-256, so a tampered or corrupted document is detected before reprocessing.
"""

from __future__ import annotations

import gzip
import hashlib
import os
import re
from pathlib import Path

_SAFE = re.compile(r"^[a-z0-9_]{1,64}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")


class RawStoreError(Exception):
    pass


class RawStore:
    def __init__(self, root: Path) -> None:
        self.root = root

    def _path(self, source: str, sha256: str) -> Path:
        # Both parts are validated, so a hostile source name or hash can't
        # escape the store directory.
        if not _SAFE.match(source) or not _SHA.match(sha256):
            raise RawStoreError("invalid source name or digest")
        return self.root / "raw" / source / sha256[:2] / f"{sha256}.gz"

    def put(self, source: str, body: bytes) -> tuple[str, str]:
        """Store ``body``; return (sha256, reference relative to the root)."""
        sha = hashlib.sha256(body).hexdigest()
        path = self._path(source, sha)
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(f".tmp{os.getpid()}")
            tmp.write_bytes(gzip.compress(body, compresslevel=6))
            tmp.replace(path)  # atomic: readers never see a half-written file
        return sha, path.relative_to(self.root).as_posix()

    def get(self, ref: str, sha256: str) -> bytes:
        path = (self.root / ref).resolve()
        if not path.is_relative_to(self.root.resolve()):
            raise RawStoreError("reference outside the store")
        body = gzip.decompress(path.read_bytes())
        if hashlib.sha256(body).hexdigest() != sha256:
            raise RawStoreError(f"integrity check failed for {ref}")
        return body
