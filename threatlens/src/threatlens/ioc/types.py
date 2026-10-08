"""Observable types.

Values mirror STIX 2.1 cyber-observable names where one exists, split where
ThreatLens needs finer handling (single IPs vs networks; one type per hash
algorithm). The STIX export maps them back (Phase 6).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class IOCType(StrEnum):
    IPV4 = "ipv4-addr"
    IPV6 = "ipv6-addr"
    IPV4_NET = "ipv4-net"
    IPV6_NET = "ipv6-net"
    DOMAIN = "domain-name"
    URL = "url"
    EMAIL = "email-addr"
    MD5 = "file-md5"
    SHA1 = "file-sha1"
    SHA256 = "file-sha256"
    CVE = "vulnerability"
    FILENAME = "file-name"
    REGKEY = "windows-registry-key"


@dataclass(frozen=True, slots=True)
class Observable:
    """A normalized observable. ``value`` is canonical: equal observables
    always produce the same ``key``, which is the dedup identity."""

    type: IOCType
    value: str

    @property
    def key(self) -> str:
        return f"{self.type.value}|{self.value}"


@dataclass(frozen=True, slots=True)
class Rejected:
    """A value that looked like an IOC but was refused, and why."""

    type: IOCType | None
    raw: str
    reason: str
