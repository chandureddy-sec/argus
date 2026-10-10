"""Enricher framework (ADR 0005).

An enricher answers one question about one observable ("who registered this
domain?", "what does AbuseIPDB say about this IP?"). It declares its terms in
``EnricherInfo``: which observable types it handles, whether it is passive or
active, whether the value leaves the platform (and whether that disclosure is
visible to others), its key, its quotas, its cache lifetime and its licence.

``query`` is a pure fetch-and-read step: it returns an :class:`Outcome` or
raises. Caching, quotas, TLP and active-mode policy, timeouts and storage are
the service's job (``threatlens.enrich.service``), so enrichers stay small and
their readers are tested against recorded responses.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar, Literal

from threatlens.connectors.base import Grade
from threatlens.ioc.types import IOCType
from threatlens.net.http import FetchResult, SafeHttp

Mode = Literal["passive", "active"]
EvidenceKind = Literal["malicious", "suspicious", "benign", "info"]

IPS = frozenset({IOCType.IPV4, IOCType.IPV6})
HASHES = frozenset({IOCType.MD5, IOCType.SHA1, IOCType.SHA256})
RAW_CAP = 256 * 1024  # bytes of upstream JSON kept per enrichment


class EnrichError(Exception):
    """The upstream answered, but not in a way we can use."""


@dataclass(frozen=True)
class Quota:
    """At most ``limit`` metered calls per ``window_s`` seconds (fixed windows
    aligned to the epoch, so a daily quota resets at 00:00 UTC)."""

    limit: int
    window_s: int

    @property
    def label(self) -> str:
        names = {60: "minute", 3600: "hour", 86400: "day", 7 * 86400: "week"}
        return f"{self.limit}/{names.get(self.window_s, f'{self.window_s}s')}"


@dataclass(frozen=True)
class EnricherInfo:
    name: str
    title: str
    homepage: str
    applies_to: frozenset[IOCType]
    mode: Mode
    # Sends the observable to someone else. Third-party enrichers are held
    # back by TLP (ADR 0005): never for AMBER/RED, and for GREEN only when the
    # lookup does not become visible to others (``discloses``).
    third_party: bool
    discloses: bool  # the provider may publish or share what was looked up
    reliability: Grade
    reliability_note: str
    license: str
    license_url: str
    commercial_use: bool
    redistribution: bool
    upstream: str
    ttl: timedelta  # how long an answer stays fresh
    negative_ttl: timedelta  # how long "not found" stays fresh
    verified: str  # date the docs were checked (docs/SOURCES.md)
    key_setting: str | None = None
    key_required: bool = False
    quotas: tuple[Quota, ...] = ()  # without a key, or for any key
    keyed_quotas: tuple[Quota, ...] | None = None  # when a key is configured, if different
    metered: bool = False  # calls count against a provider quota (and the bulk budget)
    concurrency: int = 4  # simultaneous calls to this provider
    timeout_s: float | None = None  # overrides TL_ENRICH_TIMEOUT_S (slow providers)
    auto: bool = False  # may run in background enrichment (free, passive, unmetered)
    attribution: str | None = None

    def quotas_for(self, keyed: bool) -> tuple[Quota, ...]:
        if keyed and self.keyed_quotas is not None:
            return self.keyed_quotas
        return self.quotas


@dataclass(frozen=True)
class Evidence:
    """One finding, weighted 0-100, in words an analyst can check."""

    source: str
    kind: EvidenceKind
    weight: int
    text: str
    ref: str | None = None  # where to see it upstream

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "kind": self.kind,
            "weight": self.weight,
            "text": self.text,
            "ref": self.ref,
        }


@dataclass(frozen=True)
class RateInfo:
    """What the provider's own rate-limit headers said."""

    remaining: int | None
    reset_at: datetime | None


@dataclass
class Outcome:
    status: Literal["ok", "not_found"]
    summary: dict[str, Any]
    evidence: list[Evidence] = field(default_factory=list)
    raw: Any = None
    query: str = ""
    http_status: int | None = None
    calls: int = 1  # upstream requests made (metered enrichers spend this many units)
    rate: RateInfo | None = None


class Enricher(ABC):
    info: ClassVar[EnricherInfo]

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key

    @abstractmethod
    async def query(self, http: SafeHttp, type_: IOCType, value: str) -> Outcome: ...


REGISTRY: dict[str, type[Enricher]] = {}


def register(cls: type[Enricher]) -> type[Enricher]:
    if cls.info.name in REGISTRY:
        raise ValueError(f"duplicate enricher {cls.info.name}")
    REGISTRY[cls.info.name] = cls
    return cls


# ── helpers for readers ──────────────────────────────────────────────────────


def load_json(res: FetchResult, where: str) -> Any:
    try:
        return json.loads(res.body)
    except ValueError as e:
        raise EnrichError(f"{where}: response is not JSON") from e


def cap_raw(doc: Any) -> Any:
    """Keep the upstream answer for provenance unless it is very large."""
    size = len(json.dumps(doc, default=str))
    if size <= RAW_CAP:
        return doc
    return {"_omitted": f"response was {size} bytes; over the {RAW_CAP}-byte cap"}


def rate_from_headers(
    headers: Mapping[str, str], remaining: str, reset: str, *, reset_is_epoch: bool = True
) -> RateInfo | None:
    """Read X-RateLimit-Remaining / -Reset style headers, if present."""
    rem_s, reset_s = headers.get(remaining), headers.get(reset)
    if rem_s is None:
        return None
    try:
        rem = int(rem_s)
    except ValueError:
        return None
    at: datetime | None = None
    if reset_s:
        try:
            at = (
                datetime.fromtimestamp(int(reset_s), UTC)
                if reset_is_epoch
                else datetime.fromisoformat(reset_s.replace("Z", "+00:00"))
            )
        except (ValueError, OverflowError):
            at = None
    return RateInfo(rem, at)


def parse_dt(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
