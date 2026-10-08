"""Connector framework.

A connector knows three things about one source: its terms (``SourceInfo``),
how to fetch it (``fetch``) and how to read it (``parse``). Everything else —
scheduling, raw archiving, normalization, allowlisting, dedup, metrics — is
the pipeline's job (``threatlens.collect``), so connectors stay small and
their parsers are pure functions tested against recorded fixtures.

``parse`` must raise :class:`SchemaDriftError` when the document's *structure*
is not what the connector was written for (missing keys, wrong header). A
single bad *value* is not drift: it is yielded and rejected downstream.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar, Literal

from threatlens.ioc.types import IOCType
from threatlens.net.http import FetchResult, SafeHttp

Grade = Literal["A", "B", "C", "D", "E", "F"]


class SchemaDriftError(ValueError):
    """The feed's format changed; the connector must be updated."""


class MissingKeyError(Exception):
    """The source needs an API key that isn't configured."""


@dataclass(frozen=True)
class SourceInfo:
    name: str
    title: str
    kind: str  # vulnerability | malware-url | ioc | botnet-c2 | netblock | anonymizer | phishing | pulse
    homepage: str
    url: str
    reliability: Grade  # Admiralty source grade
    reliability_note: str
    license: str
    license_url: str
    commercial_use: bool
    redistribution: bool
    upstream: str  # original producer, for independence when corroborating
    interval: timedelta  # how often we collect
    min_interval: timedelta  # the source's own fetch limit; never collect more often
    default_confidence: int
    attribution: str | None = None
    tlp: str = "TLP:CLEAR"
    key_setting: str | None = None  # Settings attribute holding the API key
    key_required: bool = False
    max_bytes: int = 50 * 1024 * 1024
    verified: str = ""  # date the terms and format were checked (docs/SOURCES.md)


@dataclass(frozen=True)
class Item:
    """One indicator as a source reported it, before normalization."""

    value: str
    type: IOCType | None  # None: let the normalizer guess
    seen_at: datetime | None = None
    confidence: int | None = None
    labels: tuple[str, ...] = ()
    context: Mapping[str, Any] = field(default_factory=dict)
    tlp: str | None = None  # per-item TLP (e.g. an OTX pulse), else the source default


class Connector(ABC):
    info: ClassVar[SourceInfo]

    def __init__(self, api_key: str | None = None) -> None:
        if self.info.key_required and not api_key:
            setting = f"TL_{self.info.key_setting.upper()}" if self.info.key_setting else "an API key"
            raise MissingKeyError(f"{self.info.name} needs {setting}")
        self.api_key = api_key

    async def fetch(self, http: SafeHttp, checkpoint: Mapping[str, Any]) -> FetchResult:
        """Default: conditional GET of ``info.url``."""
        return await http.get(
            self.info.url,
            etag=checkpoint.get("etag"),
            last_modified=checkpoint.get("last_modified"),
            max_bytes=self.info.max_bytes,
        )

    def next_checkpoint(self, result: FetchResult, checkpoint: Mapping[str, Any]) -> dict[str, Any]:
        cp = dict(checkpoint)
        if result.etag:
            cp["etag"] = result.etag
        if result.last_modified:
            cp["last_modified"] = result.last_modified
        return cp

    @abstractmethod
    def parse(self, body: bytes) -> Iterator[Item]: ...


REGISTRY: dict[str, type[Connector]] = {}


def register(cls: type[Connector]) -> type[Connector]:
    if cls.info.name in REGISTRY:
        raise ValueError(f"duplicate connector {cls.info.name}")
    REGISTRY[cls.info.name] = cls
    return cls


# ── helpers for parsers ──────────────────────────────────────────────────────


def parse_time(value: object) -> datetime | None:
    """Parse the timestamp formats feeds use; None if absent or unparseable."""
    if not value or not isinstance(value, str):
        return None
    v = value.strip().removesuffix(" UTC").replace("Z", "+00:00")
    for fmt in (None, "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.fromisoformat(v) if fmt is None else datetime.strptime(v, fmt)
        except ValueError:
            continue
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    return None


def require(obj: Mapping[str, Any], *keys: str, where: str) -> None:
    missing = [k for k in keys if k not in obj]
    if missing:
        raise SchemaDriftError(f"{where}: missing field(s) {', '.join(missing)}")


def clip(value: object, n: int = 500) -> str:
    s = "" if value is None else str(value)
    return s if len(s) <= n else s[: n - 1] + "…"
