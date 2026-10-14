"""Feeds an admin adds in the UI (ADR 0012).

A custom feed is described by data (``FeedSpec``), not code: where it lives,
whether it is plain text, CSV or JSON, which column or field holds the value,
and what kind of indicator to expect. ``connector_for`` turns a spec into an
ordinary :class:`Connector`, so the pipeline treats it exactly like a built-in
feed: the hardened HTTP client (no private addresses, size cap), the raw
archive, normalization, allowlist, dedup, scoring and run history.
"""

from __future__ import annotations

import csv
import io
import json
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Literal

from threatlens.connectors.base import Connector, Item, SchemaDriftError, SourceInfo
from threatlens.ioc.normalize import guess
from threatlens.ioc.types import IOCType, Observable
from threatlens.net.http import FetchResult, SafeHttp

Format = Literal["text", "csv", "json"]
Family = Literal["auto", "ip", "domain", "url", "hash"]
FORMATS: tuple[Format, ...] = ("text", "csv", "json")
FAMILIES: dict[Family, frozenset[IOCType]] = {
    "auto": frozenset(),
    "ip": frozenset({IOCType.IPV4, IOCType.IPV6, IOCType.IPV4_NET, IOCType.IPV6_NET}),
    "domain": frozenset({IOCType.DOMAIN}),
    "url": frozenset({IOCType.URL}),
    "hash": frozenset({IOCType.MD5, IOCType.SHA1, IOCType.SHA256}),
}
# What a value of the wrong kind is checked as, so it is rejected with a reason.
_FALLBACK = {"ip": IOCType.IPV4, "domain": IOCType.DOMAIN, "url": IOCType.URL, "hash": IOCType.SHA256}
MIN_INTERVAL = timedelta(minutes=5)  # never fetch faster, even on "Pull now"
MAX_BYTES = 20 * 1024 * 1024
MAX_ITEMS = 500_000
LABEL = "custom-feed"
_SPLIT = re.compile(r"[\s,;|]+")


@dataclass(frozen=True)
class FeedSpec:
    name: str
    title: str
    url: str
    format: Format
    ioc_type: Family = "auto"
    verdict: Literal["malicious", "suspicious"] = "malicious"
    confidence: int = 70
    comment_char: str = "#"
    value_column: int = 0
    json_path: str | None = None
    auth_header: str | None = None
    tlp: str = "TLP:CLEAR"
    reliability: str = "C"
    upstream: str = "custom"
    interval: timedelta = timedelta(hours=6)


def _decode(body: bytes) -> str:
    return body.decode("utf-8-sig", errors="replace")


def _lines(text: str, comment: str) -> Iterator[str]:
    for line in text.splitlines():
        s = line.strip()
        if not s or (comment and s.startswith(comment)):
            continue
        if comment and comment in s:  # trailing comment: "1.2.3.4  # botnet"
            s = s.split(comment, 1)[0].strip()
        if s:
            yield s


def values_text(body: bytes, comment: str) -> Iterator[str]:
    """One indicator per line; the first token (space, comma, ; or | separated)."""
    for line in _lines(_decode(body), comment):
        token = next((t for t in _SPLIT.split(line) if t), None)
        if token:
            yield token


def values_csv(body: bytes, comment: str, column: int) -> Iterator[str]:
    text = "\n".join(_lines(_decode(body), comment))
    try:
        dialect: Any = csv.Sniffer().sniff(text[:4096], delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    for row in csv.reader(io.StringIO(text), dialect):
        if column < len(row) and row[column].strip():
            yield row[column].strip()


def _walk(node: Any, path: list[str]) -> Iterator[str]:
    if isinstance(node, list):
        for x in node:
            yield from _walk(x, path)
        return
    if not path:
        if isinstance(node, str | int) and not isinstance(node, bool):
            yield str(node)
        return
    if isinstance(node, dict):
        yield from _walk(node.get(path[0]), path[1:])


def values_json(body: bytes, path: str | None) -> Iterator[str]:
    """A list of strings, or objects holding the value at ``path`` (dots go
    deeper; lists on the way are walked), e.g. ``data.ip_address``."""
    try:
        doc = json.loads(body)
    except (ValueError, UnicodeDecodeError) as e:
        raise SchemaDriftError(f"not JSON ({e})") from e
    keys = [k for k in (path or "").split(".") if k]
    yield from _walk(doc, keys)


def to_item(raw: str, family: Family, confidence: int) -> Item:
    """Pin the type when the feed says what it holds; a value of another kind
    is checked as that kind and so rejected with a reason."""
    v = raw.strip().strip("\"'")
    if family == "auto":
        return Item(v, None, confidence=confidence, labels=(LABEL,))
    r = guess(v)
    if isinstance(r, Observable) and r.type in FAMILIES[family]:
        return Item(v, r.type, confidence=confidence, labels=(LABEL,))
    return Item(v, _FALLBACK[family], confidence=confidence, labels=(LABEL,))


def parse_spec(spec: FeedSpec, body: bytes) -> Iterator[Item]:
    if spec.format == "json":
        values: Iterator[str] = values_json(body, spec.json_path)
    elif spec.format == "csv":
        values = values_csv(body, spec.comment_char, spec.value_column)
    else:
        values = values_text(body, spec.comment_char)
    n = 0
    for v in values:
        n += 1
        if n > MAX_ITEMS:
            break
        yield to_item(v, spec.ioc_type, spec.confidence)
    if n == 0 and body.strip():
        where = {"json": f"field {spec.json_path or '(top level)'!r}",
                 "csv": f"column {spec.value_column}", "text": "any line"}[spec.format]  # fmt: skip
        raise SchemaDriftError(f"no values found in {where}: check the format and column/field")


def kind_for(verdict: str) -> str:
    """The source kind scoring reads: a "suspicious" list adds suspicion,
    never a malicious verdict on its own (scoring.store.SUSPICIOUS_FEED_KINDS)."""
    return "custom-suspicious" if verdict == "suspicious" else "custom"


def connector_for(spec: FeedSpec, secret: str | None = None) -> type[Connector]:
    """A Connector class for one spec (the key travels on the class: only the
    worker builds these, never anything that renders it)."""
    info = SourceInfo(
        name=spec.name,
        title=spec.title,
        kind=kind_for(spec.verdict),
        homepage=spec.url,
        url=spec.url,
        reliability=spec.reliability,  # type: ignore[arg-type]
        reliability_note="Added by an admin; reliability as they graded it.",
        license="Your own terms with the provider",
        license_url="",
        commercial_use=True,
        redistribution=False,
        upstream=spec.upstream,
        interval=spec.interval,
        min_interval=MIN_INTERVAL,
        default_confidence=spec.confidence,
        tlp=spec.tlp,
        max_bytes=MAX_BYTES,
    )

    class CustomFeedConnector(Connector):
        def __init__(self, api_key: str | None = None) -> None:
            super().__init__(api_key)

        async def fetch(self, http: SafeHttp, checkpoint: Mapping[str, Any]) -> FetchResult:
            headers = {spec.auth_header: secret} if spec.auth_header and secret else None
            return await http.get(
                spec.url,
                headers=headers,
                etag=checkpoint.get("etag"),
                last_modified=checkpoint.get("last_modified"),
                max_bytes=MAX_BYTES,
            )

        def parse(self, body: bytes) -> Iterator[Item]:
            return parse_spec(spec, body)

    CustomFeedConnector.info = info
    CustomFeedConnector.__name__ = f"CustomFeed_{spec.name}"
    return CustomFeedConnector
