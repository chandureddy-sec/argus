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
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from threatlens import tlp as tlp_rules
from threatlens.connectors.base import Connector, Item, SchemaDriftError, SourceInfo, parse_time
from threatlens.ioc.normalize import guess
from threatlens.ioc.types import IOCType, Observable
from threatlens.net.http import FetchResult, SafeHttp, make_transport

Format = Literal["text", "csv", "json", "taxii", "misp"]
Family = Literal["auto", "ip", "domain", "url", "hash"]
FORMATS: tuple[Format, ...] = ("text", "csv", "json", "taxii", "misp")
TAXII_MEDIA = "application/taxii+json;version=2.1"
TAXII_PAGES = 50  # pages per pull (x 1000 objects)
MISP_PAGE = 5000
MISP_PAGES = 20
MISP_FIRST_PULL = "30d"  # how far back the first MISP pull reaches
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
    allow_internal: bool = False  # may reach a private LAN address (ADR 0019)
    allow_loopback: bool = False  # ... and this host (development only)


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


# ── TAXII 2.1 and MISP readers (ADR 0019) ──────────────────────────────────

_PATTERN = re.compile(r"\[\s*([a-z0-9-]+:[A-Za-z0-9_.'-]+)\s*=\s*'((?:[^'\\]|\\.)*)'\s*\]")
_PATHS: dict[str, IOCType] = {
    "ipv4-addr:value": IOCType.IPV4,
    "ipv6-addr:value": IOCType.IPV6,
    "domain-name:value": IOCType.DOMAIN,
    "url:value": IOCType.URL,
    "email-addr:value": IOCType.EMAIL,
    "file:hashes.MD5": IOCType.MD5,
    "file:hashes.'MD5'": IOCType.MD5,
    "file:hashes.'SHA-1'": IOCType.SHA1,
    "file:hashes.SHA1": IOCType.SHA1,
    "file:hashes.'SHA-256'": IOCType.SHA256,
    "file:hashes.SHA256": IOCType.SHA256,
}
_NETS = {IOCType.IPV4: IOCType.IPV4_NET, IOCType.IPV6: IOCType.IPV6_NET}


def pattern_values(pattern: str) -> list[tuple[IOCType, str]]:
    """The (type, value) pairs of a STIX pattern's simple equality comparisons
    (``[ipv4-addr:value = '1.2.3.4'] OR [...]``); anything else is skipped."""
    out = []
    for path, raw in _PATTERN.findall(pattern or ""):
        t = _PATHS.get(path)
        if t is None:
            continue
        v = raw.replace("\\'", "'").replace("\\\\", "\\")
        if t in _NETS and "/" in v:
            t = _NETS[t]
        out.append((t, v))
    return out


def _marking_tlp(refs: Any, default: str) -> str:
    from threatlens.share.stix import MARKING_TLP

    levels = [MARKING_TLP[r] for r in refs or [] if r in MARKING_TLP]
    level = default
    for lv in levels:
        level = tlp_rules.stricter(level, lv)
    return level


def parse_taxii(spec: FeedSpec, body: bytes) -> Iterator[Item]:
    try:
        doc = json.loads(body)
    except (ValueError, UnicodeDecodeError) as e:
        raise SchemaDriftError(f"TAXII: not JSON ({e})") from e
    if not isinstance(doc, dict) or not isinstance(doc.get("objects", []), list):
        raise SchemaDriftError("TAXII: expected an envelope with an objects list")
    for o in doc.get("objects", []):
        if not isinstance(o, dict) or o.get("type") != "indicator" or o.get("revoked"):
            continue
        if o.get("pattern_type", "stix") != "stix":
            continue
        conf = o.get("confidence")
        confidence = int(conf) if isinstance(conf, int) and 0 <= conf <= 100 else spec.confidence
        labels = (*tuple(str(x)[:60] for x in (o.get("labels") or []) if isinstance(x, str))[:10], LABEL)
        for t, v in pattern_values(str(o.get("pattern", ""))):
            yield Item(
                v, t, seen_at=parse_time(o.get("modified")), confidence=confidence, labels=labels,
                context={"stix_id": str(o.get("id", ""))[:100], "name": str(o.get("name", ""))[:200]},
                tlp=_marking_tlp(o.get("object_marking_refs"), spec.tlp),
            )  # fmt: skip


_MISP_TYPES: dict[str, IOCType | None] = {
    "ip-dst": None, "ip-src": None, "domain": IOCType.DOMAIN, "hostname": IOCType.DOMAIN,
    "url": IOCType.URL, "md5": IOCType.MD5, "sha1": IOCType.SHA1, "sha256": IOCType.SHA256,
    "email-src": IOCType.EMAIL, "email-dst": IOCType.EMAIL,
}  # fmt: skip
_MISP_TLP = {
    "tlp:white": "TLP:CLEAR",
    "tlp:clear": "TLP:CLEAR",
    "tlp:green": "TLP:GREEN",
    "tlp:amber": "TLP:AMBER",
    "tlp:amber+strict": "TLP:AMBER+STRICT",
    "tlp:red": "TLP:RED",
}


def misp_value(atype: str, value: str) -> tuple[IOCType | None, str] | None:
    """MISP attribute → (type or None to guess, value); composite types keep their indicator half."""
    base, _, second = atype.partition("|")
    if second:  # ip-dst|port, domain|ip, filename|sha256 ...
        left, _, right = value.partition("|")
        if base in ("ip-dst", "ip-src", "domain", "hostname"):
            atype, value = base, left
        elif second in ("md5", "sha1", "sha256"):
            atype, value = second, right
        else:
            return None
    if atype not in _MISP_TYPES or not value.strip():
        return None
    return _MISP_TYPES[atype], value.strip()


def parse_misp(spec: FeedSpec, body: bytes) -> Iterator[Item]:
    try:
        doc = json.loads(body)
    except (ValueError, UnicodeDecodeError) as e:
        raise SchemaDriftError(f"MISP: not JSON ({e})") from e
    attrs = (doc.get("response") or {}).get("Attribute") if isinstance(doc, dict) else None
    if not isinstance(attrs, list):
        raise SchemaDriftError("MISP: expected response.Attribute (an attributes/restSearch answer)")
    for a in attrs:
        if not isinstance(a, dict) or a.get("deleted") in (True, "1", 1):
            continue
        mv = misp_value(str(a.get("type", "")), str(a.get("value", "")))
        if mv is None:
            continue
        t, v = mv
        ev = a.get("Event")
        event: dict[str, Any] = ev if isinstance(ev, dict) else {}
        raw_tags = [*(a.get("Tag") or []), *(event.get("Tag") or [])]
        tags = [str(t_.get("name", "")) for t_ in raw_tags if isinstance(t_, dict)]
        tlp = spec.tlp
        for tag in tags:
            if tag.lower() in _MISP_TLP:
                tlp = tlp_rules.stricter(tlp, _MISP_TLP[tag.lower()])
        labels = (*tuple(x[:60] for x in tags if x and ":" not in x)[:8], LABEL)
        ts = str(a.get("timestamp", ""))
        seen = datetime.fromtimestamp(int(ts), tz=UTC) if ts.isdigit() else None
        context = {
            "misp_event": str(event.get("info", ""))[:200],
            "event_id": str(a.get("event_id", ""))[:20],
            "category": str(a.get("category", ""))[:60],
            "misp_type": str(a.get("type", ""))[:40],
        }
        yield Item(v, t, seen_at=seen, confidence=spec.confidence, labels=labels, tlp=tlp, context=context)


def parse_spec(spec: FeedSpec, body: bytes) -> Iterator[Item]:
    if spec.format == "taxii":
        yield from parse_taxii(spec, body)
        return
    if spec.format == "misp":
        yield from parse_misp(spec, body)
        return
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


def _objects_url(url: str) -> str:
    """A TAXII collection URL or its objects URL → the objects URL."""
    u = url.rstrip("/")
    return u + "/" if u.endswith("/objects") else u + "/objects/"


async def fetch_taxii(
    http: SafeHttp, url: str, auth: Mapping[str, str], checkpoint: Mapping[str, Any]
) -> FetchResult:
    """Every object added since the last pull, following ``next`` (TAXII 2.1 §3.4)."""
    headers = {"Accept": TAXII_MEDIA, **auth}
    since = checkpoint.get("taxii_added_last")
    base: dict[str, str] = {"limit": "1000", **({"added_after": since} if since else {})}
    params = dict(base)
    objects: list[Any] = []
    last = since or ""
    target = _objects_url(url)
    for _ in range(TAXII_PAGES):
        res = await http.get(target, params=params, headers=headers, max_bytes=MAX_BYTES)
        try:
            doc = json.loads(res.body) if res.body.strip() else {}
        except ValueError as e:
            raise SchemaDriftError(f"TAXII: not JSON ({e})") from e
        objects += doc.get("objects") or []
        last = res.headers.get("x-taxii-date-added-last") or last
        if not doc.get("more") or not doc.get("next"):
            break
        params = {**base, "next": str(doc["next"])}
    body = json.dumps({"objects": objects}).encode()
    return FetchResult(target, 200, body, "application/json", None, None, {"taxii_added_last": last})


async def fetch_misp(
    http: SafeHttp, url: str, auth: Mapping[str, str], checkpoint: Mapping[str, Any]
) -> FetchResult:
    """Published to_ids attributes changed since the last pull (attributes/restSearch)."""
    headers = {"Accept": "application/json", **auth}
    since = checkpoint.get("misp_timestamp")
    query: dict[str, Any] = {
        "returnFormat": "json",
        "to_ids": True,
        "published": True,
        "deleted": False,
        "includeEventTags": True,
        "enforceWarninglist": True,
        "limit": MISP_PAGE,
    }
    if since:
        query["timestamp"] = since
    else:
        query["last"] = MISP_FIRST_PULL
    attrs: list[Any] = []
    for page in range(1, MISP_PAGES + 1):
        res = await http.post_json(url, {**query, "page": page}, headers=headers, max_bytes=MAX_BYTES)
        try:
            doc = json.loads(res.body)
        except ValueError as e:
            raise SchemaDriftError(f"MISP: not JSON ({e})") from e
        got = ((doc.get("response") or {}).get("Attribute") or []) if isinstance(doc, dict) else []
        attrs += got
        if len(got) < MISP_PAGE:
            break
    newest = max((int(a["timestamp"]) for a in attrs if str(a.get("timestamp", "")).isdigit()), default=None)
    mark = str(newest + 1) if newest is not None else (since or "")
    body = json.dumps({"response": {"Attribute": attrs}}).encode()
    return FetchResult(url, 200, body, "application/json", None, None, {"misp_timestamp": mark})


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
            if spec.allow_internal:
                # An admin opened an internal network for this feed only: a
                # client of its own, still refusing link-local/metadata.
                transport = make_transport(internal=True, loopback=spec.allow_loopback)
                async with SafeHttp(transport=transport, allow_http=True, timeout=60.0) as own:
                    return await self._fetch(own, checkpoint)
            return await self._fetch(http, checkpoint)

        async def _fetch(self, http: SafeHttp, checkpoint: Mapping[str, Any]) -> FetchResult:
            headers = {spec.auth_header: secret} if spec.auth_header and secret else {}
            if spec.format == "taxii":
                return await fetch_taxii(http, spec.url, headers, checkpoint)
            if spec.format == "misp":
                return await fetch_misp(http, spec.url, headers, checkpoint)
            return await http.get(
                spec.url,
                headers=headers or None,
                etag=checkpoint.get("etag"),
                last_modified=checkpoint.get("last_modified"),
                max_bytes=MAX_BYTES,
            )

        def next_checkpoint(self, result: FetchResult, checkpoint: Mapping[str, Any]) -> dict[str, Any]:
            cp = super().next_checkpoint(result, checkpoint)
            for k in ("taxii_added_last", "misp_timestamp"):
                if result.headers.get(k):
                    cp[k] = result.headers[k]
            return cp

        def parse(self, body: bytes) -> Iterator[Item]:
            return parse_spec(spec, body)

    CustomFeedConnector.info = info
    CustomFeedConnector.__name__ = f"CustomFeed_{spec.name}"
    return CustomFeedConnector
