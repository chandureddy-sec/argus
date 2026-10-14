"""Feed catalog (ADR 0012): switch sources on and off, and add, edit or
remove feeds of your own without writing a connector.

A custom feed gets an ordinary ``sources`` row (title, schedule, marking,
reliability, health, run history) plus a ``custom_feeds`` row saying how to
fetch and read it. Its API key, if any, is encrypted (``threatlens.vault``)
and never shown again. Every change is audited (``source.*``,
``custom_feed.*``). Callers check roles: all of this is admin-only.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from threatlens import tlp as tlp_rules
from threatlens.connectors import REGISTRY
from threatlens.connectors.base import Connector, MissingKeyError
from threatlens.connectors.custom import FAMILIES, FORMATS, FeedSpec, connector_for, kind_for
from threatlens.kb import KB_REGISTRY
from threatlens.models import (
    TLP_LEVELS,
    AuditLog,
    ConnectorRun,
    CustomFeed,
    Indicator,
    RawDocument,
    Sighting,
    Source,
    utcnow,
)
from threatlens.models import Observable as ObsRow
from threatlens.settings import Settings
from threatlens.vault import VaultError, seal, unseal

PREFIX = "custom_"
MIN_MINUTES, MAX_MINUTES = 15, 7 * 24 * 60
GRADES = ("A", "B", "C", "D", "E", "F")
_SLUG = re.compile(r"[^a-z0-9]+")
_HEADER = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_JSON_PATH = re.compile(r"^[A-Za-z0-9_\-]+(\.[A-Za-z0-9_\-]+)*$")
_FORBIDDEN_HEADERS = frozenset(
    {"host", "cookie", "content-length", "content-type", "transfer-encoding", "connection",
     "if-none-match", "if-modified-since", "accept-encoding", "user-agent"}
)  # fmt: skip


class CatalogError(ValueError):
    """A refused change, in words the admin can act on."""


@dataclass
class FeedForm:
    """What the Add / Edit form sends. ``secret`` empty on an edit keeps the
    stored one; ``clear_secret`` removes it."""

    title: str
    url: str
    format: str = "text"
    ioc_type: str = "auto"
    verdict: str = "malicious"
    confidence: int = 70
    interval_minutes: int = 360
    tlp: str = "TLP:CLEAR"
    reliability: str = "C"
    comment_char: str = "#"
    value_column: int = 0
    json_path: str = ""
    auth_header: str = ""
    secret: str = ""
    clear_secret: bool = False
    upstream: str = ""


def builtin(name: str) -> bool:
    return name in REGISTRY or name in KB_REGISTRY


def _host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def validate(f: FeedForm) -> FeedForm:
    """Normalize and check a form; raises CatalogError with the first problem."""
    f.title = " ".join(f.title.split())
    if not 3 <= len(f.title) <= 80:
        raise CatalogError("Name: 3 to 80 characters")
    f.url = f.url.strip()
    parts = urlsplit(f.url)
    if parts.scheme not in ("http", "https") or not parts.hostname or len(f.url) > 2000:
        raise CatalogError("Feed URL: must be a full http(s):// address")
    if parts.username or parts.password:
        raise CatalogError("Feed URL: don't put credentials in the URL; use the auth header and key fields")
    try:
        ip = ipaddress.ip_address(parts.hostname)
    except ValueError:
        ip = None
    if ip is not None and not ip.is_global:
        raise CatalogError("Feed URL: private and internal addresses can't be fetched")
    if f.format not in FORMATS:
        raise CatalogError("Format: plain text, CSV or JSON")
    if f.ioc_type not in FAMILIES:
        raise CatalogError("Indicator type: unknown")
    if f.verdict not in ("malicious", "suspicious"):
        raise CatalogError("Verdict: malicious or suspicious")
    if not 0 <= f.confidence <= 100:
        raise CatalogError("Confidence: 0 to 100")
    if not MIN_MINUTES <= f.interval_minutes <= MAX_MINUTES:
        raise CatalogError(f"Pull every: {MIN_MINUTES} minutes to 7 days ({MAX_MINUTES} minutes)")
    if f.tlp not in TLP_LEVELS:
        raise CatalogError("TLP: unknown marking")
    if f.reliability not in GRADES:
        raise CatalogError("Reliability: A to F")
    f.comment_char = f.comment_char.strip()
    if len(f.comment_char) > 4:
        raise CatalogError("Comment marker: at most 4 characters")
    if not 0 <= f.value_column <= 255:
        raise CatalogError("Value column: 0 to 255")
    f.json_path = f.json_path.strip()
    if f.json_path and not _JSON_PATH.match(f.json_path):
        raise CatalogError("JSON field: names separated by dots, e.g. data.ip_address")
    f.auth_header = f.auth_header.strip()
    if f.auth_header and (not _HEADER.match(f.auth_header) or f.auth_header.lower() in _FORBIDDEN_HEADERS):
        raise CatalogError("Auth header: a header name such as Authorization, API-Key or x-api-key")
    f.secret = f.secret.strip()
    if f.secret and not f.auth_header:
        raise CatalogError("Auth header: say which header carries the key")
    if len(f.secret) > 4000 or any(c in f.secret for c in "\r\n"):
        raise CatalogError("Auth key: one line, at most 4000 characters")
    f.upstream = _SLUG.sub("-", f.upstream.strip().lower()).strip("-")[:60]
    return f


def spec_of(src: Source, feed: CustomFeed) -> FeedSpec:
    return FeedSpec(
        name=src.name,
        title=src.title,
        url=feed.url,
        format=feed.format,  # type: ignore[arg-type]
        ioc_type=feed.ioc_type,  # type: ignore[arg-type]
        verdict=feed.verdict,  # type: ignore[arg-type]
        confidence=feed.confidence,
        comment_char=feed.comment_char,
        value_column=feed.value_column,
        json_path=feed.json_path,
        auth_header=feed.auth_header,
        tlp=src.tlp_default,
        reliability=src.reliability,
        upstream=src.upstream,
        interval=timedelta(minutes=src.interval_minutes),
    )


async def custom_names(s: AsyncSession) -> set[str]:
    return set(
        (await s.scalars(select(Source.name).join(CustomFeed, CustomFeed.source_id == Source.id))).all()
    )


async def get_custom(s: AsyncSession, name: str) -> tuple[Source, CustomFeed] | None:
    row = (
        await s.execute(
            select(Source, CustomFeed)
            .join(CustomFeed, CustomFeed.source_id == Source.id)
            .where(Source.name == name)
        )
    ).first()
    return (row[0], row[1]) if row else None


async def load_connector(s: AsyncSession, name: str, settings: Settings) -> type[Connector] | None:
    """The connector for a custom feed, or None if there is no such feed. A
    key that can't be decrypted turns into MissingKeyError when the connector
    is built, so the run is recorded as "skipped" with the reason."""
    found = await get_custom(s, name)
    if found is None:
        return None
    src, feed = found
    secret: str | None = None
    problem: str | None = None
    if feed.auth_secret:
        try:
            secret = unseal(settings, feed.auth_secret)
        except VaultError as e:
            problem = str(e)
    cls = connector_for(spec_of(src, feed), secret)
    if problem is None:
        return cls

    class Unreadable(cls):  # type: ignore[valid-type,misc]
        def __init__(self, api_key: str | None = None) -> None:
            raise MissingKeyError(f"{name}: {problem}")

    return Unreadable


async def _unique_name(s: AsyncSession, title: str) -> str:
    base = PREFIX + (_SLUG.sub("_", title.lower()).strip("_")[:40] or "feed")
    taken = set((await s.scalars(select(Source.name).where(Source.name.like(base + "%")))).all())
    name, n = base, 2
    while name in taken or builtin(name):
        name, n = f"{base}_{n}", n + 1
    return name


def _audit(s: AsyncSession, actor: str, action: str, target: str, details: dict[str, Any]) -> None:
    s.add(AuditLog(actor=actor[:100], action=action, target=target, details=details))


def _public(f: FeedForm) -> dict[str, Any]:
    """The form as the audit log records it: everything but the key."""
    return {k: v for k, v in vars(f).items() if k not in ("secret",)} | {"secret_set": bool(f.secret)}


async def create(s: AsyncSession, f: FeedForm, *, actor: str, settings: Settings) -> Source:
    f = validate(f)
    sealed = seal(settings, f.secret) if f.secret else None
    now = utcnow()
    src = Source(
        name=await _unique_name(s, f.title),
        title=f.title,
        kind=kind_for(f.verdict),
        homepage=f.url,
        reliability=f.reliability,
        reliability_note="Added by an admin; reliability as they graded it.",
        credibility=6,
        license="Your own terms with the provider",
        license_url="",
        commercial_use=True,
        redistribution=False,
        attribution=None,
        upstream=f.upstream or f"custom:{_host(f.url)}",
        tlp_default=f.tlp,
        requires_key=bool(sealed),
        enabled=True,
        interval_minutes=f.interval_minutes,
        health="unknown",
        next_run_at=None,  # due now: first pull on the next scheduler tick
        checkpoint={},
    )
    s.add(src)
    await s.flush()
    s.add(
        CustomFeed(
            source_id=src.id, url=f.url, format=f.format, ioc_type=f.ioc_type, verdict=f.verdict,
            confidence=f.confidence, comment_char=f.comment_char, value_column=f.value_column,
            json_path=f.json_path or None, auth_header=f.auth_header or None, auth_secret=sealed,
            created_by=actor[:100], updated_by=actor[:100], created_at=now, updated_at=now,
        )
    )  # fmt: skip
    _audit(s, actor, "custom_feed.create", src.name, _public(f))
    return src


async def edit(s: AsyncSession, name: str, f: FeedForm, *, actor: str, settings: Settings) -> Source:
    found = await get_custom(s, name)
    if found is None:
        raise CatalogError("no such custom feed")
    src, feed = found
    f = validate(f)
    if f.secret:
        feed.auth_secret = seal(settings, f.secret)
    elif f.clear_secret:
        feed.auth_secret = None
    if feed.auth_secret and not f.auth_header:
        raise CatalogError("Auth header: say which header carries the key (or remove the key)")
    reread = (feed.url, feed.format, feed.value_column, feed.json_path, feed.comment_char, feed.ioc_type) != (
        f.url, f.format, f.value_column, f.json_path or None, f.comment_char, f.ioc_type
    )  # fmt: skip
    src.title, src.kind, src.homepage = f.title, kind_for(f.verdict), f.url
    src.reliability, src.tlp_default, src.interval_minutes = f.reliability, f.tlp, f.interval_minutes
    src.upstream = f.upstream or f"custom:{_host(f.url)}"
    src.requires_key = bool(feed.auth_secret)
    feed.url, feed.format, feed.ioc_type, feed.verdict = f.url, f.format, f.ioc_type, f.verdict
    feed.confidence, feed.comment_char, feed.value_column = f.confidence, f.comment_char, f.value_column
    feed.json_path, feed.auth_header = f.json_path or None, f.auth_header or None
    feed.updated_by, feed.updated_at = actor[:100], utcnow()
    if reread:  # read the same document again with the new settings on the next pull
        src.checkpoint = {}
    _audit(s, actor, "custom_feed.update", name, _public(f))
    return src


async def remove(s: AsyncSession, name: str, *, actor: str) -> list[int]:
    """Delete a custom feed with its run history and sightings. Indicators
    that only it reported are revoked (unless an analyst gave a verdict).
    Returns the indicator ids it had reported, to re-score."""
    found = await get_custom(s, name)
    if found is None:
        raise CatalogError("no such custom feed (built-in feeds can only be switched off)")
    src, _ = found
    ids = list((await s.scalars(select(Sighting.indicator_id).where(Sighting.source_id == src.id))).all())
    await s.execute(delete(Sighting).where(Sighting.source_id == src.id))
    others = set(
        (await s.scalars(select(Sighting.indicator_id).where(Sighting.indicator_id.in_(ids)))).all()
    ) if ids else set()  # fmt: skip
    orphans = [i for i in ids if i not in others]
    for i in range(0, len(orphans), 500):
        await s.execute(
            update(Indicator)
            .where(Indicator.id.in_(orphans[i : i + 500]), Indicator.analyst_verdict.is_(None))
            .values(status="revoked", updated_at=utcnow())
        )
    await s.execute(delete(ConnectorRun).where(ConnectorRun.source_id == src.id))
    await s.execute(delete(RawDocument).where(RawDocument.source_id == src.id))
    await s.execute(delete(CustomFeed).where(CustomFeed.source_id == src.id))
    await s.delete(src)
    _audit(s, actor, "custom_feed.delete", name, {"sightings": len(ids), "revoked": len(orphans)})
    return ids


async def set_enabled(s: AsyncSession, name: str, enabled: bool, *, actor: str) -> Source:
    src = await s.scalar(select(Source).where(Source.name == name))
    if src is None:
        raise CatalogError("no such source")
    if src.enabled != enabled:
        src.enabled = enabled
        if enabled:
            src.next_run_at = None  # catch up on the next tick
        _audit(s, actor, "source.enable" if enabled else "source.disable", name, {})
    return src


def collectable(src: Source, custom: set[str]) -> bool:
    return src.name in custom or builtin(src.name)


# ── what a feed has contributed ──────────────────────────────────────────────


async def contribution(s: AsyncSession, source_id: int, clearance: str) -> dict[str, Any]:
    """Indicators this source reported, within the reader's clearance: how
    many, by type and status, how many it alone reports, and the top ones."""
    vis = Indicator.tlp.in_(tlp_rules.readable(clearance))
    base = select(Sighting.indicator_id).where(Sighting.source_id == source_id)
    by_status = dict(
        (await s.execute(
            select(Indicator.status, func.count())
            .where(Indicator.id.in_(base), vis).group_by(Indicator.status)
        )).all()
    )  # fmt: skip
    by_type = dict(
        (await s.execute(
            select(ObsRow.type, func.count()).join(Indicator, Indicator.observable_id == ObsRow.id)
            .where(Indicator.id.in_(base), vis).group_by(ObsRow.type)
        )).all()
    )  # fmt: skip
    shared = (
        select(Sighting.indicator_id)
        .join(Indicator, Indicator.id == Sighting.indicator_id)
        .where(Sighting.indicator_id.in_(base), vis)
        .group_by(Sighting.indicator_id)
        .having(func.count() > 1)
    )
    corroborated = await s.scalar(select(func.count()).select_from(shared.subquery())) or 0
    top = (
        await s.execute(
            select(Indicator, ObsRow)
            .join(ObsRow, Indicator.observable_id == ObsRow.id)
            .where(Indicator.id.in_(base), vis, Indicator.status == "active")
            .order_by(Indicator.priority_score.desc().nulls_last(), Indicator.id.desc())
            .limit(10)
        )
    ).all()
    total = sum(int(v) for v in by_status.values())
    return {
        "total": total,
        "by_status": {str(k): int(v) for k, v in by_status.items()},
        "by_type": {str(k): int(v) for k, v in sorted(by_type.items(), key=lambda kv: -kv[1])},
        "corroborated": int(corroborated),
        "only_here": max(0, total - int(corroborated)),
        "top": [(ind, obs) for ind, obs in top],
    }


async def runs(s: AsyncSession, source_id: int, limit: int = 50) -> list[ConnectorRun]:
    return list(
        (
            await s.scalars(
                select(ConnectorRun)
                .where(ConnectorRun.source_id == source_id)
                .order_by(ConnectorRun.started_at.desc(), ConnectorRun.id.desc())
                .limit(limit)
            )
        ).all()
    )
