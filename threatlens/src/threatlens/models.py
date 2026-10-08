"""Database models (see docs/DATA_MODEL.md for the reasoning behind each
table, constraint and index).

Types are portable: JSON maps to JSONB on PostgreSQL, and nothing else is
Postgres-only, so the same models back the SQLite-based unit tests.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from threatlens.db import Base

JSONType = JSON().with_variant(JSONB(), "postgresql")
# SQLite only auto-increments INTEGER PRIMARY KEY, not BIGINT.
BigID = BigInteger().with_variant(Integer(), "sqlite")


def utcnow() -> datetime:
    return datetime.now(UTC)


def _ts(**kw: Any) -> Any:
    return mapped_column(DateTime(timezone=True), **kw)


INDICATOR_STATUSES = ("new", "active", "expired", "revoked", "false_positive")
ROLES = ("admin", "analyst", "viewer")
TLP_LEVELS = ("TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED")


class AppMeta(Base):
    """Facts about the deployment itself (created by the baseline migration)."""

    __tablename__ = "app_meta"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text)
    updated_at: Mapped[datetime] = _ts(default=utcnow)


class Source(Base):
    """A feed or enrichment provider, its licence terms and its health."""

    __tablename__ = "sources"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    title: Mapped[str] = mapped_column(String(200))
    kind: Mapped[str] = mapped_column(String(32))
    homepage: Mapped[str] = mapped_column(Text)
    reliability: Mapped[str] = mapped_column(String(1))  # Admiralty grade A-F
    reliability_note: Mapped[str] = mapped_column(Text, default="")
    license: Mapped[str] = mapped_column(String(200))
    license_url: Mapped[str] = mapped_column(Text)
    commercial_use: Mapped[bool] = mapped_column(Boolean)
    redistribution: Mapped[bool] = mapped_column(Boolean)
    attribution: Mapped[str | None] = mapped_column(Text)
    upstream: Mapped[str] = mapped_column(String(64))
    tlp_default: Mapped[str] = mapped_column(String(20), default="TLP:CLEAR")
    requires_key: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    interval_minutes: Mapped[int] = mapped_column(Integer)
    health: Mapped[str] = mapped_column(String(16), default="unknown")  # ok|degraded|failing|skipped|unknown
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    last_run_at: Mapped[datetime | None] = _ts()
    last_success_at: Mapped[datetime | None] = _ts()
    next_run_at: Mapped[datetime | None] = _ts()
    last_error: Mapped[str | None] = mapped_column(Text)
    checkpoint: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    created_at: Mapped[datetime] = _ts(default=utcnow)
    updated_at: Mapped[datetime] = _ts(default=utcnow, onupdate=utcnow)

    __table_args__ = (CheckConstraint("reliability IN ('A','B','C','D','E','F')", name="reliability"),)


class RawDocument(Base):
    """One fetched payload, kept for reprocessing and provenance."""

    __tablename__ = "raw_documents"

    id: Mapped[int] = mapped_column(BigID, primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id", ondelete="CASCADE"))
    fetched_at: Mapped[datetime] = _ts(default=utcnow)
    url: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str] = mapped_column(String(64))
    size: Mapped[int] = mapped_column(BigInteger)
    content_type: Mapped[str] = mapped_column(String(200), default="")
    payload_ref: Mapped[str] = mapped_column(Text)  # path under TL_DATA_DIR
    parse_status: Mapped[str] = mapped_column(String(16), default="pending")  # pending|parsed|failed
    parse_error: Mapped[str | None] = mapped_column(Text)
    items: Mapped[int] = mapped_column(Integer, default=0)

    __table_args__ = (
        UniqueConstraint("source_id", "sha256"),
        Index("ix_raw_documents_source_fetched", "source_id", "fetched_at"),
    )


class Observable(Base):
    """A normalized value (IP, domain, hash…), unique by canonical_key."""

    __tablename__ = "observables"

    id: Mapped[int] = mapped_column(BigID, primary_key=True)
    type: Mapped[str] = mapped_column(String(32))
    value: Mapped[str] = mapped_column(Text)
    canonical_key: Mapped[str] = mapped_column(Text, unique=True)
    defanged: Mapped[str] = mapped_column(Text)
    first_seen: Mapped[datetime] = _ts(default=utcnow)
    last_seen: Mapped[datetime] = _ts(default=utcnow)
    sightings_count: Mapped[int] = mapped_column(Integer, default=0)

    indicator: Mapped[Indicator | None] = relationship(back_populates="observable", uselist=False)

    __table_args__ = (Index("ix_observables_type_last_seen", "type", "last_seen"),)


class Indicator(Base):
    """The platform's assertion about an observable: status, confidence,
    TLP and (from Phase 4) a priority score with its full breakdown."""

    __tablename__ = "indicators"

    id: Mapped[int] = mapped_column(BigID, primary_key=True)
    observable_id: Mapped[int] = mapped_column(ForeignKey("observables.id", ondelete="CASCADE"), unique=True)
    pattern: Mapped[str | None] = mapped_column(Text)  # STIX 2.1 pattern; None for vulnerabilities
    valid_from: Mapped[datetime] = _ts(default=utcnow)
    valid_until: Mapped[datetime | None] = _ts()
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    priority_score: Mapped[float | None] = mapped_column()
    score_breakdown: Mapped[dict[str, Any] | None] = mapped_column(JSONType)
    tlp: Mapped[str] = mapped_column(String(20), default="TLP:CLEAR")
    status: Mapped[str] = mapped_column(String(16), default="active")
    labels: Mapped[list[str]] = mapped_column(JSONType, default=list)
    allowlist_reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = _ts(default=utcnow)
    updated_at: Mapped[datetime] = _ts(default=utcnow, onupdate=utcnow)

    observable: Mapped[Observable] = relationship(back_populates="indicator")
    sightings: Mapped[list[Sighting]] = relationship(back_populates="indicator")

    __table_args__ = (
        CheckConstraint(
            "status IN ('new','active','expired','revoked','false_positive')",
            name="status",
        ),
        CheckConstraint("confidence BETWEEN 0 AND 100", name="confidence"),
        Index("ix_indicators_status_updated", "status", "updated_at"),
    )


class Sighting(Base):
    """A source's report of an indicator. One row per (indicator, source):
    re-ingesting updates last_seen and count instead of adding rows, which is
    what makes collection idempotent."""

    __tablename__ = "sightings"

    id: Mapped[int] = mapped_column(BigID, primary_key=True)
    indicator_id: Mapped[int] = mapped_column(ForeignKey("indicators.id", ondelete="CASCADE"))
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id", ondelete="CASCADE"))
    raw_document_id: Mapped[int | None] = mapped_column(ForeignKey("raw_documents.id", ondelete="SET NULL"))
    first_seen: Mapped[datetime] = _ts(default=utcnow)
    last_seen: Mapped[datetime] = _ts(default=utcnow)
    times_reported: Mapped[int] = mapped_column(Integer, default=1)
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    labels: Mapped[list[str]] = mapped_column(JSONType, default=list)
    context: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    updated_at: Mapped[datetime] = _ts(default=utcnow, onupdate=utcnow)

    indicator: Mapped[Indicator] = relationship(back_populates="sightings")
    source: Mapped[Source] = relationship()

    __table_args__ = (
        UniqueConstraint("indicator_id", "source_id"),
        Index("ix_sightings_source_last_seen", "source_id", "last_seen"),
    )


class AllowlistEntry(Base):
    """Values that must not become active indicators (effect=suppress) or
    that get a warning label (effect=flag)."""

    __tablename__ = "allowlist_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(16))  # domain | cidr
    value: Mapped[str] = mapped_column(Text)
    effect: Mapped[str] = mapped_column(String(16))  # suppress | flag
    reason: Mapped[str] = mapped_column(Text)
    origin: Mapped[str] = mapped_column(String(32))  # tranco | org_profile | cloudflare | fastly | manual
    created_by: Mapped[str] = mapped_column(String(100), default="system")
    created_at: Mapped[datetime] = _ts(default=utcnow)

    __table_args__ = (
        UniqueConstraint("kind", "value", "origin"),
        CheckConstraint("kind IN ('domain','cidr')", name="kind"),
        CheckConstraint("effect IN ('suppress','flag')", name="effect"),
    )


class ConnectorRun(Base):
    """One collection attempt — the raw material for feed scorecards."""

    __tablename__ = "connector_runs"

    id: Mapped[int] = mapped_column(BigID, primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id", ondelete="CASCADE"))
    started_at: Mapped[datetime] = _ts(default=utcnow)
    finished_at: Mapped[datetime | None] = _ts()
    status: Mapped[str] = mapped_column(String(16))  # success|not_modified|unchanged|skipped|failed
    http_status: Mapped[int | None] = mapped_column(Integer)
    raw_document_id: Mapped[int | None] = mapped_column(ForeignKey("raw_documents.id", ondelete="SET NULL"))
    items_total: Mapped[int] = mapped_column(Integer, default=0)
    items_new: Mapped[int] = mapped_column(Integer, default=0)
    items_updated: Mapped[int] = mapped_column(Integer, default=0)
    items_rejected: Mapped[int] = mapped_column(Integer, default=0)
    items_allowlisted: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (Index("ix_connector_runs_source_started", "source_id", "started_at"),)


class ApiKey(Base):
    """An API credential. Only the SHA-256 of the key is stored."""

    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    prefix: Mapped[str] = mapped_column(String(16))
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    role: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[datetime] = _ts(default=utcnow)
    last_used_at: Mapped[datetime | None] = _ts()
    expires_at: Mapped[datetime | None] = _ts()
    revoked_at: Mapped[datetime | None] = _ts()

    __table_args__ = (CheckConstraint("role IN ('admin','analyst','viewer')", name="role"),)


class AuditLog(Base):
    """Append-only record of security-relevant changes."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigID, primary_key=True)
    at: Mapped[datetime] = _ts(default=utcnow)
    actor: Mapped[str] = mapped_column(String(100))
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(Text, default="")
    details: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)

    __table_args__ = (Index("ix_audit_log_at", "at"),)
