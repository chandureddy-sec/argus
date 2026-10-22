"""Database models (see docs/DATA_MODEL.md for the reasoning behind each
table, constraint and index).

Types are portable: JSON maps to JSONB on PostgreSQL, and nothing else is
Postgres-only, so the same models back the SQLite-based unit tests.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    Float,
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
_CLEARANCE_CHECK = "tlp_clearance IN ('TLP:CLEAR','TLP:GREEN','TLP:AMBER','TLP:AMBER+STRICT','TLP:RED')"
_TLP_CHECK = "tlp IN ('TLP:CLEAR','TLP:GREEN','TLP:AMBER','TLP:AMBER+STRICT','TLP:RED')"


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
    credibility: Mapped[int] = mapped_column(Integer, default=6)  # Admiralty information credibility 1-6
    # Analyst feedback on indicators this source reported (Phase 4): the
    # tallies and the weight factor derived from them (scoring.feedback).
    feedback_tp: Mapped[int] = mapped_column(Integer, default=0)
    feedback_fp: Mapped[int] = mapped_column(Integer, default=0)
    weight_factor: Mapped[float] = mapped_column(Float, default=1.0)
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

    __table_args__ = (
        CheckConstraint("reliability IN ('A','B','C','D','E','F')", name="reliability"),
        CheckConstraint("credibility BETWEEN 1 AND 6", name="credibility"),
    )


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

    __table_args__ = (
        # Lists newest first per type, with id as the tie-breaker: no sort step (docs/PERFORMANCE.md).
        Index("ix_observables_type_seen", "type", "last_seen", "id"),
        # Substring search (Argus and /indicators?q=): trigram indexes, Postgres only.
        Index(
            "ix_observables_value_trgm",
            "value",
            postgresql_using="gin",
            postgresql_ops={"value": "gin_trgm_ops"},
        ),
        Index(
            "ix_observables_defanged_trgm",
            "defanged",
            postgresql_using="gin",
            postgresql_ops={"defanged": "gin_trgm_ops"},
        ),
    )


class Indicator(Base):
    """The platform's assertion about an observable: status, confidence,
    TLP and (from Phase 4) a priority score with its full breakdown."""

    __tablename__ = "indicators"

    id: Mapped[int] = mapped_column(BigID, primary_key=True)
    observable_id: Mapped[int] = mapped_column(ForeignKey("observables.id", ondelete="CASCADE"), unique=True)
    # Deterministic STIX id (uuid5 of the canonical key); graph edges point at it.
    stix_id: Mapped[str | None] = mapped_column(String(100), unique=True)
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
    # The latest analyst feedback (tp | fp); the full history is in ``verdicts``.
    analyst_verdict: Mapped[str | None] = mapped_column(String(8))
    analyst_verdict_by: Mapped[str | None] = mapped_column(String(100))
    analyst_verdict_at: Mapped[datetime | None] = _ts()
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
        CheckConstraint("analyst_verdict IN ('tp','fp')", name="analyst_verdict"),
        Index("ix_indicators_status_updated", "status", "updated_at"),
        Index("ix_indicators_status_priority", "status", "priority_score"),
        Index("ix_indicators_created", "created_at", "id"),  # Argus lists, products, calendar
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
    status: Mapped[str] = mapped_column(String(16))  # success|partial|not_modified|unchanged|skipped|failed
    http_status: Mapped[int | None] = mapped_column(Integer)
    raw_document_id: Mapped[int | None] = mapped_column(ForeignKey("raw_documents.id", ondelete="SET NULL"))
    items_total: Mapped[int] = mapped_column(Integer, default=0)
    items_new: Mapped[int] = mapped_column(Integer, default=0)
    items_updated: Mapped[int] = mapped_column(Integer, default=0)
    items_rejected: Mapped[int] = mapped_column(Integer, default=0)
    items_allowlisted: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    note: Mapped[str | None] = mapped_column(Text)  # e.g. "loaded enterprise-attack 19.2"

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
    tlp_clearance: Mapped[str | None] = mapped_column(String(20))  # None: the role's default (tlp.py)

    __table_args__ = (
        CheckConstraint("role IN ('admin','analyst','viewer')", name="role"),
        CheckConstraint(_CLEARANCE_CHECK, name="tlp_clearance"),
    )


class User(Base):
    """A person who signs in to the analyst UI with a username and password.

    ``login`` is the case-folded username used for lookups (unique); ``name``
    keeps it as typed for display. Only a salted scrypt hash of the password
    is stored (see ``threatlens.users``). API keys stay separate: they are for
    programs such as ReconX, not for people.
    """

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    login: Mapped[str] = mapped_column(String(100), unique=True)
    name: Mapped[str] = mapped_column(String(100))
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[datetime] = _ts(default=utcnow)
    password_changed_at: Mapped[datetime] = _ts(default=utcnow)
    last_login_at: Mapped[datetime | None] = _ts()
    disabled_at: Mapped[datetime | None] = _ts()
    tlp_clearance: Mapped[str | None] = mapped_column(String(20))  # None: the role's default (tlp.py)
    totp_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    totp_enabled_at: Mapped[datetime | None] = _ts(nullable=True)
    sso_provider: Mapped[str | None] = mapped_column(String(32), nullable=True)
    sso_id: Mapped[str | None] = mapped_column(String(200), nullable=True)

    __table_args__ = (
        CheckConstraint("role IN ('admin','analyst','viewer')", name="role"),
        CheckConstraint(_CLEARANCE_CHECK, name="tlp_clearance"),
    )


class Verdict(Base):
    """Analyst feedback on an indicator, append-only (Phase 4). The latest
    row is mirrored on ``indicators.analyst_verdict``; source weights are
    recomputed from the latest verdict per indicator."""

    __tablename__ = "verdicts"

    id: Mapped[int] = mapped_column(BigID, primary_key=True)
    indicator_id: Mapped[int] = mapped_column(ForeignKey("indicators.id", ondelete="CASCADE"))
    verdict: Mapped[str] = mapped_column(String(8))  # tp | fp | reset
    actor: Mapped[str] = mapped_column(String(100))
    note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = _ts(default=utcnow)

    __table_args__ = (
        CheckConstraint("verdict IN ('tp','fp','reset')", name="verdict"),
        Index("ix_verdicts_indicator_created", "indicator_id", "created_at"),
    )


class Note(Base):
    """An analyst's note on an indicator (Phase 5). Shown to whoever may read
    the indicator; the note carries no TLP of its own."""

    __tablename__ = "notes"

    id: Mapped[int] = mapped_column(BigID, primary_key=True)
    indicator_id: Mapped[int] = mapped_column(ForeignKey("indicators.id", ondelete="CASCADE"))
    author: Mapped[str] = mapped_column(String(100))
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = _ts(default=utcnow)

    __table_args__ = (Index("ix_notes_indicator_created", "indicator_id", "created_at"),)


CASE_STATUSES = ("open", "closed")
CASE_SEVERITIES = ("low", "medium", "high", "critical")
CASE_ITEM_KINDS = ("indicator", "vulnerability", "entity", "observable", "note")


class Case(Base):
    """An investigation: evidence items, notes and a documented conclusion
    (Phase 5). Its TLP is at least as strict as its strictest item."""

    __tablename__ = "cases"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(16), default="open")
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    tlp: Mapped[str] = mapped_column(String(20), default="TLP:AMBER")
    summary: Mapped[str] = mapped_column(Text, default="")
    conclusion: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = _ts(default=utcnow)
    updated_at: Mapped[datetime] = _ts(default=utcnow)
    closed_at: Mapped[datetime | None] = _ts()

    items: Mapped[list[CaseItem]] = relationship(
        back_populates="case", cascade="all, delete-orphan", order_by="CaseItem.id"
    )

    __table_args__ = (
        CheckConstraint("status IN ('open','closed')", name="status"),
        CheckConstraint("severity IN ('low','medium','high','critical')", name="severity"),
        CheckConstraint(_TLP_CHECK, name="tlp"),
        Index("ix_cases_status_updated", "status", "updated_at"),
    )


class CaseItem(Base):
    """One piece of evidence in a case, with a snapshot of what the platform
    said about it when it was added (so the case reads the same later)."""

    __tablename__ = "case_items"

    id: Mapped[int] = mapped_column(BigID, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(16))
    ref: Mapped[str] = mapped_column(String(200), default="")
    label: Mapped[str] = mapped_column(Text, default="")
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    note: Mapped[str] = mapped_column(Text, default="")
    tlp: Mapped[str] = mapped_column(String(20), default="TLP:CLEAR")
    added_by: Mapped[str] = mapped_column(String(100))
    added_at: Mapped[datetime] = _ts(default=utcnow)

    case: Mapped[Case] = relationship(back_populates="items")

    __table_args__ = (
        CheckConstraint("kind IN ('indicator','vulnerability','entity','observable','note')", name="kind"),
        CheckConstraint(_TLP_CHECK, name="tlp"),
        Index("ix_case_items_case_added", "case_id", "added_at"),
    )


class SavedSearch(Base):
    """A named UI view (search or filtered list) saved by one account."""

    __tablename__ = "saved_searches"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner: Mapped[str] = mapped_column(String(120))  # "user:<id>" or "key:<id>"
    name: Mapped[str] = mapped_column(String(100))
    query: Mapped[str] = mapped_column(Text)  # a path under /ui with its query string
    created_at: Mapped[datetime] = _ts(default=utcnow)

    __table_args__ = (UniqueConstraint("owner", "name"),)


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


# ── knowledge base (Phase 2) ─────────────────────────────────────────────────


class Entity(Base):
    """A STIX domain object: ATT&CK techniques, tactics, groups (intrusion
    sets), software (malware, tools), campaigns, mitigations, detection
    objects, plus malware and actors named by feeds that ATT&CK lacks.
    The original STIX object is kept in ``stix``."""

    __tablename__ = "entities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    stix_id: Mapped[str] = mapped_column(String(100), unique=True)
    type: Mapped[str] = mapped_column(String(40))
    name: Mapped[str] = mapped_column(Text)
    external_id: Mapped[str | None] = mapped_column(String(32))  # T1059.001, S0367, G0102, TA0002
    description: Mapped[str] = mapped_column(Text, default="")
    aliases: Mapped[list[str]] = mapped_column(JSONType, default=list)
    domains: Mapped[list[str]] = mapped_column(JSONType, default=list)  # enterprise-attack, ...
    platforms: Mapped[list[str]] = mapped_column(JSONType, default=list)
    tactics: Mapped[list[str]] = mapped_column(JSONType, default=list)  # kill-chain phase shortnames
    is_subtechnique: Mapped[bool] = mapped_column(Boolean, default=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    deprecated: Mapped[bool] = mapped_column(Boolean, default=False)
    version: Mapped[str | None] = mapped_column(String(16))  # x_mitre_version
    stix_modified: Mapped[datetime | None] = _ts()
    origin: Mapped[str] = mapped_column(String(16))  # attack | feed
    source_id: Mapped[int | None] = mapped_column(ForeignKey("sources.id", ondelete="SET NULL"))
    stix: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    created_at: Mapped[datetime] = _ts(default=utcnow)
    updated_at: Mapped[datetime] = _ts(default=utcnow, onupdate=utcnow)

    __table_args__ = (
        Index("ix_entities_type_name", "type", "name"),
        Index("ix_entities_external_id", "external_id"),
    )


class EntityAlias(Base):
    """Normalized names (lower-case alphanumerics) for resolving the free-text
    malware and actor names feeds use ("QakBot", "Qbot") to entities."""

    __tablename__ = "entity_aliases"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    entity_id: Mapped[int] = mapped_column(ForeignKey("entities.id", ondelete="CASCADE"))
    alias_key: Mapped[str] = mapped_column(String(200))

    __table_args__ = (
        UniqueConstraint("alias_key", "entity_id"),
        Index("ix_entity_aliases_entity", "entity_id"),
    )


class Relationship(Base):
    """A directed, sourced edge between two graph nodes, each named by its
    STIX id: an entity, a vulnerability or an indicator. Polymorphic ends
    (no foreign keys) keep one table for every edge kind; ``origin`` says how
    the edge was obtained and ``provenance`` holds the evidence."""

    __tablename__ = "relationships"

    id: Mapped[int] = mapped_column(BigID, primary_key=True)
    stix_id: Mapped[str] = mapped_column(String(100), unique=True)
    src_ref: Mapped[str] = mapped_column(String(100))
    rel_type: Mapped[str] = mapped_column(String(40))
    dst_ref: Mapped[str] = mapped_column(String(100))
    # attack: an ATT&CK relationship; attack-mention: a CVE named in ATT&CK text;
    # feed: a field of a feed record; identity: same identifier (indicator <-> CVE)
    origin: Mapped[str] = mapped_column(String(16))
    scope: Mapped[str | None] = mapped_column(String(40))  # ATT&CK domain, or feed source name
    description: Mapped[str] = mapped_column(Text, default="")
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    source_id: Mapped[int | None] = mapped_column(ForeignKey("sources.id", ondelete="SET NULL"))
    provenance: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen: Mapped[datetime] = _ts(default=utcnow)
    last_seen: Mapped[datetime] = _ts(default=utcnow)

    __table_args__ = (
        Index("ix_relationships_src", "src_ref", "rel_type"),
        Index("ix_relationships_dst", "dst_ref", "rel_type"),
        Index("ix_relationships_origin_scope", "origin", "scope"),
    )


class Vulnerability(Base):
    """A CVE with what NVD, CISA KEV, EPSS and OSV say about it. A row can
    exist before NVD has been asked (``nvd_modified`` is null): KEV entries,
    feed indicators and ATT&CK text create such stubs, and NVD fills them."""

    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(32), unique=True)
    stix_id: Mapped[str] = mapped_column(String(100), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    published: Mapped[datetime | None] = _ts()
    nvd_modified: Mapped[datetime | None] = _ts()
    vuln_status: Mapped[str | None] = mapped_column(String(32))
    # The best available CVSS (highest version, NVD's own "Primary" first);
    # every version NVD reported is kept in ``cvss``.
    cvss_version: Mapped[str | None] = mapped_column(String(4))
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_severity: Mapped[str | None] = mapped_column(String(10))
    cvss_vector: Mapped[str | None] = mapped_column(Text)
    cvss: Mapped[list[dict[str, Any]]] = mapped_column(JSONType, default=list)
    cwes: Mapped[list[str]] = mapped_column(JSONType, default=list)
    cpes: Mapped[list[str]] = mapped_column(JSONType, default=list)  # vulnerable match criteria
    references: Mapped[list[dict[str, Any]]] = mapped_column(JSONType, default=list)
    exploit_refs: Mapped[list[str]] = mapped_column(JSONType, default=list)  # NVD "Exploit" tag
    ssvc: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)  # CISA ADP decision points
    kev: Mapped[bool] = mapped_column(Boolean, default=False)
    kev_date_added: Mapped[date | None] = mapped_column(Date)
    kev_due_date: Mapped[date | None] = mapped_column(Date)
    kev_ransomware: Mapped[str | None] = mapped_column(String(16))  # Known | Unknown
    kev_name: Mapped[str | None] = mapped_column(Text)
    kev_required_action: Mapped[str | None] = mapped_column(Text)
    epss: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    epss_date: Mapped[date | None] = mapped_column(Date)
    osv_ids: Mapped[list[str]] = mapped_column(JSONType, default=list)  # GHSA-..., PYSEC-...
    packages: Mapped[list[dict[str, Any]]] = mapped_column(JSONType, default=list)
    osv_checked_at: Mapped[datetime | None] = _ts()
    # Patch priority (Phase 4, scoring.vulns): P1-P4, its points and reasons.
    patch_priority: Mapped[str | None] = mapped_column(String(2))
    patch_score: Mapped[float | None] = mapped_column(Float)
    patch_breakdown: Mapped[dict[str, Any] | None] = mapped_column(JSONType)
    created_at: Mapped[datetime] = _ts(default=utcnow)
    updated_at: Mapped[datetime] = _ts(default=utcnow, onupdate=utcnow)

    products: Mapped[list[VulnerabilityProduct]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_vulnerabilities_kev", "kev", "kev_date_added"),
        Index("ix_vulnerabilities_epss", "epss"),
        Index("ix_vulnerabilities_cvss", "cvss_score"),
        Index("ix_vulnerabilities_nvd_modified", "nvd_modified"),
        Index("ix_vulnerabilities_patch", "patch_priority", "patch_score"),
    )


class VulnerabilityProduct(Base):
    """(vendor, product) pairs from a CVE's vulnerable CPEs: the join key to
    the org's tech stack (PIR-2) and, in Phase 3b, to ReconX's observed CPEs."""

    __tablename__ = "vulnerability_products"

    id: Mapped[int] = mapped_column(BigID, primary_key=True)
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id", ondelete="CASCADE"))
    part: Mapped[str] = mapped_column(String(1))  # a | o | h
    vendor: Mapped[str] = mapped_column(String(200))
    product: Mapped[str] = mapped_column(String(200))

    vulnerability: Mapped[Vulnerability] = relationship(back_populates="products")

    __table_args__ = (
        UniqueConstraint("vulnerability_id", "part", "vendor", "product"),
        Index("ix_vulnerability_products_vp", "vendor", "product"),
    )


class AttackRelease(Base):
    """One ingested ATT&CK release of one domain, with what it changed."""

    __tablename__ = "attack_releases"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    domain: Mapped[str] = mapped_column(String(40))
    version: Mapped[str] = mapped_column(String(16))
    released: Mapped[datetime | None] = _ts()
    url: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str] = mapped_column(String(64))
    baseline: Mapped[bool] = mapped_column(Boolean, default=False)  # first load: nothing to diff
    previous_version: Mapped[str | None] = mapped_column(String(16))
    counts: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    summary: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    ingested_at: Mapped[datetime] = _ts(default=utcnow)

    __table_args__ = (UniqueConstraint("domain", "version"),)


class AttackChange(Base):
    """A meaningful change to one ATT&CK object between two releases."""

    __tablename__ = "attack_changes"

    id: Mapped[int] = mapped_column(BigID, primary_key=True)
    release_id: Mapped[int] = mapped_column(ForeignKey("attack_releases.id", ondelete="CASCADE"))
    stix_id: Mapped[str] = mapped_column(String(100))
    type: Mapped[str] = mapped_column(String(40))
    external_id: Mapped[str | None] = mapped_column(String(32))
    name: Mapped[str] = mapped_column(Text)
    change: Mapped[str] = mapped_column(String(16))  # added|modified|revoked|deprecated|restored|removed
    details: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)

    __table_args__ = (Index("ix_attack_changes_release", "release_id", "change"),)


# ── enrichment (Phase 3) ─────────────────────────────────────────────────────


class Enrichment(Base):
    """The latest answer one enricher gave about one observable, with its
    provenance. It doubles as the enrichment cache: a row is fresh until
    ``expires_at``. Errors and skips are not stored (they are transient)."""

    __tablename__ = "enrichments"

    id: Mapped[int] = mapped_column(BigID, primary_key=True)
    enricher: Mapped[str] = mapped_column(String(64))
    source_id: Mapped[int | None] = mapped_column(ForeignKey("sources.id", ondelete="SET NULL"))
    # Values looked up ad hoc need not be indicators yet: the canonical key is
    # the identity, the observable link is filled in when one exists.
    canonical_key: Mapped[str] = mapped_column(Text)
    observable_id: Mapped[int | None] = mapped_column(ForeignKey("observables.id", ondelete="SET NULL"))
    type: Mapped[str] = mapped_column(String(32))
    value: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16))  # ok | not_found
    mode: Mapped[str] = mapped_column(String(8))  # passive | active
    summary: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSONType, default=list)
    raw: Mapped[Any] = mapped_column(JSONType, nullable=True)  # upstream answer, size-capped
    query: Mapped[str] = mapped_column(Text, default="")  # what was asked (never holds a key)
    http_status: Mapped[int | None] = mapped_column(Integer)
    cost: Mapped[int] = mapped_column(Integer, default=0)  # metered quota units spent
    requested_by: Mapped[str] = mapped_column(String(100), default="")
    fetched_at: Mapped[datetime] = _ts(default=utcnow)
    expires_at: Mapped[datetime] = _ts()
    times_fetched: Mapped[int] = mapped_column(Integer, default=1)

    __table_args__ = (
        UniqueConstraint("enricher", "canonical_key"),
        Index("ix_enrichments_canonical_key", "canonical_key"),
        Index("ix_enrichments_observable", "observable_id"),
        CheckConstraint("status IN ('ok','not_found')", name="status"),
        CheckConstraint("mode IN ('passive','active')", name="mode"),
    )


# ── own assets (Phase 3b: imported from ReconX) ──────────────────────────────


class AssetImport(Base):
    """One imported ReconX scan (deduplicated by the file's SHA-256)."""

    __tablename__ = "asset_imports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(32))  # reconx
    target: Mapped[str] = mapped_column(Text)
    scanned_at: Mapped[datetime | None] = _ts()
    sha256: Mapped[str] = mapped_column(String(64), unique=True)
    imported_at: Mapped[datetime] = _ts(default=utcnow)
    imported_by: Mapped[str] = mapped_column(String(100))
    counts: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)


class Asset(Base):
    """A host or IP the organization runs, as observed by ReconX. Assets are
    *watched*, never allowlisted: a feed listing one of them is the strongest
    signal there is (compromise or abuse), not noise (ADR 0006)."""

    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(16))  # domain | host | ip
    value: Mapped[str] = mapped_column(Text)
    canonical_key: Mapped[str] = mapped_column(Text, unique=True)  # same key as observables
    target: Mapped[str] = mapped_column(Text)  # the scanned apex domain or IP
    origin: Mapped[str] = mapped_column(String(32), default="reconx")
    details: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    first_seen: Mapped[datetime] = _ts(default=utcnow)
    last_seen: Mapped[datetime] = _ts(default=utcnow)
    last_import_id: Mapped[int | None] = mapped_column(ForeignKey("asset_imports.id", ondelete="SET NULL"))

    products: Mapped[list[AssetProduct]] = relationship(back_populates="asset", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_assets_target", "target"),
        CheckConstraint("kind IN ('domain','host','ip')", name="kind"),
    )


class AssetProduct(Base):
    """Software observed on an asset (CPE), e.g. from Shodan InternetDB via
    ReconX. Feeds PIR-2 ("vulnerabilities in our stack") with what is deployed."""

    __tablename__ = "asset_products"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    cpe: Mapped[str] = mapped_column(Text)  # normalized CPE 2.3 string
    part: Mapped[str] = mapped_column(String(1))
    vendor: Mapped[str] = mapped_column(String(200))
    product: Mapped[str] = mapped_column(String(200))
    version: Mapped[str | None] = mapped_column(String(100))
    source: Mapped[str] = mapped_column(String(64))
    first_seen: Mapped[datetime] = _ts(default=utcnow)
    last_seen: Mapped[datetime] = _ts(default=utcnow)

    asset: Mapped[Asset] = relationship(back_populates="products")

    __table_args__ = (
        UniqueConstraint("asset_id", "cpe"),
        Index("ix_asset_products_vendor_product", "vendor", "product"),
    )


# ── response: blocklist and feed export (ADR 0010) ───────────────────────────

BLOCK_KINDS = ("ip", "cidr", "domain", "url")
BLOCK_MODES = ("monitor", "enforce")
BLOCK_REASONS = ("known_bad", "suspect", "manual")


class Block(Base):
    """A value we want fenced off. ``monitor`` is a dry run (recorded only);
    ``enforce`` entries are what firewalls pull from the feed export. Every
    block expires; lifting one ends it early. Neither row is ever deleted."""

    __tablename__ = "blocks"

    id: Mapped[int] = mapped_column(BigID, primary_key=True)
    kind: Mapped[str] = mapped_column(String(8))
    value: Mapped[str] = mapped_column(Text)  # canonical: IP, CIDR, domain or URL
    canonical_key: Mapped[str] = mapped_column(Text)  # same key as observables
    indicator_id: Mapped[int | None] = mapped_column(ForeignKey("indicators.id", ondelete="SET NULL"))
    mode: Mapped[str] = mapped_column(String(8), default="monitor")
    reason: Mapped[str] = mapped_column(String(16))
    score: Mapped[float | None] = mapped_column(Float)  # the indicator's priority when blocked
    tlp: Mapped[str] = mapped_column(String(20), default="TLP:CLEAR")
    note: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = _ts(default=utcnow)
    expires_at: Mapped[datetime] = _ts()
    requested_by: Mapped[str | None] = mapped_column(String(100))  # asked for enforce
    requested_at: Mapped[datetime | None] = _ts()
    approved_by: Mapped[str | None] = mapped_column(String(100))  # made it enforce
    approved_at: Mapped[datetime | None] = _ts()
    lifted_by: Mapped[str | None] = mapped_column(String(100))
    lifted_at: Mapped[datetime | None] = _ts()
    lift_note: Mapped[str] = mapped_column(Text, default="")

    __table_args__ = (
        CheckConstraint("kind IN ('ip','cidr','domain','url')", name="kind"),
        CheckConstraint("mode IN ('monitor','enforce')", name="mode"),
        CheckConstraint("reason IN ('known_bad','suspect','manual')", name="reason"),
        CheckConstraint(_TLP_CHECK, name="tlp"),
        Index("ix_blocks_key", "canonical_key"),
        Index("ix_blocks_live", "lifted_at", "expires_at"),
    )


class AppSetting(Base):
    """Policy an admin edits in the UI (one JSON document per key)."""

    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    updated_by: Mapped[str] = mapped_column(String(100), default="system")
    updated_at: Mapped[datetime] = _ts(default=utcnow)


class FeedToken(Base):
    """A secret that lets a firewall or another tool pull the feed export.
    Only a SHA-256 of the token is stored; the token is shown once."""

    __tablename__ = "feed_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    prefix: Mapped[str] = mapped_column(String(8))
    created_by: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = _ts(default=utcnow)
    last_used_at: Mapped[datetime | None] = _ts()
    revoked_at: Mapped[datetime | None] = _ts()


class CustomFeed(Base):
    """A feed an admin added in the UI (ADR 0012). Its ``sources`` row holds
    the title, schedule, marking and reliability like any built-in feed's;
    this row holds how to fetch and read it. ``auth_secret`` is encrypted
    (threatlens.vault), never stored in clear."""

    __tablename__ = "custom_feeds"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id", ondelete="CASCADE"), unique=True)
    url: Mapped[str] = mapped_column(Text)
    format: Mapped[str] = mapped_column(String(8))  # text | csv | json | taxii | misp
    ioc_type: Mapped[str] = mapped_column(String(16), default="auto")  # auto | ip | domain | url | hash
    verdict: Mapped[str] = mapped_column(String(16), default="malicious")  # malicious | suspicious
    confidence: Mapped[int] = mapped_column(Integer, default=70)
    comment_char: Mapped[str] = mapped_column(String(4), default="#")
    value_column: Mapped[int] = mapped_column(Integer, default=0)  # 0-based, CSV
    json_path: Mapped[str | None] = mapped_column(String(200))  # e.g. "data.ip"
    auth_header: Mapped[str | None] = mapped_column(String(64))
    auth_secret: Mapped[str | None] = mapped_column(Text)
    # An admin may let a feed reach an internal network (a MISP or TAXII server
    # in the LAN). Link-local and cloud-metadata addresses stay blocked (ADR 0019).
    allow_internal: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = _ts(default=utcnow)
    updated_by: Mapped[str] = mapped_column(String(100))
    updated_at: Mapped[datetime] = _ts(default=utcnow)

    __table_args__ = (
        CheckConstraint("format IN ('text','csv','json','taxii','misp')", name="format"),
        CheckConstraint("ioc_type IN ('auto','ip','domain','url','hash')", name="ioc_type"),
        CheckConstraint("verdict IN ('malicious','suspicious')", name="verdict"),
        CheckConstraint("confidence BETWEEN 0 AND 100", name="confidence"),
        CheckConstraint("value_column BETWEEN 0 AND 255", name="value_column"),
    )


# ── dissemination (Phase 6, ADR 0019) ────────────────────────────────────────

INTEGRATION_KINDS = (
    "splunk_hec",
    "elastic",
    "sentinel",
    "misp",
    "webhook",
    "slack",
    "teams",
    "telegram",
    "email",
)
_KIND_CHECK = "kind IN (" + ",".join(f"'{k}'" for k in INTEGRATION_KINDS) + ")"
ALERT_KINDS = ("score", "pir", "kev_asset", "environment", "lookalike")


class Integration(Base):
    """An outbound connection an admin configured: a SIEM/TIP that receives
    indicators (splunk_hec, elastic, sentinel, misp, webhook) or a channel that
    receives alerts (slack, teams, telegram, email). Secrets live encrypted in
    ``secret`` (threatlens.vault), never in ``config``."""

    __tablename__ = "integrations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    kind: Mapped[str] = mapped_column(String(16))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    config: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    secret: Mapped[str | None] = mapped_column(Text)
    allow_internal: Mapped[bool] = mapped_column(Boolean, default=False)
    # What may be sent: indicators scoring at least this, marked at most this,
    # of these types (empty = every type), and only redistributable ones.
    min_score: Mapped[float] = mapped_column(Float, default=60.0)
    max_tlp: Mapped[str] = mapped_column(String(20), default="TLP:GREEN")
    types: Mapped[list[str]] = mapped_column(JSONType, default=list)
    interval_minutes: Mapped[int] = mapped_column(Integer, default=60)
    cursor: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    last_run_at: Mapped[datetime | None] = _ts()
    last_status: Mapped[str | None] = mapped_column(String(16))
    last_error: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = _ts(default=utcnow)
    updated_at: Mapped[datetime] = _ts(default=utcnow, onupdate=utcnow)

    __table_args__ = (
        CheckConstraint(_KIND_CHECK, name="kind"),
        CheckConstraint(
            "max_tlp IN ('TLP:CLEAR','TLP:GREEN','TLP:AMBER','TLP:AMBER+STRICT','TLP:RED')", name="max_tlp"
        ),
        CheckConstraint("min_score BETWEEN 0 AND 100", name="min_score"),
        CheckConstraint("interval_minutes BETWEEN 5 AND 10080", name="interval"),
    )


class IntegrationRun(Base):
    """One push or test of an integration: what was sent and what went wrong."""

    __tablename__ = "integration_runs"

    id: Mapped[int] = mapped_column(BigID, primary_key=True)
    integration_id: Mapped[int] = mapped_column(ForeignKey("integrations.id", ondelete="CASCADE"))
    trigger: Mapped[str] = mapped_column(String(16), default="schedule")  # schedule | manual | test | alert
    started_at: Mapped[datetime] = _ts(default=utcnow)
    finished_at: Mapped[datetime | None] = _ts()
    status: Mapped[str] = mapped_column(
        String(16), default="running"
    )  # running | success | partial | failed | skipped
    sent: Mapped[int] = mapped_column(Integer, default=0)
    held_back: Mapped[int] = mapped_column(Integer, default=0)  # refused by TLP or licence
    error: Mapped[str | None] = mapped_column(Text)
    detail: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)

    __table_args__ = (Index("ix_integration_runs_integration_started", "integration_id", "started_at"),)


class AlertRule(Base):
    """When to tell people: an indicator scoring at least N, one matching a PIR,
    a newly exploited CVE in our stack, or a known-bad value seen by our SIEM."""

    __tablename__ = "alert_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    kind: Mapped[str] = mapped_column(String(16))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    params: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    channels: Mapped[list[int]] = mapped_column(JSONType, default=list)  # integration ids
    max_tlp: Mapped[str] = mapped_column(String(20), default="TLP:AMBER")
    cursor: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    created_by: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = _ts(default=utcnow)
    updated_at: Mapped[datetime] = _ts(default=utcnow, onupdate=utcnow)

    __table_args__ = (
        CheckConstraint("kind IN ('score','pir','kev_asset','environment','lookalike')", name="kind"),
        CheckConstraint(
            "max_tlp IN ('TLP:CLEAR','TLP:GREEN','TLP:AMBER','TLP:AMBER+STRICT','TLP:RED')", name="max_tlp"
        ),
    )


class AlertEvent(Base):
    """One alert, raised once per (rule, subject): the dedup key makes a
    re-run, a re-scored indicator or a second worker unable to repeat it."""

    __tablename__ = "alert_events"

    id: Mapped[int] = mapped_column(BigID, primary_key=True)
    rule_id: Mapped[int] = mapped_column(ForeignKey("alert_rules.id", ondelete="CASCADE"))
    dedup_key: Mapped[str] = mapped_column(String(300))
    title: Mapped[str] = mapped_column(String(300))
    body: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    tlp: Mapped[str] = mapped_column(String(20), default="TLP:CLEAR")
    created_at: Mapped[datetime] = _ts(default=utcnow)
    delivered: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)  # integration id -> status

    __table_args__ = (
        UniqueConstraint("rule_id", "dedup_key"),
        CheckConstraint(_TLP_CHECK, name="tlp"),
        Index("ix_alert_events_created", "created_at"),
    )


# ── detection engineering (Phase 7, ADR 0020) ────────────────────────────────


class DetectionRule(Base):
    """A rule in our detection inventory: imported from the SOC's own Sigma
    repository (for coverage-gap analysis), or generated here and kept."""

    __tablename__ = "detection_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    origin: Mapped[str] = mapped_column(String(16))  # imported | generated
    rule_uid: Mapped[str] = mapped_column(String(100))  # the Sigma id, or a hash of the content
    title: Mapped[str] = mapped_column(String(300))
    status: Mapped[str | None] = mapped_column(String(20))
    level: Mapped[str | None] = mapped_column(String(20))
    logsource: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    techniques: Mapped[list[str]] = mapped_column(JSONType, default=list)  # T1059.001, ...
    content: Mapped[str] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = _ts(default=utcnow)

    __table_args__ = (
        UniqueConstraint("origin", "rule_uid"),
        CheckConstraint("origin IN ('imported','generated')", name="origin"),
    )


class RetroHunt(Base):
    """A query pack to run against historical logs when new high-priority
    indicators arrive (Phase 7 retro-hunt hook)."""

    __tablename__ = "retro_hunts"

    id: Mapped[int] = mapped_column(BigID, primary_key=True)
    created_at: Mapped[datetime] = _ts(default=utcnow)
    title: Mapped[str] = mapped_column(String(300))
    tlp: Mapped[str] = mapped_column(String(20), default="TLP:CLEAR")
    indicator_ids: Mapped[list[int]] = mapped_column(JSONType, default=list)
    lookback_days: Mapped[int] = mapped_column(Integer, default=30)
    queries: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)  # backend -> [queries]

    __table_args__ = (CheckConstraint(_TLP_CHECK, name="tlp"), Index("ix_retro_hunts_created", "created_at"))


# ── intelligence products, lookalikes, AI drafts (Phase 8, ADR 0021/0022) ─────


class Product(Base):
    """A generated intelligence product. The content is the structure both
    renderings come from; ``sha256`` makes regeneration checkable."""

    __tablename__ = "products"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(16))  # daily | weekly | vulns | exec
    period_start: Mapped[datetime] = _ts()
    period_end: Mapped[datetime] = _ts()
    tlp: Mapped[str] = mapped_column(String(20), default="TLP:CLEAR")
    sha256: Mapped[str] = mapped_column(String(64))
    content: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    generated_by: Mapped[str] = mapped_column(String(100), default="worker")
    created_at: Mapped[datetime] = _ts(default=utcnow)

    __table_args__ = (
        UniqueConstraint("kind", "period_end"),
        CheckConstraint("kind IN ('daily','weekly','vulns','exec')", name="kind"),
        CheckConstraint(_TLP_CHECK, name="tlp"),
    )


class Lookalike(Base):
    """A registered domain that imitates one of ours, from CT logs or our feeds."""

    __tablename__ = "lookalikes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    domain: Mapped[str] = mapped_column(String(253))  # ours
    candidate: Mapped[str] = mapped_column(String(253), unique=True)
    fuzzer: Mapped[str] = mapped_column(String(32))
    first_seen: Mapped[datetime] = _ts(default=utcnow)
    last_seen: Mapped[datetime] = _ts(default=utcnow)
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSONType, default=list)
    status: Mapped[str] = mapped_column(String(16), default="new")  # new | confirmed | benign
    reviewed_by: Mapped[str | None] = mapped_column(String(100))
    reviewed_at: Mapped[datetime | None] = _ts()

    __table_args__ = (
        CheckConstraint("status IN ('new','confirmed','benign')", name="status"),
        Index("ix_lookalikes_first_seen", "first_seen"),
    )


class AiDraft(Base):
    """What the AI assistant extracted from a report: a draft until an analyst
    approves it. Prompt, model and output are fingerprinted (ADR 0022)."""

    __tablename__ = "ai_drafts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = _ts(default=utcnow)
    actor: Mapped[str] = mapped_column(String(100))
    title: Mapped[str] = mapped_column(String(300))
    tlp: Mapped[str] = mapped_column(String(20), default="TLP:AMBER")
    source_text: Mapped[str] = mapped_column(Text)
    source_sha256: Mapped[str] = mapped_column(String(64))
    model: Mapped[str] = mapped_column(String(100))
    prompt_sha256: Mapped[str] = mapped_column(String(64))
    output_sha256: Mapped[str] = mapped_column(String(64))
    result: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)  # accepted: summary, iocs, ttps
    rejected: Mapped[list[dict[str, Any]]] = mapped_column(JSONType, default=list)  # dropped by validation
    status: Mapped[str] = mapped_column(String(16), default="draft")  # draft | approved | rejected
    reviewed_by: Mapped[str | None] = mapped_column(String(100))
    reviewed_at: Mapped[datetime | None] = _ts()

    __table_args__ = (
        CheckConstraint("status IN ('draft','approved','rejected')", name="status"),
        CheckConstraint(_TLP_CHECK, name="tlp"),
    )
