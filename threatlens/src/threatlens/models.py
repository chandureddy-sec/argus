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

    __table_args__ = (Index("ix_observables_type_last_seen", "type", "last_seen"),)


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
