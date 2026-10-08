"""Collection core: sources, raw documents, observables, indicators, sightings,
allowlist, connector runs, API keys and the audit log (see docs/DATA_MODEL.md).

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-08 22:58:06.891441
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:

    op.create_table(
        "allowlist_entries",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("effect", sa.String(length=16), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("origin", sa.String(length=32), nullable=False),
        sa.Column("created_by", sa.String(length=100), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("effect IN ('suppress','flag')", name=op.f("ck_allowlist_entries_effect")),
        sa.CheckConstraint("kind IN ('domain','cidr')", name=op.f("ck_allowlist_entries_kind")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_allowlist_entries")),
        sa.UniqueConstraint("kind", "value", "origin", name=op.f("uq_allowlist_entries_kind")),
    )
    op.create_table(
        "api_keys",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("prefix", sa.String(length=16), nullable=False),
        sa.Column("key_hash", sa.String(length=64), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("role IN ('admin','analyst','viewer')", name=op.f("ck_api_keys_role")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_api_keys")),
        sa.UniqueConstraint("key_hash", name=op.f("uq_api_keys_key_hash")),
        sa.UniqueConstraint("name", name=op.f("uq_api_keys_name")),
    )
    op.create_table(
        "audit_log",
        sa.Column("id", sa.BigInteger().with_variant(sa.Integer(), "sqlite"), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor", sa.String(length=100), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("target", sa.Text(), nullable=False),
        sa.Column(
            "details",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_log")),
    )
    op.create_index("ix_audit_log_at", "audit_log", ["at"], unique=False)
    op.create_table(
        "observables",
        sa.Column("id", sa.BigInteger().with_variant(sa.Integer(), "sqlite"), nullable=False),
        sa.Column("type", sa.String(length=32), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("canonical_key", sa.Text(), nullable=False),
        sa.Column("defanged", sa.Text(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("sightings_count", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_observables")),
        sa.UniqueConstraint("canonical_key", name=op.f("uq_observables_canonical_key")),
    )
    op.create_index("ix_observables_type_last_seen", "observables", ["type", "last_seen"], unique=False)
    op.create_table(
        "sources",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("homepage", sa.Text(), nullable=False),
        sa.Column("reliability", sa.String(length=1), nullable=False),
        sa.Column("reliability_note", sa.Text(), nullable=False),
        sa.Column("license", sa.String(length=200), nullable=False),
        sa.Column("license_url", sa.Text(), nullable=False),
        sa.Column("commercial_use", sa.Boolean(), nullable=False),
        sa.Column("redistribution", sa.Boolean(), nullable=False),
        sa.Column("attribution", sa.Text(), nullable=True),
        sa.Column("upstream", sa.String(length=64), nullable=False),
        sa.Column("tlp_default", sa.String(length=20), nullable=False),
        sa.Column("requires_key", sa.Boolean(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("interval_minutes", sa.Integer(), nullable=False),
        sa.Column("health", sa.String(length=16), nullable=False),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column(
            "checkpoint",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("reliability IN ('A','B','C','D','E','F')", name=op.f("ck_sources_reliability")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_sources")),
        sa.UniqueConstraint("name", name=op.f("uq_sources_name")),
    )
    op.create_table(
        "indicators",
        sa.Column("id", sa.BigInteger().with_variant(sa.Integer(), "sqlite"), nullable=False),
        sa.Column("observable_id", sa.BigInteger().with_variant(sa.Integer(), "sqlite"), nullable=False),
        sa.Column("pattern", sa.Text(), nullable=True),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("confidence", sa.Integer(), nullable=False),
        sa.Column("priority_score", sa.Double(), nullable=True),
        sa.Column(
            "score_breakdown",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
        sa.Column("tlp", sa.String(length=20), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column(
            "labels",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("allowlist_reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('new','active','expired','revoked','false_positive')",
            name=op.f("ck_indicators_status"),
        ),
        sa.CheckConstraint("confidence BETWEEN 0 AND 100", name=op.f("ck_indicators_confidence")),
        sa.ForeignKeyConstraint(
            ["observable_id"],
            ["observables.id"],
            name=op.f("fk_indicators_observable_id_observables"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_indicators")),
        sa.UniqueConstraint("observable_id", name=op.f("uq_indicators_observable_id")),
    )
    op.create_index("ix_indicators_status_updated", "indicators", ["status", "updated_at"], unique=False)
    op.create_table(
        "raw_documents",
        sa.Column("id", sa.BigInteger().with_variant(sa.Integer(), "sqlite"), nullable=False),
        sa.Column("source_id", sa.Integer(), nullable=False),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("size", sa.BigInteger(), nullable=False),
        sa.Column("content_type", sa.String(length=200), nullable=False),
        sa.Column("payload_ref", sa.Text(), nullable=False),
        sa.Column("parse_status", sa.String(length=16), nullable=False),
        sa.Column("parse_error", sa.Text(), nullable=True),
        sa.Column("items", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["source_id"], ["sources.id"], name=op.f("fk_raw_documents_source_id_sources"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_raw_documents")),
        sa.UniqueConstraint("source_id", "sha256", name=op.f("uq_raw_documents_source_id")),
    )
    op.create_index(
        "ix_raw_documents_source_fetched", "raw_documents", ["source_id", "fetched_at"], unique=False
    )
    op.create_table(
        "connector_runs",
        sa.Column("id", sa.BigInteger().with_variant(sa.Integer(), "sqlite"), nullable=False),
        sa.Column("source_id", sa.Integer(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("raw_document_id", sa.BigInteger().with_variant(sa.Integer(), "sqlite"), nullable=True),
        sa.Column("items_total", sa.Integer(), nullable=False),
        sa.Column("items_new", sa.Integer(), nullable=False),
        sa.Column("items_updated", sa.Integer(), nullable=False),
        sa.Column("items_rejected", sa.Integer(), nullable=False),
        sa.Column("items_allowlisted", sa.Integer(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["raw_document_id"],
            ["raw_documents.id"],
            name=op.f("fk_connector_runs_raw_document_id_raw_documents"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["sources.id"],
            name=op.f("fk_connector_runs_source_id_sources"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_connector_runs")),
    )
    op.create_index(
        "ix_connector_runs_source_started", "connector_runs", ["source_id", "started_at"], unique=False
    )
    op.create_table(
        "sightings",
        sa.Column("id", sa.BigInteger().with_variant(sa.Integer(), "sqlite"), nullable=False),
        sa.Column("indicator_id", sa.BigInteger().with_variant(sa.Integer(), "sqlite"), nullable=False),
        sa.Column("source_id", sa.Integer(), nullable=False),
        sa.Column("raw_document_id", sa.BigInteger().with_variant(sa.Integer(), "sqlite"), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("times_reported", sa.Integer(), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False),
        sa.Column(
            "labels",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "context",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["indicator_id"],
            ["indicators.id"],
            name=op.f("fk_sightings_indicator_id_indicators"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["raw_document_id"],
            ["raw_documents.id"],
            name=op.f("fk_sightings_raw_document_id_raw_documents"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["source_id"], ["sources.id"], name=op.f("fk_sightings_source_id_sources"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_sightings")),
        sa.UniqueConstraint("indicator_id", "source_id", name=op.f("uq_sightings_indicator_id")),
    )
    op.create_index("ix_sightings_source_last_seen", "sightings", ["source_id", "last_seen"], unique=False)


def downgrade() -> None:

    op.drop_index("ix_sightings_source_last_seen", table_name="sightings")
    op.drop_table("sightings")
    op.drop_index("ix_connector_runs_source_started", table_name="connector_runs")
    op.drop_table("connector_runs")
    op.drop_index("ix_raw_documents_source_fetched", table_name="raw_documents")
    op.drop_table("raw_documents")
    op.drop_index("ix_indicators_status_updated", table_name="indicators")
    op.drop_table("indicators")
    op.drop_table("sources")
    op.drop_index("ix_observables_type_last_seen", table_name="observables")
    op.drop_table("observables")
    op.drop_index("ix_audit_log_at", table_name="audit_log")
    op.drop_table("audit_log")
    op.drop_table("api_keys")
    op.drop_table("allowlist_entries")
