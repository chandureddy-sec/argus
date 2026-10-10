"""Enrichment: the ``enrichments`` table (latest answer per enricher and
observable, with provenance; also the enrichment cache).

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-10 14:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")
BIGID = sa.BigInteger().with_variant(sa.Integer(), "sqlite")
TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "enrichments",
        sa.Column("id", BIGID, nullable=False),
        sa.Column("enricher", sa.String(length=64), nullable=False),
        sa.Column("source_id", sa.Integer(), nullable=True),
        sa.Column("canonical_key", sa.Text(), nullable=False),
        sa.Column("observable_id", BIGID, nullable=True),
        sa.Column("type", sa.String(length=32), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("mode", sa.String(length=8), nullable=False),
        sa.Column("summary", JSON, nullable=False),
        sa.Column("evidence", JSON, nullable=False),
        sa.Column("raw", JSON, nullable=True),
        sa.Column("query", sa.Text(), nullable=False),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("cost", sa.Integer(), nullable=False),
        sa.Column("requested_by", sa.String(length=100), nullable=False),
        sa.Column("fetched_at", TS, nullable=False),
        sa.Column("expires_at", TS, nullable=False),
        sa.Column("times_fetched", sa.Integer(), nullable=False),
        sa.CheckConstraint("mode IN ('passive','active')", name=op.f("ck_enrichments_mode")),
        sa.CheckConstraint("status IN ('ok','not_found')", name=op.f("ck_enrichments_status")),
        sa.ForeignKeyConstraint(
            ["observable_id"],
            ["observables.id"],
            name=op.f("fk_enrichments_observable_id_observables"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["source_id"], ["sources.id"], name=op.f("fk_enrichments_source_id_sources"), ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_enrichments")),
        sa.UniqueConstraint("enricher", "canonical_key", name=op.f("uq_enrichments_enricher")),
    )
    op.create_index("ix_enrichments_canonical_key", "enrichments", ["canonical_key"])
    op.create_index("ix_enrichments_observable", "enrichments", ["observable_id"])


def downgrade() -> None:
    op.drop_index("ix_enrichments_observable", table_name="enrichments")
    op.drop_index("ix_enrichments_canonical_key", table_name="enrichments")
    op.drop_table("enrichments")
