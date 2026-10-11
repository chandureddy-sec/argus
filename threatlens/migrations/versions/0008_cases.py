"""Analyst experience (Phase 5, ADR 0009): ``cases`` and ``case_items``,
indicator ``notes`` and ``saved_searches``.

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-11 12:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")
BIGID = sa.BigInteger().with_variant(sa.Integer(), "sqlite")
TS = sa.DateTime(timezone=True)
TLP = "tlp IN ('TLP:CLEAR','TLP:GREEN','TLP:AMBER','TLP:AMBER+STRICT','TLP:RED')"
KINDS = "kind IN ('indicator','vulnerability','entity','observable','note')"


def upgrade() -> None:
    op.create_table(
        "notes",
        sa.Column("id", BIGID, nullable=False),
        sa.Column("indicator_id", BIGID, nullable=False),
        sa.Column("author", sa.String(length=100), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.ForeignKeyConstraint(
            ["indicator_id"],
            ["indicators.id"],
            name=op.f("fk_notes_indicator_id_indicators"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_notes")),
    )
    op.create_index("ix_notes_indicator_created", "notes", ["indicator_id", "created_at"])

    op.create_table(
        "cases",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("tlp", sa.String(length=20), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("conclusion", sa.Text(), nullable=False),
        sa.Column("created_by", sa.String(length=100), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.Column("closed_at", TS, nullable=True),
        sa.CheckConstraint("status IN ('open','closed')", name=op.f("ck_cases_status")),
        sa.CheckConstraint("severity IN ('low','medium','high','critical')", name=op.f("ck_cases_severity")),
        sa.CheckConstraint(TLP, name=op.f("ck_cases_tlp")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_cases")),
    )
    op.create_index("ix_cases_status_updated", "cases", ["status", "updated_at"])

    op.create_table(
        "case_items",
        sa.Column("id", BIGID, nullable=False),
        sa.Column("case_id", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("ref", sa.String(length=200), nullable=False),
        sa.Column("label", sa.Text(), nullable=False),
        sa.Column("snapshot", JSON, nullable=False),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("tlp", sa.String(length=20), nullable=False),
        sa.Column("added_by", sa.String(length=100), nullable=False),
        sa.Column("added_at", TS, nullable=False),
        sa.CheckConstraint(KINDS, name=op.f("ck_case_items_kind")),
        sa.CheckConstraint(TLP, name=op.f("ck_case_items_tlp")),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_case_items_case_id_cases"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_case_items")),
    )
    op.create_index("ix_case_items_case_added", "case_items", ["case_id", "added_at"])

    op.create_table(
        "saved_searches",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("owner", sa.String(length=120), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("query", sa.Text(), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_saved_searches")),
        sa.UniqueConstraint("owner", "name", name=op.f("uq_saved_searches_owner")),
    )


def downgrade() -> None:
    op.drop_table("saved_searches")
    op.drop_index("ix_case_items_case_added", table_name="case_items")
    op.drop_table("case_items")
    op.drop_index("ix_cases_status_updated", table_name="cases")
    op.drop_table("cases")
    op.drop_index("ix_notes_indicator_created", table_name="notes")
    op.drop_table("notes")
