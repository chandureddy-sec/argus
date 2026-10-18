"""Detection engineering: the rule inventory and retro-hunt packs (ADR 0020).

Revision ID: 0013
Revises: 0012
Create Date: 2026-10-18 22:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TS = sa.DateTime(timezone=True)
BIG = sa.BigInteger().with_variant(sa.Integer(), "sqlite")
JSON = sa.JSON().with_variant(sa.dialects.postgresql.JSONB(), "postgresql")
TLPS = "('TLP:CLEAR','TLP:GREEN','TLP:AMBER','TLP:AMBER+STRICT','TLP:RED')"


def upgrade() -> None:
    op.create_table(
        "detection_rules",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("origin", sa.String(length=16), nullable=False),
        sa.Column("rule_uid", sa.String(length=100), nullable=False),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=True),
        sa.Column("level", sa.String(length=20), nullable=True),
        sa.Column("logsource", JSON, nullable=False),
        sa.Column("techniques", JSON, nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("created_by", sa.String(length=100), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.CheckConstraint("origin IN ('imported','generated')", name=op.f("ck_detection_rules_origin")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_detection_rules")),
        sa.UniqueConstraint("origin", "rule_uid", name=op.f("uq_detection_rules_origin")),
    )
    op.create_table(
        "retro_hunts",
        sa.Column("id", BIG, nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("tlp", sa.String(length=20), nullable=False),
        sa.Column("indicator_ids", JSON, nullable=False),
        sa.Column("lookback_days", sa.Integer(), nullable=False),
        sa.Column("queries", JSON, nullable=False),
        sa.CheckConstraint(f"tlp IN {TLPS}", name=op.f("ck_retro_hunts_tlp")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_retro_hunts")),
    )
    op.create_index("ix_retro_hunts_created", "retro_hunts", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_retro_hunts_created", table_name="retro_hunts")
    op.drop_table("retro_hunts")
    op.drop_table("detection_rules")
