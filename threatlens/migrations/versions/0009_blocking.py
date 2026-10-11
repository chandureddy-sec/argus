"""Response (ADR 0010): ``blocks`` (the blocklist), ``app_settings`` (policy
edited in the UI) and ``feed_tokens`` (who may pull the feed export).

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-11 18:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")
BIGID = sa.BigInteger().with_variant(sa.Integer(), "sqlite")
TS = sa.DateTime(timezone=True)
TLP = "tlp IN ('TLP:CLEAR','TLP:GREEN','TLP:AMBER','TLP:AMBER+STRICT','TLP:RED')"


def upgrade() -> None:
    op.create_table(
        "blocks",
        sa.Column("id", BIGID, nullable=False),
        sa.Column("kind", sa.String(length=8), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("canonical_key", sa.Text(), nullable=False),
        sa.Column("indicator_id", BIGID, nullable=True),
        sa.Column("mode", sa.String(length=8), nullable=False),
        sa.Column("reason", sa.String(length=16), nullable=False),
        sa.Column("score", sa.Float(), nullable=True),
        sa.Column("tlp", sa.String(length=20), nullable=False),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("created_by", sa.String(length=100), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("expires_at", TS, nullable=False),
        sa.Column("requested_by", sa.String(length=100), nullable=True),
        sa.Column("requested_at", TS, nullable=True),
        sa.Column("approved_by", sa.String(length=100), nullable=True),
        sa.Column("approved_at", TS, nullable=True),
        sa.Column("lifted_by", sa.String(length=100), nullable=True),
        sa.Column("lifted_at", TS, nullable=True),
        sa.Column("lift_note", sa.Text(), nullable=False),
        sa.CheckConstraint("kind IN ('ip','cidr','domain','url')", name=op.f("ck_blocks_kind")),
        sa.CheckConstraint("mode IN ('monitor','enforce')", name=op.f("ck_blocks_mode")),
        sa.CheckConstraint("reason IN ('known_bad','suspect','manual')", name=op.f("ck_blocks_reason")),
        sa.CheckConstraint(TLP, name=op.f("ck_blocks_tlp")),
        sa.ForeignKeyConstraint(
            ["indicator_id"],
            ["indicators.id"],
            name=op.f("fk_blocks_indicator_id_indicators"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_blocks")),
    )
    op.create_index("ix_blocks_key", "blocks", ["canonical_key"])
    op.create_index("ix_blocks_live", "blocks", ["lifted_at", "expires_at"])

    op.create_table(
        "app_settings",
        sa.Column("key", sa.String(length=64), nullable=False),
        sa.Column("value", JSON, nullable=False),
        sa.Column("updated_by", sa.String(length=100), nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.PrimaryKeyConstraint("key", name=op.f("pk_app_settings")),
    )

    op.create_table(
        "feed_tokens",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("prefix", sa.String(length=8), nullable=False),
        sa.Column("created_by", sa.String(length=100), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("last_used_at", TS, nullable=True),
        sa.Column("revoked_at", TS, nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_feed_tokens")),
        sa.UniqueConstraint("name", name=op.f("uq_feed_tokens_name")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_feed_tokens_token_hash")),
    )


def downgrade() -> None:
    op.drop_table("feed_tokens")
    op.drop_table("app_settings")
    op.drop_index("ix_blocks_live", table_name="blocks")
    op.drop_index("ix_blocks_key", table_name="blocks")
    op.drop_table("blocks")
