"""Feed catalog (ADR 0012): ``custom_feeds``, feeds an admin adds in the UI.

Revision ID: 0010
Revises: 0009
Create Date: 2026-10-14 10:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "custom_feeds",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("source_id", sa.Integer(), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("format", sa.String(length=8), nullable=False),
        sa.Column("ioc_type", sa.String(length=16), nullable=False),
        sa.Column("verdict", sa.String(length=16), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False),
        sa.Column("comment_char", sa.String(length=4), nullable=False),
        sa.Column("value_column", sa.Integer(), nullable=False),
        sa.Column("json_path", sa.String(length=200), nullable=True),
        sa.Column("auth_header", sa.String(length=64), nullable=True),
        sa.Column("auth_secret", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(length=100), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("updated_by", sa.String(length=100), nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.CheckConstraint("format IN ('text','csv','json')", name=op.f("ck_custom_feeds_format")),
        sa.CheckConstraint(
            "ioc_type IN ('auto','ip','domain','url','hash')", name=op.f("ck_custom_feeds_ioc_type")
        ),
        sa.CheckConstraint("verdict IN ('malicious','suspicious')", name=op.f("ck_custom_feeds_verdict")),
        sa.CheckConstraint("confidence BETWEEN 0 AND 100", name=op.f("ck_custom_feeds_confidence")),
        sa.CheckConstraint("value_column BETWEEN 0 AND 255", name=op.f("ck_custom_feeds_value_column")),
        sa.ForeignKeyConstraint(
            ["source_id"], ["sources.id"], name=op.f("fk_custom_feeds_source_id_sources"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_custom_feeds")),
        sa.UniqueConstraint("source_id", name=op.f("uq_custom_feeds_source_id")),
    )


def downgrade() -> None:
    op.drop_table("custom_feeds")
