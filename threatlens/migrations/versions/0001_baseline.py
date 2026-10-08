"""Baseline: extensions and the app_meta table.

Revision ID: 0001
Revises:
Create Date: 2026-10-08

pg_trgm backs fuzzy IOC/actor search (Phase 5) and citext gives
case-insensitive keys for domains and emails. app_meta records facts about the
deployment itself (schema owner, created-at), and gives every later migration
a known-good starting point.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    if op.get_context().dialect.name == "postgresql":
        op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
        op.execute("CREATE EXTENSION IF NOT EXISTS citext")
    op.create_table(
        "app_meta",
        sa.Column("key", sa.String(64), primary_key=True),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.execute("INSERT INTO app_meta (key, value) VALUES ('schema_baseline', '0001')")


def downgrade() -> None:
    op.drop_table("app_meta")
    # Extensions are left installed: other database objects may depend on them.
