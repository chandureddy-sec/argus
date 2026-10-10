"""Username/password accounts for the analyst UI: ``users`` (ADR 0007).

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-10 22:30:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("login", sa.String(length=100), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("password_changed_at", TS, nullable=False),
        sa.Column("last_login_at", TS, nullable=True),
        sa.Column("disabled_at", TS, nullable=True),
        sa.CheckConstraint("role IN ('admin','analyst','viewer')", name=op.f("ck_users_role")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
        sa.UniqueConstraint("login", name=op.f("uq_users_login")),
    )


def downgrade() -> None:
    op.drop_table("users")
