"""Team and security: TOTP and SSO columns for users (ADR 0017).

Revision ID: 0011
Revises: 0010
Create Date: 2026-10-14 20:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.add_column("users", sa.Column("totp_secret", sa.String(length=64), nullable=True))
    op.add_column("users", sa.Column("totp_enabled_at", TS, nullable=True))
    op.add_column("users", sa.Column("sso_provider", sa.String(length=32), nullable=True))
    op.add_column("users", sa.Column("sso_id", sa.String(length=200), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "sso_id")
    op.drop_column("users", "sso_provider")
    op.drop_column("users", "totp_enabled_at")
    op.drop_column("users", "totp_secret")
