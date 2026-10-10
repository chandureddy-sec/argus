"""Own assets imported from ReconX: ``asset_imports``, ``assets`` and the
software observed on them, ``asset_products`` (ADR 0006).

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-10 20:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")
TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "asset_imports",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("target", sa.Text(), nullable=False),
        sa.Column("scanned_at", TS, nullable=True),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("imported_at", TS, nullable=False),
        sa.Column("imported_by", sa.String(length=100), nullable=False),
        sa.Column("counts", JSON, nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_asset_imports")),
        sa.UniqueConstraint("sha256", name=op.f("uq_asset_imports_sha256")),
    )
    op.create_table(
        "assets",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("canonical_key", sa.Text(), nullable=False),
        sa.Column("target", sa.Text(), nullable=False),
        sa.Column("origin", sa.String(length=32), nullable=False),
        sa.Column("details", JSON, nullable=False),
        sa.Column("first_seen", TS, nullable=False),
        sa.Column("last_seen", TS, nullable=False),
        sa.Column("last_import_id", sa.Integer(), nullable=True),
        sa.CheckConstraint("kind IN ('domain','host','ip')", name=op.f("ck_assets_kind")),
        sa.ForeignKeyConstraint(
            ["last_import_id"],
            ["asset_imports.id"],
            name=op.f("fk_assets_last_import_id_asset_imports"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_assets")),
        sa.UniqueConstraint("canonical_key", name=op.f("uq_assets_canonical_key")),
    )
    op.create_index("ix_assets_target", "assets", ["target"])
    op.create_table(
        "asset_products",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("asset_id", sa.Integer(), nullable=False),
        sa.Column("cpe", sa.Text(), nullable=False),
        sa.Column("part", sa.String(length=1), nullable=False),
        sa.Column("vendor", sa.String(length=200), nullable=False),
        sa.Column("product", sa.String(length=200), nullable=False),
        sa.Column("version", sa.String(length=100), nullable=True),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("first_seen", TS, nullable=False),
        sa.Column("last_seen", TS, nullable=False),
        sa.ForeignKeyConstraint(
            ["asset_id"], ["assets.id"], name=op.f("fk_asset_products_asset_id_assets"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_asset_products")),
        sa.UniqueConstraint("asset_id", "cpe", name=op.f("uq_asset_products_asset_id")),
    )
    op.create_index("ix_asset_products_vendor_product", "asset_products", ["vendor", "product"])


def downgrade() -> None:
    op.drop_index("ix_asset_products_vendor_product", table_name="asset_products")
    op.drop_table("asset_products")
    op.drop_index("ix_assets_target", table_name="assets")
    op.drop_table("assets")
    op.drop_table("asset_imports")
