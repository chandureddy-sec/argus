"""Intelligence products, lookalike domains, AI drafts; the lookalike alert kind
(ADR 0021, 0022).

Revision ID: 0014
Revises: 0013
Create Date: 2026-10-18 23:30:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TS = sa.DateTime(timezone=True)
JSON = sa.JSON().with_variant(sa.dialects.postgresql.JSONB(), "postgresql")
TLPS = "('TLP:CLEAR','TLP:GREEN','TLP:AMBER','TLP:AMBER+STRICT','TLP:RED')"


def upgrade() -> None:
    op.create_table(
        "products",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("period_start", TS, nullable=False),
        sa.Column("period_end", TS, nullable=False),
        sa.Column("tlp", sa.String(length=20), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("content", JSON, nullable=False),
        sa.Column("generated_by", sa.String(length=100), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.CheckConstraint("kind IN ('daily','weekly','vulns','exec')", name=op.f("ck_products_kind")),
        sa.CheckConstraint(f"tlp IN {TLPS}", name=op.f("ck_products_tlp")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_products")),
        sa.UniqueConstraint("kind", "period_end", name=op.f("uq_products_kind")),
    )
    op.create_table(
        "lookalikes",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("domain", sa.String(length=253), nullable=False),
        sa.Column("candidate", sa.String(length=253), nullable=False),
        sa.Column("fuzzer", sa.String(length=32), nullable=False),
        sa.Column("first_seen", TS, nullable=False),
        sa.Column("last_seen", TS, nullable=False),
        sa.Column("evidence", JSON, nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("reviewed_by", sa.String(length=100), nullable=True),
        sa.Column("reviewed_at", TS, nullable=True),
        sa.CheckConstraint("status IN ('new','confirmed','benign')", name=op.f("ck_lookalikes_status")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_lookalikes")),
        sa.UniqueConstraint("candidate", name=op.f("uq_lookalikes_candidate")),
    )
    op.create_index("ix_lookalikes_first_seen", "lookalikes", ["first_seen"])
    op.create_table(
        "ai_drafts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("actor", sa.String(length=100), nullable=False),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("tlp", sa.String(length=20), nullable=False),
        sa.Column("source_text", sa.Text(), nullable=False),
        sa.Column("source_sha256", sa.String(length=64), nullable=False),
        sa.Column("model", sa.String(length=100), nullable=False),
        sa.Column("prompt_sha256", sa.String(length=64), nullable=False),
        sa.Column("output_sha256", sa.String(length=64), nullable=False),
        sa.Column("result", JSON, nullable=False),
        sa.Column("rejected", JSON, nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("reviewed_by", sa.String(length=100), nullable=True),
        sa.Column("reviewed_at", TS, nullable=True),
        sa.CheckConstraint("status IN ('draft','approved','rejected')", name=op.f("ck_ai_drafts_status")),
        sa.CheckConstraint(f"tlp IN {TLPS}", name=op.f("ck_ai_drafts_tlp")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ai_drafts")),
    )
    with op.batch_alter_table("alert_rules") as b:
        b.drop_constraint(op.f("ck_alert_rules_kind"), type_="check")
        b.create_check_constraint(
            op.f("ck_alert_rules_kind"), "kind IN ('score','pir','kev_asset','environment','lookalike')"
        )


def downgrade() -> None:
    with op.batch_alter_table("alert_rules") as b:
        b.drop_constraint(op.f("ck_alert_rules_kind"), type_="check")
        b.create_check_constraint(
            op.f("ck_alert_rules_kind"), "kind IN ('score','pir','kev_asset','environment')"
        )
    op.drop_table("ai_drafts")
    op.drop_index("ix_lookalikes_first_seen", table_name="lookalikes")
    op.drop_table("lookalikes")
    op.drop_table("products")
