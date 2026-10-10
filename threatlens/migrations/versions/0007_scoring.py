"""Scoring, trust, TLP clearance and feedback (Phase 4, ADR 0008).

* ``sources``: Admiralty information credibility, analyst-feedback tallies
  and the weight factor derived from them.
* ``indicators``: the latest analyst verdict; index for priority ordering.
* ``verdicts``: analyst TP/FP feedback history.
* ``api_keys`` / ``users``: TLP clearance (null: the role's default).
* ``vulnerabilities``: patch priority P1-P4 with its points and reasons.

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-11 00:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")
BIGID = sa.BigInteger().with_variant(sa.Integer(), "sqlite")
TS = sa.DateTime(timezone=True)
CLEARANCE = "tlp_clearance IN ('TLP:CLEAR','TLP:GREEN','TLP:AMBER','TLP:AMBER+STRICT','TLP:RED')"


def upgrade() -> None:
    op.add_column("sources", sa.Column("credibility", sa.Integer(), server_default="6", nullable=False))
    op.add_column("sources", sa.Column("feedback_tp", sa.Integer(), server_default="0", nullable=False))
    op.add_column("sources", sa.Column("feedback_fp", sa.Integer(), server_default="0", nullable=False))
    op.add_column("sources", sa.Column("weight_factor", sa.Float(), server_default="1.0", nullable=False))
    op.create_check_constraint(op.f("ck_sources_credibility"), "sources", "credibility BETWEEN 1 AND 6")

    op.add_column("indicators", sa.Column("analyst_verdict", sa.String(length=8), nullable=True))
    op.add_column("indicators", sa.Column("analyst_verdict_by", sa.String(length=100), nullable=True))
    op.add_column("indicators", sa.Column("analyst_verdict_at", TS, nullable=True))
    op.create_check_constraint(
        op.f("ck_indicators_analyst_verdict"), "indicators", "analyst_verdict IN ('tp','fp')"
    )
    op.create_index("ix_indicators_status_priority", "indicators", ["status", "priority_score"])

    op.create_table(
        "verdicts",
        sa.Column("id", BIGID, nullable=False),
        sa.Column("indicator_id", BIGID, nullable=False),
        sa.Column("verdict", sa.String(length=8), nullable=False),
        sa.Column("actor", sa.String(length=100), nullable=False),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.CheckConstraint("verdict IN ('tp','fp','reset')", name=op.f("ck_verdicts_verdict")),
        sa.ForeignKeyConstraint(
            ["indicator_id"],
            ["indicators.id"],
            name=op.f("fk_verdicts_indicator_id_indicators"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_verdicts")),
    )
    op.create_index("ix_verdicts_indicator_created", "verdicts", ["indicator_id", "created_at"])

    for table in ("api_keys", "users"):
        op.add_column(table, sa.Column("tlp_clearance", sa.String(length=20), nullable=True))
        op.create_check_constraint(op.f(f"ck_{table}_tlp_clearance"), table, CLEARANCE)

    op.add_column("vulnerabilities", sa.Column("patch_priority", sa.String(length=2), nullable=True))
    op.add_column("vulnerabilities", sa.Column("patch_score", sa.Float(), nullable=True))
    op.add_column("vulnerabilities", sa.Column("patch_breakdown", JSON, nullable=True))
    op.create_index("ix_vulnerabilities_patch", "vulnerabilities", ["patch_priority", "patch_score"])


def downgrade() -> None:
    op.drop_index("ix_vulnerabilities_patch", table_name="vulnerabilities")
    for col in ("patch_breakdown", "patch_score", "patch_priority"):
        op.drop_column("vulnerabilities", col)
    for table in ("users", "api_keys"):
        op.drop_constraint(op.f(f"ck_{table}_tlp_clearance"), table, type_="check")
        op.drop_column(table, "tlp_clearance")
    op.drop_index("ix_verdicts_indicator_created", table_name="verdicts")
    op.drop_table("verdicts")
    op.drop_index("ix_indicators_status_priority", table_name="indicators")
    op.drop_constraint(op.f("ck_indicators_analyst_verdict"), "indicators", type_="check")
    for col in ("analyst_verdict_at", "analyst_verdict_by", "analyst_verdict"):
        op.drop_column("indicators", col)
    op.drop_constraint(op.f("ck_sources_credibility"), "sources", type_="check")
    for col in ("weight_factor", "feedback_fp", "feedback_tp", "credibility"):
        op.drop_column("sources", col)
