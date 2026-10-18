"""Dissemination: integrations, their runs, alert rules and events; TAXII and
MISP custom feeds that may reach an internal network (ADR 0019).

Revision ID: 0012
Revises: 0011
Create Date: 2026-10-18 20:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TS = sa.DateTime(timezone=True)
BIG = sa.BigInteger().with_variant(sa.Integer(), "sqlite")
JSON = sa.JSON().with_variant(sa.dialects.postgresql.JSONB(), "postgresql")
TLPS = "('TLP:CLEAR','TLP:GREEN','TLP:AMBER','TLP:AMBER+STRICT','TLP:RED')"
KINDS = "('splunk_hec','elastic','sentinel','misp','webhook','slack','teams','telegram','email')"


def upgrade() -> None:
    with op.batch_alter_table("custom_feeds") as b:
        b.add_column(sa.Column("allow_internal", sa.Boolean(), nullable=False, server_default=sa.false()))
        b.drop_constraint(op.f("ck_custom_feeds_format"), type_="check")
        b.create_check_constraint(
            op.f("ck_custom_feeds_format"), "format IN ('text','csv','json','taxii','misp')"
        )
    with op.batch_alter_table("custom_feeds") as b:
        b.alter_column("allow_internal", server_default=None)

    op.create_table(
        "integrations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("config", JSON, nullable=False),
        sa.Column("secret", sa.Text(), nullable=True),
        sa.Column("allow_internal", sa.Boolean(), nullable=False),
        sa.Column("min_score", sa.Float(), nullable=False),
        sa.Column("max_tlp", sa.String(length=20), nullable=False),
        sa.Column("types", JSON, nullable=False),
        sa.Column("interval_minutes", sa.Integer(), nullable=False),
        sa.Column("cursor", JSON, nullable=False),
        sa.Column("last_run_at", TS, nullable=True),
        sa.Column("last_status", sa.String(length=16), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(length=100), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.CheckConstraint(f"kind IN {KINDS}", name=op.f("ck_integrations_kind")),
        sa.CheckConstraint(f"max_tlp IN {TLPS}", name=op.f("ck_integrations_max_tlp")),
        sa.CheckConstraint("min_score BETWEEN 0 AND 100", name=op.f("ck_integrations_min_score")),
        sa.CheckConstraint("interval_minutes BETWEEN 5 AND 10080", name=op.f("ck_integrations_interval")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_integrations")),
        sa.UniqueConstraint("name", name=op.f("uq_integrations_name")),
    )
    op.create_table(
        "integration_runs",
        sa.Column("id", BIG, nullable=False),
        sa.Column("integration_id", sa.Integer(), nullable=False),
        sa.Column("trigger", sa.String(length=16), nullable=False),
        sa.Column("started_at", TS, nullable=False),
        sa.Column("finished_at", TS, nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("sent", sa.Integer(), nullable=False),
        sa.Column("held_back", sa.Integer(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("detail", JSON, nullable=False),
        sa.ForeignKeyConstraint(
            ["integration_id"],
            ["integrations.id"],
            name=op.f("fk_integration_runs_integration_id_integrations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_integration_runs")),
    )
    op.create_index(
        "ix_integration_runs_integration_started", "integration_runs", ["integration_id", "started_at"]
    )
    op.create_table(
        "alert_rules",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("params", JSON, nullable=False),
        sa.Column("channels", JSON, nullable=False),
        sa.Column("max_tlp", sa.String(length=20), nullable=False),
        sa.Column("cursor", JSON, nullable=False),
        sa.Column("created_by", sa.String(length=100), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.CheckConstraint(
            "kind IN ('score','pir','kev_asset','environment')", name=op.f("ck_alert_rules_kind")
        ),
        sa.CheckConstraint(f"max_tlp IN {TLPS}", name=op.f("ck_alert_rules_max_tlp")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_alert_rules")),
        sa.UniqueConstraint("name", name=op.f("uq_alert_rules_name")),
    )
    op.create_table(
        "alert_events",
        sa.Column("id", BIG, nullable=False),
        sa.Column("rule_id", sa.Integer(), nullable=False),
        sa.Column("dedup_key", sa.String(length=300), nullable=False),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("body", JSON, nullable=False),
        sa.Column("tlp", sa.String(length=20), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("delivered", JSON, nullable=False),
        sa.CheckConstraint(f"tlp IN {TLPS}", name=op.f("ck_alert_events_tlp")),
        sa.ForeignKeyConstraint(
            ["rule_id"],
            ["alert_rules.id"],
            name=op.f("fk_alert_events_rule_id_alert_rules"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_alert_events")),
        sa.UniqueConstraint("rule_id", "dedup_key", name=op.f("uq_alert_events_rule_id")),
    )
    op.create_index("ix_alert_events_created", "alert_events", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_alert_events_created", table_name="alert_events")
    op.drop_table("alert_events")
    op.drop_table("alert_rules")
    op.drop_index("ix_integration_runs_integration_started", table_name="integration_runs")
    op.drop_table("integration_runs")
    op.drop_table("integrations")
    with op.batch_alter_table("custom_feeds") as b:
        b.drop_constraint(op.f("ck_custom_feeds_format"), type_="check")
        b.create_check_constraint(op.f("ck_custom_feeds_format"), "format IN ('text','csv','json')")
        b.drop_column("allow_internal")
