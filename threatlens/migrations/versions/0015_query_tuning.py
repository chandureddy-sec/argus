"""Query tuning from EXPLAIN ANALYZE on 44k indicators (Phase 9, docs/PERFORMANCE.md).

* observables (type, last_seen, id) replaces (type, last_seen): newest-first
  lists per type with a unique tie-breaker walk the index instead of sorting.
* indicators (created_at, id): Argus lists, products and the calendar.
* Trigram GIN on observables.value and .defanged (Postgres): substring search.

Revision ID: 0015
Revises: 0014
Create Date: 2026-10-19 00:30:00
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _pg() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def upgrade() -> None:
    op.drop_index("ix_observables_type_last_seen", table_name="observables")
    op.create_index("ix_observables_type_seen", "observables", ["type", "last_seen", "id"])
    op.create_index("ix_indicators_created", "indicators", ["created_at", "id"])
    if _pg():
        op.create_index(
            "ix_observables_value_trgm",
            "observables",
            ["value"],
            postgresql_using="gin",
            postgresql_ops={"value": "gin_trgm_ops"},
        )
        op.create_index(
            "ix_observables_defanged_trgm",
            "observables",
            ["defanged"],
            postgresql_using="gin",
            postgresql_ops={"defanged": "gin_trgm_ops"},
        )


def downgrade() -> None:
    if _pg():
        op.drop_index("ix_observables_defanged_trgm", table_name="observables")
        op.drop_index("ix_observables_value_trgm", table_name="observables")
    op.drop_index("ix_indicators_created", table_name="indicators")
    op.drop_index("ix_observables_type_seen", table_name="observables")
    op.create_index("ix_observables_type_last_seen", "observables", ["type", "last_seen"])
