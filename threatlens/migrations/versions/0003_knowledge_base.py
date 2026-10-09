"""Knowledge base: ATT&CK entities and releases, vulnerabilities, the
relationship graph, indicator STIX ids and run notes (see docs/DATA_MODEL.md).

Indicators created before this revision get their ``stix_id`` from the
application on its next collection run (``backfill_indicator_ids``): the id
is a uuid5 computed in Python, which keeps this migration free of extensions.

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-09 19:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")
BIGID = sa.BigInteger().with_variant(sa.Integer(), "sqlite")
TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.add_column("indicators", sa.Column("stix_id", sa.String(length=100), nullable=True))
    op.create_unique_constraint(op.f("uq_indicators_stix_id"), "indicators", ["stix_id"])
    op.add_column("connector_runs", sa.Column("note", sa.Text(), nullable=True))

    op.create_table(
        "entities",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("stix_id", sa.String(length=100), nullable=False),
        sa.Column("type", sa.String(length=40), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("external_id", sa.String(length=32), nullable=True),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("aliases", JSON, nullable=False),
        sa.Column("domains", JSON, nullable=False),
        sa.Column("platforms", JSON, nullable=False),
        sa.Column("tactics", JSON, nullable=False),
        sa.Column("is_subtechnique", sa.Boolean(), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False),
        sa.Column("deprecated", sa.Boolean(), nullable=False),
        sa.Column("version", sa.String(length=16), nullable=True),
        sa.Column("stix_modified", TS, nullable=True),
        sa.Column("origin", sa.String(length=16), nullable=False),
        sa.Column("source_id", sa.Integer(), nullable=True),
        sa.Column("stix", JSON, nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.ForeignKeyConstraint(
            ["source_id"], ["sources.id"], name=op.f("fk_entities_source_id_sources"), ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_entities")),
        sa.UniqueConstraint("stix_id", name=op.f("uq_entities_stix_id")),
    )
    op.create_index("ix_entities_type_name", "entities", ["type", "name"])
    op.create_index("ix_entities_external_id", "entities", ["external_id"])

    op.create_table(
        "entity_aliases",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("entity_id", sa.Integer(), nullable=False),
        sa.Column("alias_key", sa.String(length=200), nullable=False),
        sa.ForeignKeyConstraint(
            ["entity_id"],
            ["entities.id"],
            name=op.f("fk_entity_aliases_entity_id_entities"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_entity_aliases")),
        sa.UniqueConstraint("alias_key", "entity_id", name=op.f("uq_entity_aliases_alias_key")),
    )
    op.create_index("ix_entity_aliases_entity", "entity_aliases", ["entity_id"])

    op.create_table(
        "relationships",
        sa.Column("id", BIGID, nullable=False),
        sa.Column("stix_id", sa.String(length=100), nullable=False),
        sa.Column("src_ref", sa.String(length=100), nullable=False),
        sa.Column("rel_type", sa.String(length=40), nullable=False),
        sa.Column("dst_ref", sa.String(length=100), nullable=False),
        sa.Column("origin", sa.String(length=16), nullable=False),
        sa.Column("scope", sa.String(length=40), nullable=True),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False),
        sa.Column("source_id", sa.Integer(), nullable=True),
        sa.Column("provenance", JSON, nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False),
        sa.Column("first_seen", TS, nullable=False),
        sa.Column("last_seen", TS, nullable=False),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["sources.id"],
            name=op.f("fk_relationships_source_id_sources"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_relationships")),
        sa.UniqueConstraint("stix_id", name=op.f("uq_relationships_stix_id")),
    )
    op.create_index("ix_relationships_src", "relationships", ["src_ref", "rel_type"])
    op.create_index("ix_relationships_dst", "relationships", ["dst_ref", "rel_type"])
    op.create_index("ix_relationships_origin_scope", "relationships", ["origin", "scope"])

    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column("stix_id", sa.String(length=100), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("published", TS, nullable=True),
        sa.Column("nvd_modified", TS, nullable=True),
        sa.Column("vuln_status", sa.String(length=32), nullable=True),
        sa.Column("cvss_version", sa.String(length=4), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cvss_severity", sa.String(length=10), nullable=True),
        sa.Column("cvss_vector", sa.Text(), nullable=True),
        sa.Column("cvss", JSON, nullable=False),
        sa.Column("cwes", JSON, nullable=False),
        sa.Column("cpes", JSON, nullable=False),
        sa.Column("references", JSON, nullable=False),
        sa.Column("exploit_refs", JSON, nullable=False),
        sa.Column("ssvc", JSON, nullable=False),
        sa.Column("kev", sa.Boolean(), nullable=False),
        sa.Column("kev_date_added", sa.Date(), nullable=True),
        sa.Column("kev_due_date", sa.Date(), nullable=True),
        sa.Column("kev_ransomware", sa.String(length=16), nullable=True),
        sa.Column("kev_name", sa.Text(), nullable=True),
        sa.Column("kev_required_action", sa.Text(), nullable=True),
        sa.Column("epss", sa.Float(), nullable=True),
        sa.Column("epss_percentile", sa.Float(), nullable=True),
        sa.Column("epss_date", sa.Date(), nullable=True),
        sa.Column("osv_ids", JSON, nullable=False),
        sa.Column("packages", JSON, nullable=False),
        sa.Column("osv_checked_at", TS, nullable=True),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_vulnerabilities")),
        sa.UniqueConstraint("cve_id", name=op.f("uq_vulnerabilities_cve_id")),
        sa.UniqueConstraint("stix_id", name=op.f("uq_vulnerabilities_stix_id")),
    )
    op.create_index("ix_vulnerabilities_kev", "vulnerabilities", ["kev", "kev_date_added"])
    op.create_index("ix_vulnerabilities_epss", "vulnerabilities", ["epss"])
    op.create_index("ix_vulnerabilities_cvss", "vulnerabilities", ["cvss_score"])
    op.create_index("ix_vulnerabilities_nvd_modified", "vulnerabilities", ["nvd_modified"])

    op.create_table(
        "vulnerability_products",
        sa.Column("id", BIGID, nullable=False),
        sa.Column("vulnerability_id", sa.Integer(), nullable=False),
        sa.Column("part", sa.String(length=1), nullable=False),
        sa.Column("vendor", sa.String(length=200), nullable=False),
        sa.Column("product", sa.String(length=200), nullable=False),
        sa.ForeignKeyConstraint(
            ["vulnerability_id"],
            ["vulnerabilities.id"],
            name=op.f("fk_vulnerability_products_vulnerability_id_vulnerabilities"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_vulnerability_products")),
        sa.UniqueConstraint(
            "vulnerability_id",
            "part",
            "vendor",
            "product",
            name=op.f("uq_vulnerability_products_vulnerability_id"),
        ),
    )
    op.create_index("ix_vulnerability_products_vp", "vulnerability_products", ["vendor", "product"])

    op.create_table(
        "attack_releases",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("domain", sa.String(length=40), nullable=False),
        sa.Column("version", sa.String(length=16), nullable=False),
        sa.Column("released", TS, nullable=True),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("baseline", sa.Boolean(), nullable=False),
        sa.Column("previous_version", sa.String(length=16), nullable=True),
        sa.Column("counts", JSON, nullable=False),
        sa.Column("summary", JSON, nullable=False),
        sa.Column("ingested_at", TS, nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_attack_releases")),
        sa.UniqueConstraint("domain", "version", name=op.f("uq_attack_releases_domain")),
    )

    op.create_table(
        "attack_changes",
        sa.Column("id", BIGID, nullable=False),
        sa.Column("release_id", sa.Integer(), nullable=False),
        sa.Column("stix_id", sa.String(length=100), nullable=False),
        sa.Column("type", sa.String(length=40), nullable=False),
        sa.Column("external_id", sa.String(length=32), nullable=True),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("change", sa.String(length=16), nullable=False),
        sa.Column("details", JSON, nullable=False),
        sa.ForeignKeyConstraint(
            ["release_id"],
            ["attack_releases.id"],
            name=op.f("fk_attack_changes_release_id_attack_releases"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_attack_changes")),
    )
    op.create_index("ix_attack_changes_release", "attack_changes", ["release_id", "change"])


def downgrade() -> None:
    op.drop_index("ix_attack_changes_release", table_name="attack_changes")
    op.drop_table("attack_changes")
    op.drop_table("attack_releases")
    op.drop_index("ix_vulnerability_products_vp", table_name="vulnerability_products")
    op.drop_table("vulnerability_products")
    for ix in (
        "ix_vulnerabilities_nvd_modified",
        "ix_vulnerabilities_cvss",
        "ix_vulnerabilities_epss",
        "ix_vulnerabilities_kev",
    ):
        op.drop_index(ix, table_name="vulnerabilities")
    op.drop_table("vulnerabilities")
    for ix in ("ix_relationships_origin_scope", "ix_relationships_dst", "ix_relationships_src"):
        op.drop_index(ix, table_name="relationships")
    op.drop_table("relationships")
    op.drop_index("ix_entity_aliases_entity", table_name="entity_aliases")
    op.drop_table("entity_aliases")
    op.drop_index("ix_entities_external_id", table_name="entities")
    op.drop_index("ix_entities_type_name", table_name="entities")
    op.drop_table("entities")
    op.drop_column("connector_runs", "note")
    op.drop_constraint(op.f("uq_indicators_stix_id"), "indicators", type_="unique")
    op.drop_column("indicators", "stix_id")
