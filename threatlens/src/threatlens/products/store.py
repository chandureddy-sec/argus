"""Storing and scheduling products (ADR 0021).

A product is identified by its kind and the end of its period: generating the
same period again replaces the stored one (data may have changed since), and
``verify`` rebuilds a stored product to show whether it still matches.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from threatlens import tlp as tlp_rules
from threatlens.models import AuditLog, Product
from threatlens.products.build import KINDS, Kind, build, window
from threatlens.settings import Settings


def _aware(v: datetime) -> datetime:
    return v if v.tzinfo else v.replace(tzinfo=UTC)


async def generate(
    sm: async_sessionmaker[AsyncSession],
    settings: Settings,
    kind: Kind,
    as_of: datetime,
    *,
    actor: str = "worker",
) -> Product:
    """Build the product for the period containing ``as_of`` and store it."""
    w = window(kind, as_of)
    async with sm() as s, s.begin():
        content = await build(s, kind, as_of, settings, settings.products_max_tlp)
        row = await s.scalar(select(Product).where(Product.kind == kind, Product.period_end == w.end))
        if row is None:
            row = Product(kind=kind, period_start=w.start, period_end=w.end)
            s.add(row)
        row.tlp = content["tlp"]
        row.sha256 = content["sha256"]
        row.content = content
        row.generated_by = actor[:100]
        row.created_at = datetime.now(UTC)
        await s.flush()
        s.add(
            AuditLog(
                actor=actor[:100],
                action="product.generate",
                target=f"product:{row.id}",
                details={"kind": kind, "period_end": w.end.isoformat(), "sha256": content["sha256"]},
            )
        )
    return row


async def due(sm: async_sessionmaker[AsyncSession], now: datetime) -> list[Kind]:
    """Kinds whose current period has ended and has no stored product yet.

    Daily products cover the previous UTC day; weekly ones the previous
    Monday-to-Monday week. Run after 06:00 UTC so the night's collection is in."""
    out: list[Kind] = []
    async with sm() as s:
        for kind in KINDS:
            end = window(kind, now).end
            if (
                await s.scalar(select(Product.id).where(Product.kind == kind, Product.period_end == end))
                is None
            ):
                out.append(kind)
    return out


async def listing(
    s: AsyncSession, clearance: str, kind: str | None = None, limit: int = 100
) -> list[Product]:
    stmt = select(Product).where(Product.tlp.in_(tlp_rules.readable(clearance)))
    if kind:
        stmt = stmt.where(Product.kind == kind)
    return list(
        (await s.scalars(stmt.order_by(Product.period_end.desc(), Product.id.desc()).limit(limit))).all()
    )


async def get(s: AsyncSession, product_id: int, clearance: str) -> Product | None:
    row = await s.get(Product, product_id)
    return row if row is not None and tlp_rules.may_read(clearance, row.tlp) else None


async def verify(s: AsyncSession, row: Product, settings: Settings) -> dict[str, Any]:
    """Rebuild a stored product from the database and compare fingerprints."""
    as_of = _aware(row.period_end)
    max_tlp = row.content.get("maxTlp", settings.products_max_tlp)
    again = await build(s, row.kind, as_of, settings, max_tlp)  # type: ignore[arg-type]
    return {"stored": row.sha256, "rebuilt": again["sha256"], "match": again["sha256"] == row.sha256}


def view(r: Product) -> dict[str, Any]:
    return {
        "id": r.id,
        "kind": r.kind,
        "title": KINDS.get(r.kind, r.kind),  # type: ignore[call-overload]
        "periodStart": _aware(r.period_start).isoformat(),
        "periodEnd": _aware(r.period_end).isoformat(),
        "tlp": r.tlp,
        "sha256": r.sha256,
        "generatedBy": r.generated_by,
        "createdAt": _aware(r.created_at).isoformat(),
    }
