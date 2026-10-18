"""Which indicators may leave the platform, for every outbound path (TAXII,
exports, integrations): the one place the sharing rules live.

An indicator is shareable to a destination when all of these hold:

* **TLP**: its marking is no stricter than the destination's ``max_tlp``.
  TLP:RED never leaves, whatever a destination is configured to accept.
* **Licence**: at least one source that reported it allows redistribution
  (``sources.redistribution``), or no feed reported it at all (our own
  analysts' intelligence). A value only Spamhaus or URLhaus reported stays here.
* **Confidence**: active, scoring at least ``min_score``. A false positive is
  shared too, as a *revocation*, so consumers drop what we told them earlier.
* **Type**: in ``types`` when the destination limits them; CVEs have no
  pattern and are never sent as indicators.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import and_, exists, or_, select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession

from threatlens import tlp as tlp_rules
from threatlens.models import Indicator, Sighting, Source
from threatlens.models import Observable as ObsRow

NEVER = "TLP:RED"


@dataclass(frozen=True)
class Rules:
    max_tlp: str = "TLP:CLEAR"
    min_score: float = 60.0
    types: tuple[str, ...] = ()
    revocations: bool = True  # include analyst false positives as revoked objects


@dataclass
class Row:
    ind: Indicator
    obs: ObsRow
    sources: list[Source]


def levels(max_tlp: str) -> list[str]:
    """Markings at most ``max_tlp``, never RED."""
    cap = tlp_rules.rank(max_tlp)
    return [lv for lv in tlp_rules.LEVELS if lv != NEVER and tlp_rules.rank(lv) <= cap]


def where(rules: Rules) -> list[Any]:
    redistributable = exists().where(
        Sighting.indicator_id == Indicator.id,
        Sighting.source_id == Source.id,
        Source.redistribution.is_(True),
    )
    no_feed = ~exists().where(Sighting.indicator_id == Indicator.id)
    live = and_(Indicator.status == "active", Indicator.priority_score >= rules.min_score)
    state = or_(live, Indicator.status == "false_positive") if rules.revocations else live
    conds: list[Any] = [
        Indicator.tlp.in_(levels(rules.max_tlp)),
        Indicator.pattern.is_not(None),
        or_(redistributable, no_feed),
        state,
    ]
    if rules.types:
        conds.append(ObsRow.type.in_(rules.types))
    return conds


async def page(
    s: AsyncSession,
    rules: Rules,
    *,
    after: tuple[datetime, int] | None = None,
    added_after: datetime | None = None,
    limit: int = 500,
    ids: Sequence[str] | None = None,
) -> list[Row]:
    """Shareable indicators in (updated_at, id) order, a page at a time.
    ``after`` is the last row of the previous page; ``added_after`` the TAXII
    filter (strictly newer versions only)."""
    stmt = select(Indicator, ObsRow).join(ObsRow, ObsRow.id == Indicator.observable_id).where(*where(rules))
    if added_after is not None:
        stmt = stmt.where(Indicator.updated_at > added_after)
    if after is not None:
        stmt = stmt.where(tuple_(Indicator.updated_at, Indicator.id) > tuple_(after[0], after[1]))
    if ids:
        stmt = stmt.where(Indicator.stix_id.in_(list(ids)))
    rows = (await s.execute(stmt.order_by(Indicator.updated_at, Indicator.id).limit(limit))).all()
    by_ind: dict[int, list[Source]] = {}
    if rows:
        for ind_id, src in (
            await s.execute(
                select(Sighting.indicator_id, Source)
                .join(Source, Source.id == Sighting.source_id)
                .where(Sighting.indicator_id.in_([i.id for i, _ in rows]))
                # our own SIEM's sightings describe our network: never shared as a source
                .where(Source.kind != "environment")
            )
        ).all():
            by_ind.setdefault(int(ind_id), []).append(src)
    return [Row(i, o, by_ind.get(i.id, [])) for i, o in rows]


async def held_back(s: AsyncSession, rules: Rules) -> dict[str, int]:
    """How many otherwise-qualifying indicators each rule keeps here (for the UI)."""
    from sqlalchemy import func

    base = (
        select(func.count())
        .select_from(Indicator)
        .join(ObsRow, ObsRow.id == Indicator.observable_id)
        .where(Indicator.status == "active", Indicator.priority_score >= rules.min_score)
    )
    total = int(await s.scalar(base) or 0)
    by_tlp = int(await s.scalar(base.where(Indicator.tlp.not_in(levels(rules.max_tlp)))) or 0)
    shareable = int(
        await s.scalar(
            select(func.count())
            .select_from(Indicator)
            .join(ObsRow, ObsRow.id == Indicator.observable_id)
            .where(*where(Rules(rules.max_tlp, rules.min_score, rules.types, revocations=False)))
        )
        or 0
    )
    return {"qualifying": total, "tlp": by_tlp, "licence_or_type": max(0, total - by_tlp - shareable),
            "shareable": shareable}  # fmt: skip


def aware(v: datetime) -> datetime:
    return v if v.tzinfo else v.replace(tzinfo=UTC)
