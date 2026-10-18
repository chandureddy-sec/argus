"""The retro-hunt hook (ADR 0020): when new high-priority indicators arrive,
build a query pack to run against historical logs, because an indicator
published today may have been active in our network last week.

A pack holds the new indicators' Sigma rules compiled for each backend, with
a lookback window. Packs are stored (``retro_hunts``), shown on the
Detections page and, when an alert rule of kind ``score`` exists, the alert
links to them.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from threatlens import tlp as tlp_rules
from threatlens.detect import rules as gen
from threatlens.models import AppSetting, Indicator, RetroHunt, Sighting, Source
from threatlens.models import Observable as ObsRow
from threatlens.settings import Settings

MIN_SCORE = 80.0
LOOKBACK_DAYS = 30
MAX_PER_PACK = 500
CURSOR_KEY = "retrohunt.cursor"


async def iocs(s: AsyncSession, rows: list[tuple[Indicator, ObsRow]]) -> list[gen.Ioc]:
    srcs: dict[int, list[str]] = {}
    if rows:
        for ind_id, name in (
            await s.execute(
                select(Sighting.indicator_id, Source.name)
                .join(Source, Source.id == Sighting.source_id)
                .where(Sighting.indicator_id.in_([i.id for i, _ in rows]), Source.kind != "environment")
            )
        ).all():
            srcs.setdefault(int(ind_id), []).append(name)
    return [
        gen.Ioc(
            i.id,
            o.type,
            o.value,
            i.priority_score or 0,
            i.tlp,
            tuple(i.labels or ()),
            tuple(sorted(srcs.get(i.id, []))),
        )
        for i, o in rows
    ]


async def build(
    sm: async_sessionmaker[AsyncSession], settings: Settings, now: datetime | None = None
) -> int | None:
    """Make a pack for indicators that reached MIN_SCORE since the last run; returns its id."""
    now = now or datetime.now(UTC)
    async with sm() as s, s.begin():
        cur = await s.get(AppSetting, CURSOR_KEY)
        since = (
            datetime.fromisoformat(cur.value["since"])
            if cur and cur.value.get("since")
            else now - timedelta(hours=1)
        )
        rows = (
            await s.execute(
                select(Indicator, ObsRow)
                .join(ObsRow, ObsRow.id == Indicator.observable_id)
                .where(
                    Indicator.status == "active",
                    Indicator.priority_score >= MIN_SCORE,
                    Indicator.created_at > since,
                    Indicator.tlp != "TLP:RED",
                )
                .order_by(Indicator.created_at)
                .limit(MAX_PER_PACK)
            )
        ).all()
        newest = max((r[0].created_at for r in rows), default=None)
        mark = (
            newest if newest and newest.tzinfo else (newest.replace(tzinfo=UTC) if newest else now)
        ).isoformat()
        if cur is None:
            s.add(AppSetting(key=CURSOR_KEY, value={"since": mark}))
        else:
            cur.value = {"since": mark}
        if not rows:
            return None
        found = await iocs(s, [(i, o) for i, o in rows])
        sigma = gen.sigma_rules(found, author=settings.org_identity, base_url=settings.public_url)
        queries: dict[str, Any] = {b: [] for b in gen.SIGMA_BACKENDS}
        for r in sigma:
            for b, q in r.queries.items():
                if q:
                    queries[b].append({"rule": r.title, "query": q})
        queries["sigma"] = [{"rule": r.title, "query": r.body} for r in sigma]
        tlp = "TLP:CLEAR"
        for i in found:
            tlp = tlp_rules.stricter(tlp, i.tlp)
        pack = RetroHunt(
            created_at=now,
            title=f"{len(found)} new high-priority indicator(s) since {since:%Y-%m-%d %H:%M} UTC",
            tlp=tlp,
            indicator_ids=[i.id for i in found],
            lookback_days=LOOKBACK_DAYS,
            queries=queries,
        )
        s.add(pack)
        await s.flush()
        return pack.id


def view(p: RetroHunt) -> dict[str, Any]:
    created = p.created_at if p.created_at.tzinfo else p.created_at.replace(tzinfo=UTC)
    return {
        "id": p.id,
        "createdAt": created.isoformat(),
        "title": p.title,
        "tlp": p.tlp,
        "indicators": len(p.indicator_ids or []),
        "indicatorIds": (p.indicator_ids or [])[:50],
        "lookbackDays": p.lookback_days,
        "from": (created - timedelta(days=p.lookback_days)).isoformat(),
        "queries": p.queries,
    }
