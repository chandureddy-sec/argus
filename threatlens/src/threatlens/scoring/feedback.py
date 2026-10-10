"""Analyst feedback: true/false-positive verdicts on indicators, and the
source weights derived from them (ADR 0008).

* A verdict is appended to ``verdicts`` and mirrored on the indicator:
  ``fp`` marks it ``false_positive`` (score 0, never re-activated by the
  allowlist or a feed); ``tp`` adds an analyst signal to its score and
  re-activates it if it was marked false positive; ``reset`` removes the
  analyst's decision and lets the allowlist and feeds decide again.
* Source weights: for each feed, count the indicators it reported whose
  latest analyst verdict is TP or FP, then

      precision = (tp + k * p0) / (tp + fp + k)
      factor    = clamp(min_factor, max_factor, precision / p0)

  with prior precision ``p0`` and ``k`` pseudo-verdicts from the config. The
  factor multiplies the source's Admiralty weight in every score. It is
  recomputed from all verdicts each time (never nudged incrementally, so it
  can't drift), and every change is written to the audit log.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from threatlens.models import AuditLog, Indicator, Sighting, Source, Verdict
from threatlens.models import Observable as ObsRow
from threatlens.scoring.config import ScoringConfig, get_config
from threatlens.scoring.store import rescore
from threatlens.settings import Settings

Feedback = Literal["tp", "fp", "reset"]


@dataclass
class WeightChange:
    source: str
    tp: int
    fp: int
    before: float
    after: float


def factor(tp: int, fp: int, cfg: ScoringConfig) -> float:
    fb = cfg.feedback
    precision = (tp + fb.pseudo_count * fb.prior_precision) / (tp + fp + fb.pseudo_count)
    return round(max(fb.min_factor, min(fb.max_factor, precision / fb.prior_precision)), 4)


async def apply_feedback(
    s: AsyncSession, indicator_id: int, verdict: Feedback, *, actor: str, note: str = ""
) -> Indicator:
    """Record one verdict and update the indicator (the caller commits)."""
    ind = await s.get(Indicator, indicator_id)
    if ind is None:
        raise LookupError("no such indicator")
    now = datetime.now(UTC)
    before = {"status": ind.status, "analyst_verdict": ind.analyst_verdict}
    s.add(Verdict(indicator_id=ind.id, verdict=verdict, actor=actor[:100], note=note[:2000], created_at=now))
    if verdict == "fp":
        ind.analyst_verdict, ind.status = "fp", "false_positive"
    elif verdict == "tp":
        ind.analyst_verdict = "tp"
        if ind.status == "false_positive":
            ind.status = "active"
    else:
        ind.analyst_verdict = None
        if ind.status == "false_positive" and ind.allowlist_reason is None:
            ind.status = "active"
        await _reapply_allowlist(s, ind)
    ind.analyst_verdict_by = actor[:100] if ind.analyst_verdict else None
    ind.analyst_verdict_at = now if ind.analyst_verdict else None
    ind.updated_at = now
    s.add(
        AuditLog(
            actor=actor[:100],
            action="indicator.feedback",
            target=f"indicator:{ind.id}",
            details={"verdict": verdict, "note": note[:500], "before": before,
                     "after": {"status": ind.status, "analyst_verdict": ind.analyst_verdict}},
        )
    )  # fmt: skip
    return ind


async def _reapply_allowlist(s: AsyncSession, ind: Indicator) -> None:
    from threatlens.collect import Collector, load_allowlist  # collect imports scoring; avoid a cycle
    from threatlens.ioc.types import IOCType, Observable

    obs = await s.get(ObsRow, ind.observable_id)
    if obs is not None:
        verdict = (await load_allowlist(s)).check(Observable(IOCType(obs.type), obs.value))
        Collector._apply_verdict(ind, verdict)


async def recompute_source_weights(s: AsyncSession, cfg: ScoringConfig, *, actor: str) -> list[WeightChange]:
    """Re-derive every feed's weight factor from the latest verdicts; audit each change."""
    counts: dict[int, dict[str, int]] = {}
    for source_id, verdict, n in (
        await s.execute(
            select(Sighting.source_id, Indicator.analyst_verdict, func.count())
            .join(Indicator, Indicator.id == Sighting.indicator_id)
            .where(Indicator.analyst_verdict.is_not(None))
            .group_by(Sighting.source_id, Indicator.analyst_verdict)
        )
    ).all():
        if verdict:
            counts.setdefault(source_id, {})[verdict] = int(n)
    changes: list[WeightChange] = []
    for src in (await s.scalars(select(Source))).all():
        c = counts.get(src.id, {})
        tp, fp = c.get("tp", 0), c.get("fp", 0)
        new = factor(tp, fp, cfg)
        old = src.weight_factor if src.weight_factor is not None else 1.0
        if (src.feedback_tp, src.feedback_fp) == (tp, fp) and abs(old - new) < 1e-9:
            continue
        src.feedback_tp, src.feedback_fp, src.weight_factor = tp, fp, new
        if abs(old - new) >= 1e-9:
            changes.append(WeightChange(src.name, tp, fp, old, new))
            s.add(
                AuditLog(
                    actor=actor[:100],
                    action="source.weight",
                    target=src.name,
                    details={"from": old, "to": new, "tp": tp, "fp": fp, "config": cfg.tag},
                )
            )
    return changes


async def history(s: AsyncSession, indicator_id: int, limit: int = 50) -> list[dict[str, Any]]:
    rows = (
        await s.scalars(
            select(Verdict)
            .where(Verdict.indicator_id == indicator_id)
            .order_by(Verdict.created_at.desc(), Verdict.id.desc())
            .limit(limit)
        )
    ).all()
    return [{"verdict": v.verdict, "actor": v.actor, "note": v.note, "at": v.created_at} for v in rows]


async def sources_of(s: AsyncSession, indicator_id: int) -> list[int]:
    return list(
        (await s.scalars(select(Sighting.source_id).where(Sighting.indicator_id == indicator_id))).all()
    )


async def give_feedback(
    sm: async_sessionmaker[AsyncSession],
    settings: Settings,
    indicator_id: int,
    verdict: Feedback,
    *,
    actor: str,
    note: str = "",
) -> list[WeightChange]:
    """Record a verdict, re-derive source weights, and re-score the indicator.
    Returns the source weight changes (other indicators of those sources are
    re-scored by :func:`rescore_sources`, the caller schedules it)."""
    cfg = get_config(settings.scoring_path)
    async with sm() as s, s.begin():
        await apply_feedback(s, indicator_id, verdict, actor=actor, note=note)
        changes = await recompute_source_weights(s, cfg, actor=actor)
    await rescore(sm, settings, ids=[indicator_id])
    return changes


async def rescore_sources(sm: async_sessionmaker[AsyncSession], settings: Settings, names: list[str]) -> int:
    """Re-score every indicator the named sources reported (after a weight change)."""
    if not names:
        return 0
    async with sm() as s:
        ids = list(
            (
                await s.scalars(
                    select(Sighting.indicator_id).join(Source).where(Source.name.in_(names)).distinct()
                )
            ).all()
        )
    return (await rescore(sm, settings, ids=ids)).scored if ids else 0
