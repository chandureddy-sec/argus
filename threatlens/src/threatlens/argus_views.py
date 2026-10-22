"""Argus JSON for the interactive views (SecIncyte parity step 4, ADR 0018):
the threat map, the activity calendar and an indicator's threat journey.

Same rules as the rest of /app/api: a signed-in session or an API key, TLP
clearance on every indicator, values defanged. Nothing here looks anything up
upstream: the map uses stored RIPEstat answers, the journey stored rows.
"""

from __future__ import annotations

import calendar as cal
from collections import Counter
from datetime import UTC, date, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from threatlens import assets, blocking
from threatlens import tlp as tlp_rules
from threatlens.api.v1 import Viewer, _sm
from threatlens.auth import Principal
from threatlens.ioc.extract import defang_text
from threatlens.models import (
    Block,
    Case,
    CaseItem,
    Enrichment,
    Indicator,
    Note,
    Sighting,
    Source,
    Verdict,
)
from threatlens.models import Observable as ObsRow
from threatlens.respcache import cached
from threatlens.webapp import MALICIOUS, SUSPICIOUS

router = APIRouter(prefix="/app/api", include_in_schema=False)

MAP_LIMIT = 3000  # located IPs drawn at most (highest score first)
PER_POINT = 60  # IPs listed per map location
ENVIRONMENT_KINDS = ("environment",)  # sources that report sightings in *our* systems (SIEM, EDR)


def _iso(v: datetime | date | None) -> str | None:
    if v is None:
        return None
    if isinstance(v, datetime) and v.tzinfo is None:
        v = v.replace(tzinfo=UTC)
    return v.isoformat()


def _aware(v: datetime) -> datetime:
    return v if v.tzinfo else v.replace(tzinfo=UTC)


def _n(n: int, word: str) -> str:
    return f"{n:,} {word}{'' if n == 1 else 's'}"


def verdict_of(score: float | None, status: str) -> str:
    if status == "false_positive":
        return "benign"
    if (score or 0) >= MALICIOUS:
        return "malicious"
    if (score or 0) >= SUSPICIOUS:
        return "suspicious"
    return "unknown"


def project(lat: float, lon: float) -> tuple[float, float]:
    """Equirectangular projection on the 1000 x 500 canvas of the land outline."""
    return round((lon + 180) / 360 * 1000, 2), round((90 - lat) / 180 * 500, 2)


# ── threat map ───────────────────────────────────────────────────────────────


@router.get("/threatmap")
async def threatmap(
    who: Viewer,
    request: Request,
    mode: Literal["landscape", "acted"] = "landscape",
) -> dict[str, Any]:
    """Located indicator IPs grouped by place. ``landscape``: every active IP
    indicator with a stored location; ``acted``: only the ones we blocked or
    an analyst confirmed malicious."""
    return await cached(request, ("threatmap", who.clearance, mode), lambda: _threatmap(request, who, mode))


async def _threatmap(request: Request, who: Principal, mode: str) -> dict[str, Any]:
    now = datetime.now(UTC)
    async with _sm(request)() as s:
        vis = Indicator.tlp.in_(tlp_rules.readable(who.clearance))
        stmt = (
            select(Indicator, ObsRow)
            .join(ObsRow, ObsRow.id == Indicator.observable_id)
            .where(vis, ObsRow.type.in_(("ipv4-addr", "ipv6-addr")))
        )
        live = select(Block.canonical_key).where(blocking.live_clause(now))
        if mode == "acted":
            stmt = stmt.where((ObsRow.canonical_key.in_(live)) | (Indicator.analyst_verdict == "tp"))
        else:
            stmt = stmt.where(Indicator.status == "active")
        rows = (
            await s.execute(stmt.order_by(Indicator.priority_score.desc().nulls_last()).limit(20_000))
        ).all()
        keys = [o.canonical_key for _, o in rows]
        geo: dict[str, dict[str, Any]] = {}
        for i in range(0, len(keys), 1000):
            for key, summ in (
                await s.execute(
                    select(Enrichment.canonical_key, Enrichment.summary).where(
                        Enrichment.enricher == "ripestat",
                        Enrichment.status == "ok",
                        Enrichment.canonical_key.in_(keys[i : i + 1000]),
                    )
                )
            ).all():
                if isinstance(summ, dict) and summ.get("latitude") is not None:
                    geo[key] = summ
        blocked = await blocking.blocks_for(s, list(geo), now)
        seen = await _env_counts(s, [ind.id for ind, o in rows if o.canonical_key in geo])
    points: dict[tuple[float, float], dict[str, Any]] = {}
    located = 0
    for ind, o in rows:
        g = geo.get(o.canonical_key)
        if g is None:
            continue
        if located >= MAP_LIMIT:
            break
        located += 1
        try:
            lat, lon = float(g["latitude"]), float(g["longitude"])
        except (TypeError, ValueError, KeyError):
            continue
        key = (round(lat * 2) / 2, round(lon * 2) / 2)  # ~0.5° cells: one dot per city
        p = points.get(key)
        if p is None:
            x, y = project(lat, lon)
            place = ", ".join(str(v) for v in (g.get("city"), g.get("country")) if v) or "Unknown"
            p = points[key] = {"lat": lat, "lon": lon, "x": x, "y": y, "place": place,
                               "country": g.get("country") or "", "count": 0, "ips": []}  # fmt: skip
        p["count"] += 1
        b = blocked.get(o.canonical_key)
        if len(p["ips"]) < PER_POINT:
            p["ips"].append(
                {
                    "id": ind.id,
                    "value": o.defanged,
                    "verdict": verdict_of(ind.priority_score, ind.status),
                    "score": ind.priority_score,
                    "blocked": b.mode if b else None,
                    "flagged": ind.analyst_verdict == "tp",
                    "seen": seen.get(ind.id, 0),
                    "asn": defang_text(str(g.get("as_holder") or "")),
                    "lastSeen": _iso(o.last_seen),
                }
            )
    pts = sorted(points.values(), key=lambda p: -p["count"])
    for p in pts:
        verdicts = {i["verdict"] for i in p["ips"]}
        p["tone"] = (
            "malicious"
            if "malicious" in verdicts
            else "suspicious"
            if "suspicious" in verdicts
            else "unknown"
        )
        p["acted"] = sum(1 for i in p["ips"] if i["blocked"] or i["flagged"])
        p["seen"] = sum(1 for i in p["ips"] if i["seen"])
    return {
        "mode": mode,
        "points": pts,
        "located": located,
        "missing": max(0, len(rows) - len(geo)),
        "truncated": len(geo) > MAP_LIMIT,
    }


async def _env_counts(s: AsyncSession, ids: list[int]) -> dict[int, int]:
    """Indicator id → times seen in our own environment (SIEM/EDR sightings)."""
    out: dict[int, int] = {}
    for i in range(0, len(ids), 1000):
        for ind_id, n in (
            await s.execute(
                select(Sighting.indicator_id, func.sum(Sighting.times_reported))
                .join(Source, Source.id == Sighting.source_id)
                .where(Source.kind.in_(ENVIRONMENT_KINDS), Sighting.indicator_id.in_(ids[i : i + 1000]))
                .group_by(Sighting.indicator_id)
            )
        ).all():
            out[int(ind_id)] = int(n or 0)
    return out


# ── activity calendar ────────────────────────────────────────────────────────


@router.get("/calendar")
async def calendar(
    who: Viewer,
    request: Request,
    month: Annotated[str | None, Query(pattern=r"^\d{4}-\d{2}$")] = None,
) -> dict[str, Any]:
    """One month, day by day: new indicators (and how many scored malicious),
    cases opened and blocks placed. Each day links to its indicators."""
    return await cached(request, ("calendar", who.clearance, month), lambda: _calendar(request, who, month))


async def _calendar(request: Request, who: Principal, month: str | None) -> dict[str, Any]:
    today = datetime.now(UTC).date()
    try:
        first = date.fromisoformat(f"{month}-01") if month else today.replace(day=1)
    except ValueError as e:
        raise HTTPException(422, "month must be YYYY-MM") from e
    days_in = cal.monthrange(first.year, first.month)[1]
    start = datetime(first.year, first.month, 1, tzinfo=UTC)
    end = start + timedelta(days=days_in)
    vis = Indicator.tlp.in_(tlp_rules.readable(who.clearance))
    async with _sm(request)() as s:
        new: Counter[int] = Counter()
        mal: Counter[int] = Counter()
        for created, score in (
            await s.execute(
                select(Indicator.created_at, Indicator.priority_score).where(
                    vis, Indicator.created_at >= start, Indicator.created_at < end
                )
            )
        ).all():
            d = _aware(created).day
            new[d] += 1
            if (score or 0) >= MALICIOUS:
                mal[d] += 1
        cases: Counter[int] = Counter(
            _aware(c).day
            for c in (
                await s.scalars(
                    select(Case.created_at).where(
                        Case.tlp.in_(tlp_rules.readable(who.clearance)),
                        Case.created_at >= start,
                        Case.created_at < end,
                    )
                )
            ).all()
        )
        blocks: Counter[int] = Counter(
            _aware(c).day
            for c in (
                await s.scalars(
                    select(Block.created_at).where(
                        Block.tlp.in_(tlp_rules.readable(who.clearance)),
                        Block.created_at >= start,
                        Block.created_at < end,
                    )
                )
            ).all()
        )
    prev = (first - timedelta(days=1)).replace(day=1)
    nxt = (first + timedelta(days=days_in)).replace(day=1)
    return {
        "month": first.strftime("%Y-%m"),
        "label": first.strftime("%B %Y"),
        "prev": prev.strftime("%Y-%m"),
        "next": nxt.strftime("%Y-%m") if nxt <= today.replace(day=1) else None,
        "firstWeekday": (first.weekday() + 1) % 7,  # 0 = Sunday, for a Sunday-first grid
        "today": today.isoformat() if today.replace(day=1) == first else None,
        "max": max(new.values(), default=0),
        "days": [
            {
                "date": (first + timedelta(days=d - 1)).isoformat(),
                "day": d,
                "new": new[d],
                "malicious": mal[d],
                "cases": cases[d],
                "blocks": blocks[d],
            }
            for d in range(1, days_in + 1)
        ],
    }


# ── threat journey ───────────────────────────────────────────────────────────


async def journey(s: AsyncSession, ind: Indicator, obs: ObsRow, clearance: str) -> list[dict[str, Any]]:
    """An indicator's path from feed to action, as ordered stages. Each stage
    is ``done`` (it happened), ``none`` (not yet) or ``warn`` (needs a look),
    with the time it happened and plain-language lines."""
    now = datetime.now(UTC)
    sightings = list(ind.sightings)
    feeds = [sg for sg in sightings if sg.source.kind not in ENVIRONMENT_KINDS]
    env = [sg for sg in sightings if sg.source.kind in ENVIRONMENT_KINDS]
    stages: list[dict[str, Any]] = []

    first = min((_aware(sg.first_seen) for sg in feeds), default=None)
    stages.append(
        {
            "key": "reported",
            "title": "Reported",
            "state": "done" if feeds else "none",
            "at": _iso(first),
            "lines": [
                f"{sg.source.title} (grade {sg.source.reliability}), {_n(sg.times_reported, 'report')} since "
                f"{_aware(sg.first_seen):%Y-%m-%d}"
                for sg in sorted(feeds, key=lambda x: x.first_seen)
            ]
            or ["Added by an analyst, not by a feed"],
        }
    )
    stages.append(
        {
            "key": "ingested",
            "title": "Ingested",
            "state": "done",
            "at": _iso(ind.created_at),
            "lines": [
                f"Normalised as {obs.type}, marked {ind.tlp}",
                f"Status {ind.status.replace('_', ' ')}",
            ],
        }
    )
    v = verdict_of(ind.priority_score, ind.status)
    bd = ind.score_breakdown or {}
    stages.append(
        {
            "key": "scored",
            "title": "Scored",
            "state": "done" if ind.priority_score is not None else "none",
            "at": _iso(ind.updated_at),
            "lines": [
                f"{round(ind.priority_score or 0)}/100: {v}",
                *([f"Valid until {_aware(ind.valid_until):%Y-%m-%d}"] if ind.valid_until else []),
                *([f"Model {bd.get('config_version')}"] if bd.get("config_version") else []),
            ],
            "tone": v,
        }
    )
    enr = (
        await s.execute(
            select(Enrichment.enricher, Enrichment.fetched_at, Enrichment.status)
            .where(Enrichment.canonical_key == obs.canonical_key)
            .order_by(Enrichment.fetched_at.desc())
        )
    ).all()
    names = ", ".join(e for e, _, _ in enr)
    stages.append(
        {
            "key": "enriched",
            "title": "Enriched",
            "state": "done" if enr else "none",
            "at": _iso(enr[0][1]) if enr else None,
            "lines": [f"{len(enr)} provider{'s' if len(enr) != 1 else ''} answered: {names}"]
            if enr
            else ["No provider asked yet (Verify asks them)"],
        }
    )
    asset = await assets.asset_for(s, obs.canonical_key)
    env_lines = [
        f"{sg.source.title}: {sg.times_reported:,} times, last {_aware(sg.last_seen):%Y-%m-%d %H:%M} UTC"
        for sg in env
    ]
    if asset:
        env_lines.append("It is one of our own assets")
    stages.append(
        {
            "key": "seen",
            "title": "Seen in our environment",
            "state": "warn" if env else "done" if asset else "none",
            "at": _iso(max((_aware(sg.last_seen) for sg in env), default=None)),
            "lines": env_lines or ["Not seen in our alerts (sightings arrive from the SIEM integrations)"],
        }
    )
    decisions = (
        await s.execute(
            select(Verdict.verdict, Verdict.actor, Verdict.created_at)
            .where(Verdict.indicator_id == ind.id)
            .order_by(Verdict.created_at.desc())
        )
    ).all()
    notes = int(
        await s.scalar(select(func.count()).select_from(Note).where(Note.indicator_id == ind.id)) or 0
    )
    words = {"tp": "confirmed malicious", "fp": "marked not malicious", "reset": "reset the decision"}
    stages.append(
        {
            "key": "decided",
            "title": "Analyst decision",
            "state": "done" if ind.analyst_verdict else "none",
            "at": _iso(decisions[0][2]) if decisions else None,
            "lines": [f"{a} {words.get(d, d)} on {_aware(t):%Y-%m-%d %H:%M}" for d, a, t in decisions[:3]]
            + ([f"{notes} note{'s' if notes != 1 else ''}"] if notes else [])
            or ["No decision yet"],
        }
    )
    b = await blocking.live_block(s, obs.canonical_key, now)
    case_rows = (
        await s.execute(
            select(Case.id, Case.title, Case.status, CaseItem.added_at)
            .join(CaseItem, CaseItem.case_id == Case.id)
            .where(
                and_(CaseItem.kind == "indicator", CaseItem.ref == str(ind.id)),
                Case.tlp.in_(tlp_rules.readable(clearance)),
            )
            .order_by(CaseItem.added_at.desc())
        )
    ).all()
    acted = []
    if b is not None:
        acted.append(
            f"Blocked ({blocking.state(b, now).replace('_', ' ')}), expires {_aware(b.expires_at):%Y-%m-%d}"
        )
    acted += [f"In case #{cid} ({status}): {defang_text(title)}" for cid, title, status, _ in case_rows[:3]]
    stages.append(
        {
            "key": "acted",
            "title": "Action",
            "state": "done" if acted else "none",
            "at": _iso(
                max([*(t for *_, t in case_rows), *([b.created_at] if b else [])], default=None, key=_aware)
            ),
            "lines": acted or ["No block or case yet"],
            "cases": [{"id": cid, "title": defang_text(t), "status": st} for cid, t, st, _ in case_rows[:5]],
            "block": {"id": b.id, "mode": b.mode, "state": blocking.state(b, now)} if b else None,
        }
    )
    return stages
