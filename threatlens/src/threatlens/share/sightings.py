"""Sightings from our own environment (ADR 0019): a SIEM, EDR or proxy saw a
value that our intelligence knows about.

* Only values we already hold as indicators are recorded: a log line is not
  intelligence, so nothing new is created from it.
* They are stored as ordinary ``sightings`` of a source of kind
  ``environment`` (``siem_<name>``). Scoring ignores that kind, because seeing
  a value is not a report that it is malicious; the threat journey and the
  ``environment`` alert rule read it.
* The caller gets back what each value is (verdict, score, action), within
  their TLP clearance, so a SOC workflow can enrich the alert in the same call.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from threatlens import tlp as tlp_rules
from threatlens.ioc.extract import extract
from threatlens.ioc.normalize import guess
from threatlens.ioc.types import Observable
from threatlens.models import AuditLog, Indicator, Sighting, Source
from threatlens.models import Observable as ObsRow

MAX_VALUES = 200
_SLUG = re.compile(r"[^a-z0-9]+")
# Wazuh alert fields that hold network or file indicators (the rest of `data` is scanned too).
WAZUH_FIELDS = ("srcip", "dstip", "src_ip", "dest_ip", "url", "hostname", "domain", "md5", "sha1", "sha256")


@dataclass
class Match:
    value: str  # defanged
    indicator_id: int
    verdict: str
    score: float | None
    tlp: str
    action: str


def source_name(system: str) -> str:
    slug = _SLUG.sub("_", system.strip().lower()).strip("_")[:40] or "siem"
    return f"siem_{slug}"


async def ensure_source(s: AsyncSession, system: str) -> Source:
    name = source_name(system)
    src = await s.scalar(select(Source).where(Source.name == name))
    if src is None:
        src = Source(
            name=name,
            title=f"{system.strip()[:60] or 'SIEM'} (our environment)",
            kind="environment",
            homepage="",
            reliability="A",
            reliability_note="Our own telemetry: what our systems saw.",
            credibility=1,
            license="Own telemetry",
            license_url="",
            commercial_use=True,
            redistribution=False,
            attribution=None,
            upstream=name,
            tlp_default="TLP:AMBER",
            requires_key=False,
            enabled=True,
            interval_minutes=1440,
            health="ok",
            checkpoint={},
        )
        s.add(src)
        await s.flush()
    return src


def observables(values: Iterable[str]) -> list[Observable]:
    out: dict[str, Observable] = {}
    for raw in values:
        if len(out) >= MAX_VALUES:
            break
        r = guess(str(raw).strip())
        if isinstance(r, Observable):
            out.setdefault(r.key, r)
            continue
        for found in extract(str(raw)[:5000]):  # free text: pull indicators out of it
            if isinstance(found, Observable):
                out.setdefault(found.key, found)
    return list(out.values())[:MAX_VALUES]


def _strings(node: Any, depth: int = 0) -> Iterator[str]:
    if depth > 6:
        return
    if isinstance(node, str):
        yield node[:2000]
    elif isinstance(node, dict):
        for v in node.values():
            yield from _strings(v, depth + 1)
    elif isinstance(node, list):
        for v in node[:100]:
            yield from _strings(v, depth + 1)


def wazuh_values(alert: dict[str, Any]) -> list[str]:
    """Candidate indicator values in one Wazuh alert: the well-known fields first,
    then anything under ``data`` and ``syscheck`` (hashes of changed files)."""
    data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
    vals = [str(data[k]) for k in WAZUH_FIELDS if isinstance(data, dict) and data.get(k)]
    vals += list(_strings(data))
    sys_ = alert.get("syscheck") if isinstance(alert.get("syscheck"), dict) else {}
    vals += [
        str(sys_[k])
        for k in ("md5_after", "sha1_after", "sha256_after")
        if isinstance(sys_, dict) and sys_.get(k)
    ]
    return vals


async def record(
    s: AsyncSession,
    system: str,
    values: Iterable[str],
    *,
    clearance: str,
    actor: str,
    seen_at: datetime | None = None,
    context: dict[str, Any] | None = None,
) -> tuple[list[Match], int]:
    """Record sightings of known indicators; return (matches the caller may see, values checked)."""
    obs = observables(values)
    if not obs:
        return [], 0
    rows = (
        await s.execute(
            select(Indicator, ObsRow)
            .join(ObsRow, ObsRow.id == Indicator.observable_id)
            .where(ObsRow.canonical_key.in_([o.key for o in obs]))
        )
    ).all()
    if not rows:
        return [], len(obs)
    src = await ensure_source(s, system)
    when = seen_at or datetime.now(UTC)
    ctx = {k: str(v)[:300] for k, v in (context or {}).items()}
    existing = {
        sg.indicator_id: sg
        for sg in (
            await s.scalars(
                select(Sighting).where(
                    Sighting.source_id == src.id, Sighting.indicator_id.in_([i.id for i, _ in rows])
                )
            )
        ).all()
    }
    matches: list[Match] = []
    for ind, o in rows:
        sg = existing.get(ind.id)
        if sg is None:
            s.add(
                Sighting(
                    indicator_id=ind.id,
                    source_id=src.id,
                    first_seen=when,
                    last_seen=when,
                    times_reported=1,
                    confidence=100,
                    labels=[],
                    context=ctx,
                )
            )
        else:
            sg.last_seen = max(_aware(sg.last_seen), when)
            sg.times_reported += 1
            sg.context = ctx or sg.context
        if tlp_rules.may_read(clearance, ind.tlp):
            score = ind.priority_score
            verdict = (
                "benign"
                if ind.status == "false_positive"
                else "malicious"
                if (score or 0) >= 60
                else "suspicious"
                if (score or 0) >= 30
                else "unknown"
            )
            action = {"malicious": "block", "suspicious": "investigate"}.get(verdict, "monitor")
            matches.append(Match(o.defanged, ind.id, verdict, score, ind.tlp, action))
    s.add(
        AuditLog(
            actor=actor[:100],
            action="sighting.record",
            target=src.name,
            details={"checked": len(obs), "known": len(rows)},
        )
    )
    return matches, len(obs)


def _aware(v: datetime) -> datetime:
    return v if v.tzinfo else v.replace(tzinfo=UTC)
