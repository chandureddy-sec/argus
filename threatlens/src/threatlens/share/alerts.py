"""Alerting (ADR 0019): rules decide what is worth a message, channels
(Slack, Teams, Telegram, email, webhook integrations) carry it.

Rule kinds:

* ``score``: an indicator reaches ``min_score`` (default 80).
* ``pir``: an indicator that matches a priority intelligence requirement or
  our assets (its score breakdown has relevance hits), from ``min_score`` 30.
* ``kev_asset``: CISA adds a CVE that affects software in our stack.
* ``environment``: our SIEM saw a value we hold at ``min_score`` or more.
* ``lookalike``: a new domain imitating ours turned up in CT logs or our
  feeds (ADR 0021).

Guarantees:

* **Once.** Every alert has a dedup key per rule (the indicator, the CVE,
  or the indicator and day for SIEM sightings); a unique constraint makes a
  re-run, a re-score or a second worker unable to repeat it.
* **Within TLP.** An alert carries its subject's marking. It goes only to
  channels whose ``max_tlp`` allows it, and never above the rule's own cap.
  TLP:RED never leaves.
* **Rate-limited.** At most ``Settings.alert_max_per_hour`` messages per channel
  per hour. The rest are held and summarised in one digest message.
* **No backlog storms.** A new rule starts from "now"; it does not alert on
  everything already in the store.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from threatlens import assets
from threatlens import tlp as tlp_rules
from threatlens.ioc.extract import defang_text
from threatlens.models import (
    ALERT_KINDS,
    TLP_LEVELS,
    AlertEvent,
    AlertRule,
    AuditLog,
    Indicator,
    Integration,
    IntegrationRun,
    Lookalike,
    Sighting,
    Source,
    Vulnerability,
    VulnerabilityProduct,
    utcnow,
)
from threatlens.models import Observable as ObsRow
from threatlens.settings import Settings
from threatlens.share import integrations, sinks

PER_RUN = 200
DEFAULT_MIN = {"score": 80.0, "pir": 30.0, "environment": 60.0}


class AlertError(ValueError):
    pass


@dataclass
class Candidate:
    key: str
    title: str
    lines: list[str]
    link: str
    tlp: str
    at: datetime


def _aware(v: datetime) -> datetime:
    return v if v.tzinfo else v.replace(tzinfo=UTC)


def _iso(v: datetime | None) -> str | None:
    return _aware(v).isoformat() if v else None


# ── rules ────────────────────────────────────────────────────────────────────


def check_rule(
    name: str, kind: str, params: dict[str, Any], channels: Sequence[int], max_tlp: str
) -> dict[str, Any]:
    if not 2 <= len(name.strip()) <= 100:
        raise AlertError("Name: 2 to 100 characters")
    if kind not in ALERT_KINDS:
        raise AlertError("Kind: score, pir, kev_asset, environment or lookalike")
    if max_tlp not in TLP_LEVELS or max_tlp == "TLP:RED":
        raise AlertError("Most restricted marking: CLEAR to AMBER+STRICT (RED never leaves)")
    if not channels:
        raise AlertError("Channels: pick at least one")
    out: dict[str, Any] = {}
    if kind in DEFAULT_MIN:
        try:
            out["min_score"] = float(params.get("min_score", DEFAULT_MIN[kind]))
        except (TypeError, ValueError) as e:
            raise AlertError("Minimum score: a number") from e
        if not 0 <= out["min_score"] <= 100:
            raise AlertError("Minimum score: 0 to 100")
    if kind == "score" and params.get("types"):
        out["types"] = [str(t) for t in params["types"]][:10]
    return out


async def create_rule(
    s: AsyncSession,
    *,
    name: str,
    kind: str,
    params: dict[str, Any],
    channels: Sequence[int],
    max_tlp: str,
    actor: str,
) -> AlertRule:
    p = check_rule(name, kind, params, channels, max_tlp)
    await _check_channels(s, channels)
    if await s.scalar(select(AlertRule).where(AlertRule.name == name.strip())):
        raise AlertError(f"a rule named {name.strip()!r} already exists")
    now = utcnow()
    r = AlertRule(
        name=name.strip(),
        kind=kind,
        enabled=True,
        params=p,
        channels=list(channels),
        max_tlp=max_tlp,
        cursor={"since": now.isoformat()},
        created_by=actor[:100],
        created_at=now,
        updated_at=now,
    )
    s.add(r)
    await s.flush()
    s.add(
        AuditLog(
            actor=actor[:100],
            action="alert_rule.create",
            target=f"alert_rule:{r.id}",
            details={
                "name": r.name,
                "kind": kind,
                "params": p,
                "channels": list(channels),
                "max_tlp": max_tlp,
            },
        )
    )
    return r


async def update_rule(
    s: AsyncSession,
    r: AlertRule,
    *,
    params: dict[str, Any],
    channels: Sequence[int],
    max_tlp: str,
    enabled: bool,
    actor: str,
) -> AlertRule:
    p = check_rule(r.name, r.kind, params, channels, max_tlp)
    await _check_channels(s, channels)
    r.params, r.channels, r.max_tlp, r.enabled, r.updated_at = p, list(channels), max_tlp, enabled, utcnow()
    s.add(
        AuditLog(
            actor=actor[:100],
            action="alert_rule.update",
            target=f"alert_rule:{r.id}",
            details={"params": p, "channels": list(channels), "max_tlp": max_tlp, "enabled": enabled},
        )
    )
    return r


async def _check_channels(s: AsyncSession, ids: Sequence[int]) -> None:
    rows = (await s.scalars(select(Integration).where(Integration.id.in_(list(ids))))).all()
    if len(rows) != len(set(ids)):
        raise AlertError("Channels: unknown integration")
    wrong = [i.name for i in rows if sinks.KINDS[i.kind].role == "indicators"]
    if wrong:
        raise AlertError(f"Channels: {', '.join(wrong)} receive indicators, not alerts")


def rule_view(r: AlertRule) -> dict[str, Any]:
    return {
        "id": r.id,
        "name": r.name,
        "kind": r.kind,
        "enabled": r.enabled,
        "params": r.params,
        "channels": r.channels,
        "maxTlp": r.max_tlp,
        "since": (r.cursor or {}).get("since"),
        "createdBy": r.created_by,
        "createdAt": _iso(r.created_at),
    }


# ── candidates per kind ─────────────────────────────────────────────────────


def _ind_lines(ind: Indicator, obs: ObsRow, why: str) -> list[str]:
    return [
        f"{obs.type} {obs.defanged}",
        f"Score {round(ind.priority_score or 0)}/100 · {why}",
        *(["Labels: " + ", ".join((ind.labels or [])[:6])] if ind.labels else []),
    ]


async def _score(s: AsyncSession, r: AlertRule, since: datetime) -> list[Candidate]:
    stmt = (
        select(Indicator, ObsRow)
        .join(ObsRow, ObsRow.id == Indicator.observable_id)
        .where(
            Indicator.status == "active",
            Indicator.priority_score >= r.params.get("min_score", 80),
            Indicator.updated_at > since,
            Indicator.tlp != "TLP:RED",
        )
    )
    if r.params.get("types"):
        stmt = stmt.where(ObsRow.type.in_(r.params["types"]))
    rows = (await s.execute(stmt.order_by(Indicator.updated_at).limit(PER_RUN))).all()
    return [
        Candidate(
            f"ind:{i.id}",
            f"High-priority indicator: {o.defanged}",
            _ind_lines(i, o, f"at or above {r.params.get('min_score', 80):g}"),
            f"/indicators/{i.id}",
            i.tlp,
            _aware(i.updated_at),
        )
        for i, o in rows
    ]


async def _pir(s: AsyncSession, r: AlertRule, since: datetime) -> list[Candidate]:
    rows = (
        await s.execute(
            select(Indicator, ObsRow)
            .join(ObsRow, ObsRow.id == Indicator.observable_id)
            .where(
                Indicator.status == "active",
                Indicator.priority_score >= r.params.get("min_score", 30),
                Indicator.updated_at > since,
                Indicator.tlp != "TLP:RED",
            )
            .order_by(Indicator.updated_at)
            .limit(PER_RUN * 5)
        )
    ).all()
    out = []
    for i, o in rows:
        rel = (i.score_breakdown or {}).get("relevance") or {}
        hits = [h for h in rel.get("hits") or [] if isinstance(h, dict)]
        if not hits or not rel.get("applied", True):
            continue
        why = "; ".join(str(h.get("reason", ""))[:120] for h in hits[:3])
        out.append(
            Candidate(
                f"ind:{i.id}",
                f"Matches our priorities: {o.defanged}",
                _ind_lines(i, o, why),
                f"/indicators/{i.id}",
                i.tlp,
                _aware(i.updated_at),
            )
        )
        if len(out) >= PER_RUN:
            break
    return out


async def _kev_asset(s: AsyncSession, r: AlertRule, since: datetime, settings: Settings) -> list[Candidate]:
    stack = {(v.lower(), p.lower()) for _, v, p in await assets.org_stack(s, settings)}
    if not stack:
        return []
    vulns = (
        await s.scalars(
            # by the day CISA added it: EPSS refreshes touch every CVE daily, and an old
            # KEV entry is not news (the dedup key still stops repeats)
            select(Vulnerability)
            .where(Vulnerability.kev.is_(True), Vulnerability.kev_date_added >= since.date())
            .order_by(Vulnerability.kev_date_added)
            .limit(PER_RUN * 5)
        )
    ).all()
    out = []
    for v in vulns:
        prods = (
            await s.execute(
                select(VulnerabilityProduct.vendor, VulnerabilityProduct.product).where(
                    VulnerabilityProduct.vulnerability_id == v.id
                )
            )
        ).all()
        hit = [f"{a} {b}" for a, b in prods if (a.lower(), b.lower()) in stack]
        if not hit:
            continue
        out.append(
            Candidate(
                f"cve:{v.cve_id}",
                f"Exploited vulnerability in our stack: {v.cve_id}",
                [
                    f"{v.kev_name or v.cve_id}",
                    f"Affects: {', '.join(hit[:3])}",
                    f"Patch priority {v.patch_priority or '?'} · CISA due {v.kev_due_date or 'n/a'}",
                ],
                f"/vulnerabilities/{v.cve_id}",
                "TLP:CLEAR",
                since,
            )
        )
    return out[:PER_RUN]


async def _environment(s: AsyncSession, r: AlertRule, since: datetime) -> list[Candidate]:
    rows = (
        await s.execute(
            select(Sighting, Indicator, ObsRow, Source)
            .join(Indicator, Indicator.id == Sighting.indicator_id)
            .join(ObsRow, ObsRow.id == Indicator.observable_id)
            .join(Source, Source.id == Sighting.source_id)
            .where(
                Source.kind == "environment",
                Sighting.last_seen > since,
                Indicator.priority_score >= r.params.get("min_score", 60),
                Indicator.tlp != "TLP:RED",
            )
            .order_by(Sighting.last_seen)
            .limit(PER_RUN)
        )
    ).all()
    return [
        Candidate(
            f"env:{i.id}:{_aware(sg.last_seen):%Y-%m-%d}",
            f"Known-bad value seen in our environment: {o.defanged}",
            [
                *_ind_lines(i, o, f"seen by {src.title} ({sg.times_reported}x)"),
                *(f"{k}: {v}" for k, v in list((sg.context or {}).items())[:4]),
            ],
            f"/indicators/{i.id}",
            i.tlp,
            _aware(sg.last_seen),
        )
        for sg, i, o, src in rows
    ]


async def _lookalike(s: AsyncSession, since: datetime) -> list[Candidate]:
    rows = (
        await s.scalars(
            select(Lookalike)
            .where(Lookalike.first_seen > since, Lookalike.status == "new")
            .order_by(Lookalike.first_seen, Lookalike.id)
            .limit(PER_RUN)
        )
    ).all()
    out = []
    for lk in rows:
        seen = sorted({str(e.get("source", "")) for e in lk.evidence or [] if e.get("source")})
        out.append(
            Candidate(
                f"lookalike:{lk.candidate}",
                f"Lookalike of {lk.domain}: {defang_text(lk.candidate)}",
                [
                    f"Technique: {lk.fuzzer}",
                    f"Seen in: {', '.join('certificate logs' if x == 'ct' else 'our feeds' for x in seen)}",
                    "Confirm and block it, or mark it benign, in Argus.",
                ],
                "/lookalikes",
                "TLP:CLEAR",  # public CT data about our own brand
                _aware(lk.first_seen),
            )
        )
    return out


async def candidates(s: AsyncSession, r: AlertRule, since: datetime, settings: Settings) -> list[Candidate]:
    if r.kind == "score":
        return await _score(s, r, since)
    if r.kind == "pir":
        return await _pir(s, r, since)
    if r.kind == "kev_asset":
        return await _kev_asset(s, r, since, settings)
    if r.kind == "lookalike":
        return await _lookalike(s, since)
    return await _environment(s, r, since)


# ── evaluation and delivery ─────────────────────────────────────────────────


async def evaluate(sm: async_sessionmaker[AsyncSession], settings: Settings) -> dict[str, int]:
    """Raise new alerts for every enabled rule and deliver them; safe to run often."""
    raised = delivered = held = 0
    async with sm() as s:
        rules = (await s.scalars(select(AlertRule).where(AlertRule.enabled.is_(True)))).all()
    for rule in rules:
        new_events: list[int] = []
        async with sm() as s, s.begin():
            r = await s.get(AlertRule, rule.id)
            if r is None:
                continue
            since = datetime.fromisoformat((r.cursor or {}).get("since") or utcnow().isoformat())
            found = await candidates(s, r, _aware(since), settings)
            newest = since
            for c in found:
                newest = max(_aware(newest), c.at)
                if tlp_rules.rank(c.tlp) > tlp_rules.rank(r.max_tlp):
                    continue
                exists = await s.scalar(
                    select(AlertEvent.id).where(AlertEvent.rule_id == r.id, AlertEvent.dedup_key == c.key)
                )
                if exists:
                    continue
                ev = AlertEvent(
                    rule_id=r.id,
                    dedup_key=c.key[:300],
                    title=c.title[:300],
                    body={"lines": c.lines, "link": c.link},
                    tlp=c.tlp,
                    created_at=utcnow(),
                    delivered={},
                )
                s.add(ev)
                try:
                    async with s.begin_nested():
                        await s.flush()
                except IntegrityError:
                    continue  # another worker raised it first
                new_events.append(ev.id)
            r.cursor = {"since": _aware(newest).isoformat()}
        raised += len(new_events)
        if new_events:
            d, h = await deliver(sm, settings, rule.id, new_events)
            delivered += d
            held += h
    return {"rules": len(rules), "raised": raised, "delivered": delivered, "held": held}


async def _sent_last_hour(s: AsyncSession, integration_id: int, now: datetime) -> int:
    return int(
        await s.scalar(
            select(func.count())
            .select_from(IntegrationRun)
            .where(
                IntegrationRun.integration_id == integration_id,
                IntegrationRun.trigger == "alert",
                IntegrationRun.status == "success",
                IntegrationRun.started_at > now - timedelta(hours=1),
            )
        )
        or 0
    )


async def deliver(
    sm: async_sessionmaker[AsyncSession], settings: Settings, rule_id: int, event_ids: Sequence[int]
) -> tuple[int, int]:
    """Send events to the rule's channels; returns (messages sent, events held)."""
    base = settings.public_url.rstrip("/")
    async with sm() as s:
        rule = await s.get(AlertRule, rule_id)
        if rule is None:
            return 0, 0
        channels = (
            await s.scalars(
                select(Integration).where(
                    Integration.id.in_(rule.channels or []), Integration.enabled.is_(True)
                )
            )
        ).all()
        events = (
            await s.scalars(
                select(AlertEvent).where(AlertEvent.id.in_(list(event_ids))).order_by(AlertEvent.id)
            )
        ).all()
        rule_name = rule.name
        plan = []
        for ch in channels:
            secret = integrations.secrets_of(ch, settings)
            used = await _sent_last_hour(s, ch.id, utcnow())
            plan.append((ch.id, ch.kind, dict(ch.config), secret, ch.allow_internal, ch.max_tlp, used))
        evs = [
            (e.id, e.title, list((e.body or {}).get("lines") or []), (e.body or {}).get("link"), e.tlp)
            for e in events
        ]
    sent = held = 0
    status: dict[int, dict[str, str]] = {e[0]: {} for e in evs}
    for ch_id, kind, config, secret, internal, max_tlp, used in plan:
        backlog = 0
        async with sinks.http_for(internal, settings, retries=0) as http:
            for ev_id, title, lines, link, tlp in evs:
                if tlp == "TLP:RED" or tlp_rules.rank(tlp) > tlp_rules.rank(max_tlp):
                    status[ev_id][str(ch_id)] = "held: above this channel's TLP"
                    held += 1
                    continue
                if used >= settings.alert_max_per_hour:
                    status[ev_id][str(ch_id)] = "held: rate limit"
                    backlog += 1
                    held += 1
                    continue
                alert = sinks.Alert(title, lines, f"{base}/app{link}" if link else None, tlp, rule_name)
                ok, err = await _send(sm, ch_id, http, kind, config, secret, alert)
                status[ev_id][str(ch_id)] = "sent" if ok else f"failed: {err}"
                if ok:
                    sent += 1
                    used += 1
            if backlog:
                digest = sinks.Alert(
                    f"{backlog} more alert{'s' if backlog != 1 else ''} from rule {rule_name!r}",
                    ["Held back by the hourly limit; open Argus to see them."],
                    f"{base}/app/alerts",
                    "TLP:CLEAR",
                    rule_name,
                )
                await _send(sm, ch_id, http, kind, config, secret, digest)
    async with sm() as s, s.begin():
        for e in (await s.scalars(select(AlertEvent).where(AlertEvent.id.in_(list(event_ids))))).all():
            e.delivered = {**(e.delivered or {}), **status.get(e.id, {})}
    return sent, held


async def _send(
    sm: async_sessionmaker[AsyncSession],
    ch_id: int,
    http: Any,
    kind: str,
    config: dict[str, Any],
    secret: dict[str, Any],
    alert: sinks.Alert,
) -> tuple[bool, str | None]:
    err: str | None = None
    try:
        await sinks.send_alert(http, kind, config, secret, alert)
    except Exception as e:
        err = sinks._redact(e, *[str(v) for v in secret.values()])
    async with sm() as s, s.begin():
        now = utcnow()
        s.add(
            IntegrationRun(
                integration_id=ch_id,
                trigger="alert",
                started_at=now,
                finished_at=now,
                status="failed" if err else "success",
                sent=0 if err else 1,
                held_back=0,
                error=err,
                detail={"title": defang_text(alert.title)[:200]},
            )
        )
    return err is None, err


async def recent(s: AsyncSession, clearance: str, limit: int = 100) -> list[dict[str, Any]]:
    rows = (
        await s.execute(
            select(AlertEvent, AlertRule.name)
            .join(AlertRule, AlertRule.id == AlertEvent.rule_id)
            .where(AlertEvent.tlp.in_(tlp_rules.readable(clearance)))
            .order_by(AlertEvent.created_at.desc())
            .limit(limit)
        )
    ).all()
    return [
        {
            "id": e.id,
            "rule": name,
            "ruleId": e.rule_id,
            "title": defang_text(e.title),
            "lines": [defang_text(x) for x in (e.body or {}).get("lines", [])],
            "link": (e.body or {}).get("link"),
            "tlp": e.tlp,
            "createdAt": _iso(e.created_at),
            "delivered": e.delivered,
        }
        for e, name in rows
    ]
