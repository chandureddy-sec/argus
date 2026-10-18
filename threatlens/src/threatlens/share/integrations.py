"""Integrations an admin configures (ADR 0019): create, edit, test, and push
indicators to them on a schedule or on demand.

A push walks the shareable indicators (``share.select``, with this
integration's TLP cap, minimum score and types) changed since its cursor, in
(updated_at, id) order and in the destination's batch size, so a re-run never
resends what was delivered and a failure resumes where it stopped. Each push
is an ``integration_runs`` row; secrets are sealed with the vault and never
returned, logged or audited.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from threatlens import tlp as tlp_rules
from threatlens.models import TLP_LEVELS, AuditLog, Integration, IntegrationRun, utcnow
from threatlens.settings import Settings
from threatlens.share import select as sel
from threatlens.share import sinks, stix
from threatlens.vault import VaultError, seal, unseal

MAX_PER_RUN = 20_000
_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{1,62}$")
INDICATOR_TYPES = (
    "ipv4-addr",
    "ipv6-addr",
    "ipv4-net",
    "ipv6-net",
    "domain-name",
    "url",
    "email-addr",
    "file-md5",
    "file-sha1",
    "file-sha256",
)
IntegrationError = sinks.IntegrationError


@dataclass
class Form:
    name: str
    kind: str
    config: dict[str, Any]
    secret: dict[str, Any]
    enabled: bool = True
    allow_internal: bool = False
    min_score: float = 60.0
    max_tlp: str = "TLP:GREEN"
    types: Sequence[str] = ()
    interval_minutes: int = 60


def _check(f: Form) -> None:
    if not _NAME.match(f.name):
        raise IntegrationError("Name: 2-63 lower-case letters, digits, - or _")
    if f.kind not in sinks.KINDS:
        raise IntegrationError("unknown integration kind")
    if f.max_tlp not in TLP_LEVELS or f.max_tlp == "TLP:RED":
        raise IntegrationError(
            "Most restricted marking: CLEAR, GREEN, AMBER or AMBER+STRICT (RED never leaves)"
        )
    if not 0 <= f.min_score <= 100:
        raise IntegrationError("Minimum score: 0 to 100")
    if not 5 <= f.interval_minutes <= 10080:
        raise IntegrationError("Push every: 5 minutes to 7 days")
    bad = [t for t in f.types if t not in INDICATOR_TYPES]
    if bad:
        raise IntegrationError(f"Types: unknown {', '.join(bad)}")


def view(i: Integration) -> dict[str, Any]:
    spec = sinks.KINDS[i.kind]
    return {
        "id": i.id,
        "name": i.name,
        "kind": i.kind,
        "kindTitle": spec.title,
        "role": spec.role,
        "enabled": i.enabled,
        "config": i.config,
        "hasSecret": bool(i.secret),
        "allowInternal": i.allow_internal,
        "minScore": i.min_score,
        "maxTlp": i.max_tlp,
        "types": i.types,
        "intervalMinutes": i.interval_minutes,
        "lastRunAt": _iso(i.last_run_at),
        "lastStatus": i.last_status,
        "lastError": i.last_error,
        "cursor": (i.cursor or {}).get("after_at"),
    }


def _iso(v: datetime | None) -> str | None:
    return (v if v.tzinfo else v.replace(tzinfo=UTC)).isoformat() if v else None


def _audit(s: AsyncSession, actor: str, action: str, i: Integration, **details: Any) -> None:
    s.add(AuditLog(actor=actor[:100], action=action, target=f"integration:{i.name}", details=details))


async def create(s: AsyncSession, f: Form, *, actor: str, settings: Settings) -> Integration:
    _check(f)
    if await s.scalar(select(Integration).where(Integration.name == f.name)):
        raise IntegrationError(f"an integration named {f.name!r} already exists")
    config, secret = sinks.validate(f.kind, f.config, f.secret)
    now = utcnow()
    i = Integration(
        name=f.name,
        kind=f.kind,
        enabled=f.enabled,
        config=config,
        secret=seal(settings, json.dumps(secret)) if secret else None,
        allow_internal=f.allow_internal,
        min_score=f.min_score,
        max_tlp=f.max_tlp,
        types=list(f.types),
        interval_minutes=f.interval_minutes,
        cursor={},
        created_by=actor[:100],
        created_at=now,
        updated_at=now,
    )
    s.add(i)
    await s.flush()
    _audit(
        s,
        actor,
        "integration.create",
        i,
        kind=f.kind,
        config=config,
        secret_fields=sorted(secret),
        allow_internal=f.allow_internal,
        max_tlp=f.max_tlp,
        min_score=f.min_score,
    )
    return i


def secrets_of(i: Integration, settings: Settings) -> dict[str, Any]:
    if not i.secret:
        return {}
    try:
        data = json.loads(unseal(settings, i.secret))
    except (VaultError, ValueError) as e:
        raise IntegrationError(f"the stored secret can't be read ({e}); enter it again") from e
    return data if isinstance(data, dict) else {}


async def update(s: AsyncSession, i: Integration, f: Form, *, actor: str, settings: Settings) -> Integration:
    f.name = i.name  # names are identities: renaming would break audit trails
    f.kind = i.kind
    _check(f)
    config, fresh = sinks.validate(i.kind, f.config, f.secret, partial_secret=True)
    secret = {**secrets_of(i, settings), **fresh}
    sinks.validate(i.kind, config, secret)  # every required secret is now present
    scope_changed = (i.min_score, i.max_tlp, sorted(i.types)) != (f.min_score, f.max_tlp, sorted(f.types))
    i.enabled, i.config, i.allow_internal = f.enabled, config, f.allow_internal
    i.secret = seal(settings, json.dumps(secret)) if secret else None
    i.min_score, i.max_tlp, i.types, i.interval_minutes = (
        f.min_score,
        f.max_tlp,
        list(f.types),
        f.interval_minutes,
    )
    if scope_changed:
        i.cursor = {}  # a wider scope sends what the narrower one skipped
    i.updated_at = utcnow()
    _audit(
        s,
        actor,
        "integration.update",
        i,
        config=config,
        secret_fields_changed=sorted(fresh),
        allow_internal=f.allow_internal,
        max_tlp=f.max_tlp,
        min_score=f.min_score,
        resent=scope_changed,
    )
    return i


async def remove(s: AsyncSession, i: Integration, *, actor: str) -> None:
    _audit(s, actor, "integration.delete", i, kind=i.kind)
    await s.delete(i)


async def get(s: AsyncSession, ident: int | str) -> Integration | None:
    if isinstance(ident, int) or str(ident).isdigit():
        return await s.get(Integration, int(ident))
    return await s.scalar(select(Integration).where(Integration.name == str(ident)))


def _rules(i: Integration) -> sel.Rules:
    return sel.Rules(i.max_tlp, i.min_score, tuple(i.types), revocations=i.kind != "misp")


async def _finish(
    s: AsyncSession, i: Integration, run: IntegrationRun, status: str, error: str | None
) -> None:
    run.status, run.error, run.finished_at = status, error, utcnow()
    i.last_run_at, i.last_status, i.last_error = run.started_at, status, error


async def push(
    sm: async_sessionmaker[AsyncSession],
    settings: Settings,
    ident: int | str,
    *,
    trigger: str = "schedule",
    actor: str = "worker",
) -> dict[str, Any]:
    """Send everything shareable that changed since the cursor; returns the run summary."""
    async with sm() as s, s.begin():
        i = await get(s, ident)
        if i is None:
            raise IntegrationError("no such integration")
        spec = sinks.KINDS[i.kind]
        if spec.role == "alerts":
            raise IntegrationError(f"{spec.title} receives alerts, not indicators")
        run = IntegrationRun(
            integration_id=i.id,
            trigger=trigger,
            started_at=utcnow(),
            status="running",
            sent=0,
            held_back=0,
            detail={},
        )
        s.add(run)
        await s.flush()
        run_id, kind, config, rules = run.id, i.kind, dict(i.config), _rules(i)
        cur = i.cursor or {}
        after = (
            (datetime.fromisoformat(cur["after_at"]), int(cur["after_id"])) if cur.get("after_at") else None
        )
        try:
            secret = secrets_of(i, settings)
        except IntegrationError as e:
            await _finish(s, i, run, "failed", str(e))
            return {"run": run_id, "status": "failed", "sent": 0, "error": str(e)}
        if trigger == "manual":
            _audit(s, actor, "integration.push", i)
        allow_internal = i.allow_internal
    sent = held = 0
    error: str | None = None
    detail: dict[str, Any] = {}
    batch = spec.batch - (1 if kind == "sentinel" else 0)  # room for the producer identity
    producer = settings.org_identity
    async with sinks.http_for(allow_internal, settings, retries=0 if kind == "misp" else 1) as http:
        while sent + held < MAX_PER_RUN:
            async with sm() as s:
                rows = await sel.page(s, rules, after=after, limit=batch)
                objects: list[dict[str, Any]] = []
                if rows and kind == "sentinel":
                    ident_obj = stix.identity(producer)
                    objects = [ident_obj, *(stix.indicator(r, ident_obj["id"]) for r in rows)]
            if not rows:
                break
            try:
                res = await sinks.send_indicators(http, kind, config, secret, rows, objects, producer)
            except (sinks.IntegrationError, Exception) as e:
                error = sinks._redact(e, *[str(v) for v in secret.values()])
                break
            sent += res.sent
            held += res.held_back
            for k, v in res.detail.items():
                detail.setdefault(k, []).extend(v if isinstance(v, list) else [v])
            after = (rows[-1].ind.updated_at, rows[-1].ind.id)
            if len(rows) < batch:
                break
    async with sm() as s, s.begin():
        i = await get(s, ident)
        done = await s.get(IntegrationRun, run_id)
        if i is None or done is None:
            return {
                "run": run_id,
                "status": "failed",
                "sent": sent,
                "error": "integration removed during the run",
            }
        if after is not None:
            i.cursor = {"after_at": sel.aware(after[0]).isoformat(), "after_id": after[1]}
        done.sent, done.held_back, done.detail = sent, held, {k: v[:20] for k, v in detail.items()}
        status = "failed" if error and not sent else "partial" if error else "success"
        await _finish(s, i, done, status, error)
    return {"run": run_id, "status": status, "sent": sent, "heldBack": held, "error": error}


async def due(sm: async_sessionmaker[AsyncSession], now: datetime | None = None) -> list[int]:
    """Enabled indicator integrations whose interval has passed."""
    now = now or datetime.now(UTC)
    async with sm() as s:
        rows = (await s.scalars(select(Integration).where(Integration.enabled.is_(True)))).all()
    out = []
    for i in rows:
        if sinks.KINDS[i.kind].role == "alerts":
            continue
        last = i.last_run_at
        if (
            last is None
            or (last if last.tzinfo else last.replace(tzinfo=UTC)) + timedelta(minutes=i.interval_minutes)
            <= now
        ):
            out.append(i.id)
    return out


async def test(
    sm: async_sessionmaker[AsyncSession], settings: Settings, ident: int | str, *, actor: str
) -> str:
    async with sm() as s, s.begin():
        i = await get(s, ident)
        if i is None:
            raise IntegrationError("no such integration")
        kind, config, allow_internal = i.kind, dict(i.config), i.allow_internal
        secret = secrets_of(i, settings)
        run = IntegrationRun(
            integration_id=i.id,
            trigger="test",
            started_at=utcnow(),
            status="running",
            sent=0,
            held_back=0,
            detail={},
        )
        s.add(run)
        await s.flush()
        run_id = run.id
        _audit(s, actor, "integration.test", i)
    try:
        async with sinks.http_for(allow_internal, settings, retries=0) as http:
            msg = await sinks.test(http, kind, config, secret, settings.org_identity)
        status, error = "success", None
    except Exception as e:
        msg, status, error = "", "failed", sinks._redact(e, *[str(v) for v in secret.values()])
    async with sm() as s, s.begin():
        done = await s.get(IntegrationRun, run_id)
        if done is not None:
            done.status, done.error, done.finished_at, done.detail = status, error, utcnow(), {"result": msg}
    if error:
        raise IntegrationError(error)
    return msg


async def runs(s: AsyncSession, integration_id: int, limit: int = 20) -> list[dict[str, Any]]:
    rows = (
        await s.scalars(
            select(IntegrationRun)
            .where(IntegrationRun.integration_id == integration_id)
            .order_by(IntegrationRun.started_at.desc())
            .limit(limit)
        )
    ).all()
    return [
        {
            "id": r.id,
            "trigger": r.trigger,
            "startedAt": _iso(r.started_at),
            "finishedAt": _iso(r.finished_at),
            "status": r.status,
            "sent": r.sent,
            "heldBack": r.held_back,
            "error": r.error,
            "detail": r.detail,
        }
        for r in rows
    ]


def may_carry(i: Integration, tlp: str) -> bool:
    """Whether a message marked ``tlp`` may go to this destination."""
    return tlp != "TLP:RED" and tlp_rules.rank(tlp) <= tlp_rules.rank(i.max_tlp)
