"""Blocklist and feed export (ADR 0010).

ThreatLens has no agents on endpoints: "block" means *publish*. A block puts a
value on a managed list; firewalls, EDRs and other tools pull the enforced part
of that list from a token-protected feed URL (plain text for an External
Dynamic List, CSV, JSON or a STIX 2.1 bundle).

* **Two modes.** A new block is ``monitor``: recorded only, a dry run that
  nothing pulls. ``enforce`` entries are published. Promoting needs a request
  and an approval by a *different* admin (four eyes; switchable in Settings).
* **Every block expires.** Known-bad values (an active indicator at or above
  the known-bad score) get the long duration, values typed in by hand the
  manual one, everything else the short "suspect" one. Lifting ends a block
  early; rows are never deleted, so the history stays readable.
* **Never-block guard, checked twice** (when a block is made and again on
  every export): non-global addresses (private, loopback, CGNAT, link-local,
  documentation…), public DNS resolvers, our own assets (ReconX), every
  allowlist entry (our domains and ranges, popular domains, CDN edges, manual
  "never block" entries) and ranges broader than /16 (IPv4) or /32 (IPv6).
* **TLP**: a block carries its indicator's marking; the export only includes
  blocks at or below the export limit (default TLP:AMBER+STRICT: a firewall is
  inside the organisation, but TLP:RED never leaves for a device).
* Every change is audited (``block.*``, ``feed_token.*``, ``settings.update``).
"""

from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
import secrets
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from threatlens import tlp as tlp_rules
from threatlens.allowlist import Allowlist, Entry
from threatlens.ioc.defang import refang
from threatlens.ioc.normalize import guess
from threatlens.ioc.types import IOCType, Observable
from threatlens.models import AllowlistEntry, AppSetting, Asset, AuditLog, Block, FeedToken, Indicator
from threatlens.models import Observable as ObsRow

POLICY_KEY = "blocking"
POLICY_DEFAULTS: dict[str, Any] = {
    "known_bad_days": 30,
    "suspect_days": 6,
    "manual_days": 30,
    "known_bad_score": 60,
    "require_second_approver": True,
    "export_max_tlp": "TLP:AMBER+STRICT",
}
EXPORT_TLPS = ("TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT")
PUBLIC_RESOLVERS = frozenset({
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220", "2606:4700:4700::1111", "2606:4700:4700::1001",
    "2001:4860:4860::8888", "2001:4860:4860::8844", "2620:fe::fe",
})  # fmt: skip
MIN_PREFIX = {4: 16, 6: 32}
MAX_NOTE = 500
KIND_OF = {
    IOCType.IPV4: "ip",
    IOCType.IPV6: "ip",
    IOCType.IPV4_NET: "cidr",
    IOCType.IPV6_NET: "cidr",
    IOCType.DOMAIN: "domain",
    IOCType.URL: "url",
}
View = Literal["live", "enforce", "monitor", "pending", "expired", "lifted", "all"]
VIEWS: tuple[View, ...] = ("live", "enforce", "monitor", "pending", "expired", "lifted", "all")


class BlockError(ValueError):
    """A block request that can't be honoured (the message is shown to the user)."""


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(dt: datetime | None) -> datetime | None:
    return dt.replace(tzinfo=UTC) if dt is not None and dt.tzinfo is None else dt


def is_live(b: Block, now: datetime | None = None) -> bool:
    exp = _aware(b.expires_at)
    return b.lifted_at is None and exp is not None and exp > (now or _now())


def state(b: Block, now: datetime | None = None) -> str:
    """lifted | expired | pending (monitor, enforce asked) | enforce | monitor."""
    if b.lifted_at is not None:
        return "lifted"
    if not is_live(b, now):
        return "expired"
    if b.mode == "monitor" and b.requested_by:
        return "pending"
    return b.mode


# ── policy ───────────────────────────────────────────────────────────────────


async def get_policy(s: AsyncSession) -> dict[str, Any]:
    row = await s.get(AppSetting, POLICY_KEY)
    return {**POLICY_DEFAULTS, **(row.value if row else {})}


def check_policy(p: dict[str, Any]) -> dict[str, Any]:
    out = {**POLICY_DEFAULTS}
    for k in ("known_bad_days", "suspect_days", "manual_days"):
        v = int(p.get(k, out[k]))
        if not 1 <= v <= 365:
            raise BlockError("block durations must be between 1 and 365 days")
        out[k] = v
    score = float(p.get("known_bad_score", out["known_bad_score"]))
    if not 0 <= score <= 100:
        raise BlockError("the known-bad score must be between 0 and 100")
    out["known_bad_score"] = score
    out["require_second_approver"] = bool(p.get("require_second_approver", True))
    lv = str(p.get("export_max_tlp", out["export_max_tlp"]))
    if lv not in EXPORT_TLPS:
        raise BlockError(f"the export limit must be one of {', '.join(EXPORT_TLPS)} (TLP:RED never leaves)")
    out["export_max_tlp"] = lv
    return out


async def set_policy(s: AsyncSession, changes: dict[str, Any], *, actor: str) -> dict[str, Any]:
    before = await get_policy(s)
    after = check_policy({**before, **changes})
    row = await s.get(AppSetting, POLICY_KEY)
    if row is None:
        s.add(AppSetting(key=POLICY_KEY, value=after, updated_by=actor[:100], updated_at=_now()))
    else:
        row.value, row.updated_by, row.updated_at = after, actor[:100], _now()
    diff = {k: [before[k], after[k]] for k in after if before.get(k) != after[k]}
    if diff:
        s.add(
            AuditLog(
                actor=actor[:100], action="settings.update", target=f"settings:{POLICY_KEY}", details=diff
            )
        )
    return after


# ── what may be blocked ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class Target:
    kind: str
    value: str
    obs: Observable

    @property
    def key(self) -> str:
        return self.obs.key


def parse_target(raw: str) -> Target:
    text = raw.strip()
    if not text:
        raise BlockError("enter an IP, a CIDR range, a domain or a URL")
    r = guess(text[:2000])
    if not isinstance(r, Observable):
        if r.reason.startswith("non-public"):  # the normalizer already refuses private and reserved space
            raise BlockError(f"{text[:80]} is never blocked: a private or reserved address")
        raise BlockError(f"{text[:80]!r} is not a valid IP, range, domain or URL ({r.reason})")
    kind = KIND_OF.get(r.type)
    if kind is None:
        raise BlockError(f"only IPs, CIDR ranges, domains and URLs can be blocked, not a {r.type.value}")
    return Target(kind, r.value, r)


def _url_host(url: str) -> str:
    rest = url.split("://", 1)[1]
    host = rest.split("/", 1)[0].split("?", 1)[0].rsplit("@", 1)[-1]
    if host.startswith("["):
        return host[1:].split("]", 1)[0]
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


class Guard:
    """The never-block rules, loaded once per request or export."""

    def __init__(self, allow: Allowlist, assets: Sequence[tuple[str, str, str]]) -> None:
        self.allow = allow
        self.own_ips: dict[ipaddress.IPv4Address | ipaddress.IPv6Address, str] = {}
        self.own_names: dict[str, str] = {}
        for kind, value, target in assets:
            label = f"our asset (ReconX scan of {target})"
            if kind == "ip":
                try:
                    self.own_ips[ipaddress.ip_address(value)] = label
                except ValueError:
                    continue
            else:
                self.own_names[value.lower().rstrip(".")] = label

    def _ip(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
        if not ip.is_global:
            return "a private or reserved address"
        if str(ip) in PUBLIC_RESOLVERS:
            return "a public DNS resolver"
        return self.own_ips.get(ip)

    def _name(self, name: str) -> str | None:
        name = name.lower().rstrip(".")
        for own, label in self.own_names.items():
            if own == name or own.endswith("." + name):
                return label if own == name else f"it contains {own}, {label}"
        return None

    def why(self, t: Target) -> str | None:
        """Why this target must never be blocked, or None."""
        if t.kind == "ip":
            if reason := self._ip(ipaddress.ip_address(t.value)):
                return reason
        elif t.kind == "cidr":
            net = ipaddress.ip_network(t.value, strict=False)
            if net.prefixlen < MIN_PREFIX[net.version]:
                return f"the range is broader than /{MIN_PREFIX[net.version]}"
            for edge in (net.network_address, net.broadcast_address):
                if reason := self._ip(edge):
                    return f"it reaches {edge}, {reason}"
            for r in PUBLIC_RESOLVERS:
                if ipaddress.ip_address(r) in net:
                    return f"it contains {r}, a public DNS resolver"
            for ip, label in self.own_ips.items():
                if ip.version == net.version and ip in net:
                    return f"it contains {ip}, {label}"
        elif t.kind == "domain":
            if reason := self._name(t.value):
                return reason
        else:  # url: only our own hosts are off limits; a bad URL on a big site is still blockable
            host = _url_host(t.value)
            try:
                ip = ipaddress.ip_address(host)
            except ValueError:
                if reason := self._name(host):
                    return f"its host {host} is {reason}"
            else:
                if reason := self._ip(ip):
                    return f"its host is {reason}"
            v = self.allow.check(t.obs)
            return "; ".join(v.reasons) if v.suppressed else None
        v = self.allow.check(t.obs)
        return "; ".join(v.reasons) if v.effect else None


async def load_guard(s: AsyncSession) -> Guard:
    entries = (await s.scalars(select(AllowlistEntry))).all()
    allow = Allowlist(Entry(r.kind, r.value, r.effect, r.reason, r.origin) for r in entries)  # type: ignore[arg-type]
    assets = (await s.execute(select(Asset.kind, Asset.value, Asset.target))).all()
    return Guard(allow, [(str(k), str(v), str(t)) for k, v, t in assets])


# ── the block lifecycle ──────────────────────────────────────────────────────


def live_clause(now: datetime) -> Any:
    return and_(Block.lifted_at.is_(None), Block.expires_at > now)


async def live_block(s: AsyncSession, key: str, now: datetime | None = None) -> Block | None:
    return await s.scalar(
        select(Block).where(Block.canonical_key == key, live_clause(now or _now())).order_by(Block.id.desc())
    )


async def create_block(
    s: AsyncSession,
    raw: str,
    *,
    actor: str,
    clearance: str,
    origin: Literal["manual", "indicator", "lookup"] = "manual",
    note: str = "",
    guard: Guard | None = None,
    now: datetime | None = None,
) -> Block:
    """A new ``monitor`` block for one value. Raises BlockError when the value
    is invalid, protected, or already blocked."""
    now = now or _now()
    t = parse_target(raw)
    guard = guard or await load_guard(s)
    if reason := guard.why(t):
        raise BlockError(f"{t.value} is never blocked: {reason}")
    if existing := await live_block(s, t.key, now):
        raise BlockError(f"{t.value} is already blocked (#{existing.id}, {state(existing, now)})")
    policy = await get_policy(s)
    ind = await s.scalar(
        select(Indicator)
        .join(ObsRow, ObsRow.id == Indicator.observable_id)
        .where(ObsRow.canonical_key == t.key, Indicator.tlp.in_(tlp_rules.readable(clearance)))
    )  # an indicator above the actor's clearance is treated as unknown: nothing about it leaks
    score = ind.priority_score if ind is not None else None
    if ind is not None and ind.status == "active" and (score or 0) >= policy["known_bad_score"]:
        reason, days = "known_bad", policy["known_bad_days"]
    elif origin == "manual":
        reason, days = "manual", policy["manual_days"]
    else:
        reason, days = "suspect", policy["suspect_days"]
    b = Block(
        kind=t.kind, value=t.value, canonical_key=t.key, indicator_id=ind.id if ind else None,
        mode="monitor", reason=reason, score=score, tlp=ind.tlp if ind else "TLP:CLEAR",
        note=note.strip()[:MAX_NOTE], created_by=actor[:100], created_at=now,
        expires_at=now + timedelta(days=days), lift_note="",
    )  # fmt: skip
    s.add(b)
    await s.flush()
    details = {"value": t.value, "kind": t.kind, "reason": reason, "days": days, "origin": origin}
    s.add(AuditLog(actor=actor[:100], action="block.create", target=f"block:{b.id}", details=details))
    return b


async def get_block(s: AsyncSession, block_id: int, clearance: str) -> Block | None:
    b = await s.get(Block, block_id)
    return b if b is not None and tlp_rules.may_read(clearance, b.tlp) else None


def _audit(s: AsyncSession, actor: str, action: str, b: Block, **details: Any) -> None:
    s.add(
        AuditLog(
            actor=actor[:100], action=action, target=f"block:{b.id}", details={"value": b.value, **details}
        )
    )


def _must_be_live(b: Block, now: datetime) -> None:
    if not is_live(b, now):
        raise BlockError(f"block #{b.id} has {state(b, now)}; make a new one")


async def request_enforce(s: AsyncSession, b: Block, *, actor: str, is_admin: bool) -> Block:
    """Ask for a monitor block to be enforced. Without the four-eyes rule an
    admin's request takes effect at once."""
    now = _now()
    _must_be_live(b, now)
    if b.mode == "enforce":
        raise BlockError(f"block #{b.id} is already enforced")
    policy = await get_policy(s)
    if is_admin and not policy["require_second_approver"]:
        await _enforce(s, b, actor=actor, now=now)
        return b
    if b.requested_by:
        raise BlockError(f"enforcing block #{b.id} was already requested by {b.requested_by}")
    b.requested_by, b.requested_at = actor[:100], now
    _audit(s, actor, "block.request_enforce", b)
    return b


async def _enforce(s: AsyncSession, b: Block, *, actor: str, now: datetime) -> None:
    guard = await load_guard(s)
    if reason := guard.why(parse_target(b.value)):  # the never-block list may have grown since
        raise BlockError(f"{b.value} can't be enforced: it is never blocked ({reason})")
    b.mode, b.approved_by, b.approved_at = "enforce", actor[:100], now
    _audit(s, actor, "block.enforce", b, requested_by=b.requested_by)


async def approve(s: AsyncSession, b: Block, *, actor: str, is_admin: bool) -> Block:
    now = _now()
    _must_be_live(b, now)
    if not is_admin:
        raise BlockError("approving an enforce request needs the admin role")
    if b.mode == "enforce":
        raise BlockError(f"block #{b.id} is already enforced")
    if not b.requested_by:
        raise BlockError(f"nobody has asked to enforce block #{b.id}")
    policy = await get_policy(s)
    if policy["require_second_approver"] and b.requested_by == actor[:100]:
        raise BlockError("you can't approve your own request: another admin has to")
    _audit(s, actor, "block.approve", b, requested_by=b.requested_by)
    await _enforce(s, b, actor=actor, now=now)
    return b


async def decline(s: AsyncSession, b: Block, *, actor: str, is_admin: bool) -> Block:
    if not (is_admin or b.requested_by == actor[:100]):
        raise BlockError("only an admin or the requester can withdraw an enforce request")
    if not b.requested_by or b.mode == "enforce":
        raise BlockError(f"block #{b.id} has no pending enforce request")
    _audit(s, actor, "block.decline", b, requested_by=b.requested_by)
    b.requested_by, b.requested_at = None, None
    return b


async def lift(s: AsyncSession, b: Block, *, actor: str, note: str = "") -> Block:
    now = _now()
    _must_be_live(b, now)
    b.lifted_by, b.lifted_at, b.lift_note = actor[:100], now, note.strip()[:MAX_NOTE]
    _audit(s, actor, "block.lift", b, mode=b.mode)
    return b


async def extend(s: AsyncSession, b: Block, *, actor: str, days: int) -> Block:
    now = _now()
    _must_be_live(b, now)
    if not 1 <= days <= 365:
        raise BlockError("extend by 1 to 365 days")
    before = _aware(b.expires_at) or now
    b.expires_at = max(before, now) + timedelta(days=days)
    _audit(s, actor, "block.extend", b, days=days, expires_at=b.expires_at.isoformat())
    return b


def _view_clause(view: View, now: datetime) -> Any:
    live = live_clause(now)
    return {
        "live": live,
        "enforce": and_(live, Block.mode == "enforce"),
        "monitor": and_(live, Block.mode == "monitor", Block.requested_by.is_(None)),
        "pending": and_(live, Block.mode == "monitor", Block.requested_by.is_not(None)),
        "expired": and_(Block.lifted_at.is_(None), Block.expires_at <= now),
        "lifted": Block.lifted_at.is_not(None),
        "all": True,
    }[view]


async def list_blocks(
    s: AsyncSession,
    clearance: str,
    *,
    view: View = "live",
    q: str | None = None,
    limit: int = 50,
    offset: int = 0,
    now: datetime | None = None,
) -> tuple[list[Block], int]:
    now = now or _now()
    cond = [Block.tlp.in_(tlp_rules.readable(clearance)), _view_clause(view, now)]
    if q:
        q = refang(q.strip())  # a defanged search (203.0.113[.]5) finds the stored value
        like = "%" + q.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        cond.append(
            or_(
                func.lower(Block.value).like(like, escape="\\"),
                func.lower(Block.note).like(like, escape="\\"),
            )
        )
    total = int(await s.scalar(select(func.count()).select_from(Block).where(*cond)) or 0)
    rows = (
        await s.scalars(
            select(Block)
            .where(*cond)
            .order_by(Block.created_at.desc(), Block.id.desc())
            .limit(limit)
            .offset(offset)
        )
    ).all()
    return list(rows), total


async def counts(s: AsyncSession, clearance: str, now: datetime | None = None) -> dict[str, int]:
    now = now or _now()
    vis = Block.tlp.in_(tlp_rules.readable(clearance))
    out = {}
    for view in ("enforce", "monitor", "pending", "lifted"):
        out[view] = int(
            await s.scalar(select(func.count()).select_from(Block).where(vis, _view_clause(view, now))) or 0
        )
    out["expiring"] = int(
        await s.scalar(
            select(func.count())
            .select_from(Block)
            .where(vis, live_clause(now), Block.expires_at <= now + timedelta(hours=24))
        )
        or 0
    )
    return out


async def blocks_for(s: AsyncSession, keys: Sequence[str], now: datetime | None = None) -> dict[str, Block]:
    """The live block of each canonical key that has one."""
    if not keys:
        return {}
    rows = (
        await s.scalars(select(Block).where(Block.canonical_key.in_(list(keys)), live_clause(now or _now())))
    ).all()
    return {b.canonical_key: b for b in rows}


# ── feed tokens ──────────────────────────────────────────────────────────────

TOKEN_PREFIX = "tlf_"  # noqa: S105  # nosec B105  # a public marker, not a secret


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def create_token(s: AsyncSession, name: str, *, actor: str) -> tuple[FeedToken, str]:
    name = name.strip()
    if not 1 <= len(name) <= 64:
        raise BlockError("give the token a name of 1 to 64 characters (e.g. the firewall it is for)")
    if await s.scalar(select(FeedToken).where(FeedToken.name == name)):
        raise BlockError(f"a token named {name!r} already exists")
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    row = FeedToken(
        name=name, token_hash=_hash(token), prefix=token[:8], created_by=actor[:100], created_at=_now()
    )
    s.add(row)
    await s.flush()
    s.add(
        AuditLog(
            actor=actor[:100],
            action="feed_token.create",
            target=f"feed_token:{row.id}",
            details={"name": name},
        )
    )
    return row, token


async def revoke_token(s: AsyncSession, token_id: int, *, actor: str) -> FeedToken:
    row = await s.get(FeedToken, token_id)
    if row is None:
        raise BlockError("no such token")
    if row.revoked_at is None:
        row.revoked_at = _now()
        s.add(
            AuditLog(
                actor=actor[:100],
                action="feed_token.revoke",
                target=f"feed_token:{row.id}",
                details={"name": row.name},
            )
        )
    return row


async def check_token(s: AsyncSession, token: str) -> FeedToken | None:
    if not token.startswith(TOKEN_PREFIX) or len(token) > 100:
        return None
    row = await s.scalar(
        select(FeedToken).where(FeedToken.token_hash == _hash(token), FeedToken.revoked_at.is_(None))
    )
    if row is not None:
        last = _aware(row.last_used_at)
        if last is None or _now() - last > timedelta(minutes=1):
            row.last_used_at = _now()
    return row


# ── export ───────────────────────────────────────────────────────────────────

FORMATS: dict[str, str] = {
    "ip.txt": "text/plain; charset=utf-8",
    "domain.txt": "text/plain; charset=utf-8",
    "url.txt": "text/plain; charset=utf-8",
    "blocks.csv": "text/csv; charset=utf-8",
    "blocks.json": "application/json",
    "stix.json": "application/stix+json;version=2.1",
}
# STIX 2.1 spec §7.2.1.4 TLP marking definitions (TLP 1.0 names; CLEAR = WHITE).
STIX_TLP = {
    "TLP:CLEAR": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "TLP:GREEN": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "TLP:AMBER": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "TLP:AMBER+STRICT": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
}
_NS = uuid.UUID("6f4f2b8e-0d7e-4c55-9a51-3c1f1b4c2a10")


async def export_entries(s: AsyncSession, now: datetime | None = None) -> list[Block]:
    """Enforced, live blocks within the export TLP limit that still pass the
    never-block guard (the second check)."""
    now = now or _now()
    policy = await get_policy(s)
    levels = [lv for lv in EXPORT_TLPS if tlp_rules.rank(lv) <= tlp_rules.rank(policy["export_max_tlp"])]
    rows = (
        await s.scalars(
            select(Block)
            .where(_view_clause("enforce", now), Block.tlp.in_(levels))
            .order_by(Block.kind, Block.value)
        )
    ).all()
    guard = await load_guard(s)
    return [b for b in rows if guard.why(parse_target(b.value)) is None]


def _stix_pattern(b: Block) -> str:
    v = b.value.replace("\\", "\\\\").replace("'", "\\'")
    if b.kind in ("ip", "cidr"):
        version = ipaddress.ip_network(b.value, strict=False).version
        return f"[ipv{version}-addr:value = '{v}']"
    return f"[{'domain-name' if b.kind == 'domain' else 'url'}:value = '{v}']"


def _iso(dt: datetime | None) -> str | None:
    dt = _aware(dt)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z") if dt else None


def render(entries: Sequence[Block], fmt: str, now: datetime | None = None) -> str:
    """One export format. Plain-text lists hold bare values, one per line, the
    shape a firewall External Dynamic List expects (URLs without a scheme)."""
    now = now or _now()
    if fmt == "ip.txt":
        return "".join(f"{b.value}\n" for b in entries if b.kind in ("ip", "cidr"))
    if fmt == "domain.txt":
        return "".join(f"{b.value}\n" for b in entries if b.kind == "domain")
    if fmt == "url.txt":
        return "".join(f"{b.value.split('://', 1)[1]}\n" for b in entries if b.kind == "url")
    rows = [
        {"value": b.value, "kind": b.kind, "reason": b.reason, "score": b.score, "tlp": b.tlp,
         "blocked_at": _iso(b.created_at), "expires_at": _iso(b.expires_at), "approved_by": b.approved_by}
        for b in entries
    ]  # fmt: skip
    if fmt == "blocks.csv":
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=list(rows[0]) if rows else ["value"], lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
        return buf.getvalue()
    if fmt == "blocks.json":
        return json.dumps({"generated_at": _iso(now), "count": len(rows), "blocks": rows}, indent=1)
    if fmt == "stix.json":
        objects = [
            {
                "type": "indicator", "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid5(_NS, b.canonical_key)}",
                "created": _iso(b.created_at), "modified": _iso(b.approved_at or b.created_at),
                "name": f"Blocked {b.kind}: {b.value}", "indicator_types": ["malicious-activity"],
                "pattern": _stix_pattern(b), "pattern_type": "stix",
                "valid_from": _iso(b.created_at), "valid_until": _iso(b.expires_at),
                "object_marking_refs": [STIX_TLP[b.tlp]],
                **({"x_threatlens_tlp": b.tlp} if b.tlp == "TLP:AMBER+STRICT" else {}),
            }
            for b in entries
        ]  # fmt: skip
        return json.dumps({"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}, indent=1)
    raise BlockError(f"unknown export format {fmt!r}")
