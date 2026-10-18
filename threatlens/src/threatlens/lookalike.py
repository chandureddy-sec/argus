"""Brand and lookalike-domain monitoring (Phase 8, ADR 0021). Passive only.

For each domain in the org profile, dnstwist generates the permutations an
attacker might register: homoglyphs, typos, bitsquatting, TLD swaps, and
others. Two passive sources show which ones exist:

* **Certificate Transparency** (crt.sh): one query per brand keyword
  (``%example%``). Names that are a permutation, or that contain the keyword
  on a domain that isn't ours (combosquatting, e.g. ``example-login.com``),
  are candidates. Nothing is resolved or contacted.
* **Our own feeds**: phishing/malware domains and URLs already in the store
  whose registered domain is a permutation or contains the keyword.

Candidates are stored in ``lookalikes`` for an analyst to confirm (then block
or watch) or dismiss. New ones feed the ``lookalike`` alert rule and the
daily brief.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import tldextract
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from threatlens.ioc.extract import defang_text
from threatlens.models import AuditLog, Indicator, Lookalike
from threatlens.models import Observable as ObsRow
from threatlens.net.http import FetchError, SafeHttp
from threatlens.settings import Settings

CRT_URL = "https://crt.sh/"
MAX_CT_BYTES = 30 * 1024 * 1024
MAX_PER_DOMAIN = 500
# TLDs tried for tld-swap: the generic ones phishers favour, plus large ccTLDs.
SWAP_TLDS = (
    "com", "net", "org", "info", "biz", "co", "io", "app", "xyz", "top", "online", "site", "shop",
    "store", "live", "click", "link", "support", "help", "cc", "me", "us", "in", "co.in", "uk",
    "co.uk", "de", "ru", "cn", "br",
)  # fmt: skip
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)  # bundled snapshot: no fetch


@dataclass
class Candidate:
    domain: str  # the org domain it imitates
    candidate: str  # the registered lookalike domain
    fuzzer: str  # dnstwist technique, or "keyword" (combosquatting)
    evidence: list[dict[str, Any]] = field(default_factory=list)


def registered(name: str) -> str:
    e = _EXTRACT(name.strip().lower().rstrip(".").lstrip("*."))
    return f"{e.domain}.{e.suffix}" if e.domain and e.suffix else ""


def permutations(domain: str) -> dict[str, str]:
    """Permutation (registered domain) -> dnstwist technique, the domain itself excluded."""
    import dnstwist

    f = dnstwist.Fuzzer(domain, tld_dictionary=list(SWAP_TLDS))
    f.generate()
    out: dict[str, str] = {}
    for p in f.domains:
        d = str(p["domain"]).lower()
        if p["fuzzer"] != "*original" and d != domain:
            out.setdefault(registered(d) or d, str(p["fuzzer"]))
    return out


def keyword(domain: str) -> str:
    return _EXTRACT(domain).domain.lower()


def match(names: Iterable[str], domain: str, perms: dict[str, str], ours: set[str]) -> dict[str, str]:
    """Registered domains among ``names`` that imitate ``domain``: name -> technique."""
    kw = keyword(domain)
    out: dict[str, str] = {}
    for n in names:
        reg = registered(n)
        if not reg or reg in ours:
            continue
        if reg in perms:
            out.setdefault(reg, perms[reg])
        elif len(kw) >= 4 and kw in reg.split(".")[0]:
            out.setdefault(reg, "keyword")
    return out


async def ct_names(http: SafeHttp, kw: str) -> list[tuple[str, str]]:
    """(name, first seen) for certificates whose names contain ``kw`` (one crt.sh query)."""
    res = await http.get(CRT_URL, params={"q": f"%{kw}%", "output": "json"}, max_bytes=MAX_CT_BYTES)
    try:
        doc = json.loads(res.body or b"[]")
    except ValueError as e:
        raise FetchError(f"crt.sh answered with something that isn't JSON ({e})") from e
    out: list[tuple[str, str]] = []
    for row in doc if isinstance(doc, list) else []:
        if not isinstance(row, dict):
            continue
        for n in str(row.get("name_value", "")).splitlines():
            out.append((n, str(row.get("not_before") or row.get("entry_timestamp") or "")[:19]))
    return out


async def feed_names(s: AsyncSession, kw: str, perms: Iterable[str] = ()) -> list[tuple[str, int]]:
    """(domain or URL host, indicator id) in our store that is a permutation
    (exact domain) or mentions the keyword (domains and URLs)."""
    conds = [ObsRow.value.like(f"%{kw}%")] if len(kw) >= 4 else []
    rows: list[tuple[str, int]] = []
    names = sorted(set(perms))
    for i in range(0, len(names), 500):
        rows += [
            (str(v), int(n))
            for v, n in (
                await s.execute(
                    select(ObsRow.value, Indicator.id)
                    .join(Indicator, Indicator.observable_id == ObsRow.id)
                    .where(ObsRow.type == "domain-name", ObsRow.value.in_(names[i : i + 500]))
                )
            ).all()
        ]
    if conds:
        rows += [
            (str(v), int(n))
            for v, n in (
                await s.execute(
                    select(ObsRow.value, Indicator.id)
                    .join(Indicator, Indicator.observable_id == ObsRow.id)
                    .where(ObsRow.type.in_(("domain-name", "url")), *conds)
                    .limit(5000)
                )
            ).all()
        ]
    out = []
    for value, ind_id in rows:
        host = value.split("://", 1)[-1].split("/", 1)[0].split(":")[0] if "://" in value else value
        out.append((host, ind_id))
    return out


async def scan(
    sm: async_sessionmaker[AsyncSession],
    http: SafeHttp,
    domains: list[str],
    ours: set[str],
    *,
    use_ct: bool = True,
) -> dict[str, Any]:
    """Look for lookalikes of ``domains``; store new and updated candidates."""
    found: dict[str, Candidate] = {}
    errors: list[str] = []
    ct: dict[str, list[tuple[str, str]]] = {}
    for d in domains:
        d = d.lower()
        perms = permutations(d)
        kw = keyword(d)
        if use_ct and len(kw) >= 4:
            if kw not in ct:  # example.com and example.in share one query
                try:
                    ct[kw] = await ct_names(http, kw)
                except FetchError as e:
                    errors.append(f"crt.sh for {kw}: {str(e)[:160]}")
                    ct[kw] = []
            names = ct[kw]
            hits = match((n for n, _ in names), d, perms, ours)
            first: dict[str, str] = {}
            for n, when in names:
                r = registered(n)
                if r in hits and (r not in first or when < first[r]):
                    first[r] = when
            for reg, tech in list(hits.items())[:MAX_PER_DOMAIN]:
                c = found.setdefault(reg, Candidate(d, reg, tech))
                c.evidence.append({"source": "ct", "first_certificate": first.get(reg, "")})
        async with sm() as s:
            rows = await feed_names(s, kw, perms)
        hits = match((h for h, _ in rows), d, perms, ours)
        for host, ind_id in rows:
            reg = registered(host)
            if reg in hits:
                c = found.setdefault(reg, Candidate(d, reg, hits[reg]))
                if not any(e.get("indicator") == ind_id for e in c.evidence):
                    c.evidence.append({"source": "feed", "indicator": ind_id})
    new = 0
    now = datetime.now(UTC)
    async with sm() as s, s.begin():
        existing = {
            r.candidate: r
            for r in (await s.scalars(select(Lookalike).where(Lookalike.candidate.in_(list(found))))).all()
        }
        for reg, c in found.items():
            row = existing.get(reg)
            if row is None:
                s.add(
                    Lookalike(
                        domain=c.domain,
                        candidate=reg,
                        fuzzer=c.fuzzer,
                        first_seen=now,
                        last_seen=now,
                        evidence=c.evidence[:20],
                        status="new",
                    )
                )
                new += 1
            else:
                row.last_seen = now
                known = {json.dumps(e, sort_keys=True) for e in row.evidence or []}
                row.evidence = (row.evidence or []) + [
                    e for e in c.evidence if json.dumps(e, sort_keys=True) not in known
                ]
                row.evidence = row.evidence[:20]
        s.add(
            AuditLog(
                actor="worker",
                action="lookalike.scan",
                target=",".join(domains)[:500],
                details={"candidates": len(found), "new": new, "errors": errors[:5]},
            )
        )
    return {"domains": domains, "candidates": len(found), "new": new, "errors": errors}


def view(r: Lookalike) -> dict[str, Any]:
    def iso(v: datetime | None) -> str | None:
        return (v if v.tzinfo else v.replace(tzinfo=UTC)).isoformat() if v else None

    return {
        "id": r.id,
        "domain": r.domain,
        "candidate": defang_text(r.candidate),
        "fuzzer": r.fuzzer,
        "firstSeen": iso(r.first_seen),
        "lastSeen": iso(r.last_seen),
        "evidence": r.evidence,
        "status": r.status,
        "reviewedBy": r.reviewed_by,
        "reviewedAt": iso(r.reviewed_at),
    }


def org_domains(settings: Settings) -> tuple[list[str], set[str]]:
    """(domains to protect, every registered domain that is ours)."""
    from threatlens.profile import ProfileError, load_profile

    try:
        org = load_profile(settings.profile_path).org
    except (ProfileError, OSError):
        return [], set()
    doms = sorted({registered(d) or d.lower() for d in org.domains})
    return doms, set(doms)


async def recent(s: AsyncSession, status: str | None = None, limit: int = 200) -> list[Lookalike]:
    stmt = select(Lookalike)
    if status:
        stmt = stmt.where(Lookalike.status == status)
    return list(
        (await s.scalars(stmt.order_by(Lookalike.first_seen.desc(), Lookalike.id.desc()).limit(limit))).all()
    )
