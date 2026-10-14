"""Verify an indicator, and act on the verdict (step 2 of the response work).

* How each provider's answer is presented: a headline (the one line an
  analyst reads first) and the fields worth showing, per enricher.
* Second-opinion links to public portals, offered only when the value's TLP
  allows sending it there: a click is a disclosure, the same rule as the
  enrichers (portals that publish what is searched need TLP:CLEAR).
* Flag malicious / not malicious. On a value we already hold this is the
  analyst TP/FP feedback of ADR 0008. "Malicious" on a value we have never
  seen records it as an *analyst-submitted* indicator (label
  ``analyst-submitted``, no feed sighting) and scores it from the analyst
  signal, so it shows up in lists, lookups and the blocklist's known-bad rule.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import quote

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from threatlens import tlp as tlp_rules
from threatlens.collect import stix_pattern
from threatlens.ioc.defang import defang
from threatlens.ioc.normalize import guess
from threatlens.ioc.types import IOCType, Observable
from threatlens.kb.ids import indicator_stix_id
from threatlens.models import AuditLog, Indicator
from threatlens.models import Observable as ObsRow
from threatlens.scoring.feedback import WeightChange, give_feedback
from threatlens.settings import Settings

LOOKUP_TYPES = frozenset({
    IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN, IOCType.URL, IOCType.EMAIL,
    IOCType.MD5, IOCType.SHA1, IOCType.SHA256,
})  # fmt: skip
ANALYST_LABEL = "analyst-submitted"

Fmt = Callable[[Any], "str | list[str]"]


def _date(v: Any) -> str:
    """ISO date or timestamp → '2 Jun 2024' (or '13 Sep 2026, 17:38 UTC' when the time matters)."""
    try:
        dt = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        return str(v)
    day = f"{dt.day} {dt:%b %Y}"
    has_time = isinstance(v, str) and "T" in v and (dt.hour, dt.minute) != (0, 0)
    return f"{day}, {dt:%H:%M} UTC" if has_time else day


def _days(v: Any) -> str:
    """Days → '2 years 4 months', '3 months', '12 days'."""
    d = int(v)
    if d < 60:
        return f"{d} day{'s' if d != 1 else ''}"
    years, months = d // 365, (d % 365) // 30
    if not years:
        return f"{months} months"
    return f"{years} year{'s' if years != 1 else ''}" + (
        f" {months} month{'s' if months != 1 else ''}" if months else ""
    )


def _num(v: Any) -> str:
    return f"{int(v):,}" if isinstance(v, int | float) and not isinstance(v, bool) else str(v)


def _size(v: Any) -> str:
    n = float(v)
    for unit in ("bytes", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:,.0f} {unit}" if unit == "bytes" else f"{n:,.1f} {unit}"
        n /= 1024
    return str(v)


def _issuers(v: Any) -> list[str]:
    return [f"{name} ({n})" for name, n in v.items()] if isinstance(v, dict) else [str(v)]


def _pct(v: Any) -> str:
    return f"{int(v)} / 100"


# (label, summary key, formatter or None) per provider, in display order; empty values are skipped.
FIELDS: dict[str, list[tuple[str, str, Fmt | None]]] = {
    "virustotal": [("Flagged by", "malicious", lambda v: f"{v} engines"), ("Suspicious", "suspicious", None),
                   ("Engines asked", "engines", None), ("Community score", "reputation", None),
                   ("Network owner", "as_owner", None), ("Country", "country", None),
                   ("Threat label", "threat_label", None), ("Last analysed", "last_analysis", _date),
                   ("Tags", "tags", None)],
    "abuseipdb": [("Abuse confidence", "abuse_confidence", _pct), ("Reports", "total_reports", _num),
                  ("Reported by", "distinct_reporters", lambda v: f"{_num(v)} users"),
                  ("Last reported", "last_reported_at", _date), ("Used by", "usage_type", None),
                  ("ISP", "isp", None), ("Domain", "domain", None), ("Country", "country", None),
                  ("Tor exit node", "is_tor", None), ("Host names", "hostnames", None)],
    "greynoise": [("Classification", "classification", lambda v: str(v).capitalize()), ("Name", "name", None),
                  ("Scans the internet", "noise", None), ("Known business service", "riot", None),
                  ("Last seen", "last_seen", _date), ("Note", "message", None)],
    "rdap": [("Domain", "domain", None), ("Registrar", "registrar", None), ("Registrant", "registrant", None),
             ("Registered", "created", _date), ("Age", "age_days", _days), ("Expires", "expires", _date),
             ("Last changed", "updated", _date), ("Name servers", "nameservers", None),
             ("Network name", "name", None), ("Network", "cidrs", None), ("Address range", "range", None),
             ("Organisation", "organization", None), ("Country", "country", None),
             ("Abuse contact", "abuse_email", None), ("Registry status", "status", None)],
    "ripestat": [("Network (ASN)", "asn", lambda v: f"AS{v}"), ("Network owner", "as_holder", None),
                 ("Routed prefix", "prefix", None), ("Announced on the internet", "announced", None),
                 ("City", "city", None), ("Country", "country", None)],
    "dns": [("Addresses (A)", "a", None), ("IPv6 addresses (AAAA)", "aaaa", None),
            ("Alias of (CNAME)", "cname", None), ("Mail servers (MX)", "mx", None),
            ("Name servers (NS)", "ns", None), ("Text records (TXT)", "txt", None)],
    "urlscan": [("Public scans", "total", _num), ("Tags", "tags", None)],
    "malwarebazaar": [("Malware family", "signature", None), ("File name", "file_name", None),
                      ("File type", "file_type", None), ("Size", "file_size", _size),
                      ("First seen", "first_seen", _date), ("Last seen", "last_seen", _date),
                      ("SHA-256", "sha256", None), ("Tags", "tags", None)],
    "crtsh": [("Certificates", "certificates", _num), ("First issued", "first_issued", _date),
              ("Latest issued", "latest_issued", _date), ("Issued by", "issuers", _issuers),
              ("Names covered", "names", None)],
}  # fmt: skip
CARD_TITLE = {
    "rdap": "WHOIS registration", "ripestat": "Network & location", "dns": "DNS records",
    "crtsh": "Certificates (crt.sh)", "urlscan": "urlscan.io scans", "greynoise": "GreyNoise",
    "virustotal": "VirusTotal", "abuseipdb": "AbuseIPDB", "malwarebazaar": "MalwareBazaar",
}  # fmt: skip
HIDDEN = frozenset(
    {"latitude", "longitude", "link", "more", "raw", "names_total", "found", "scans", "latest"}
)


VERDICT = {
    "malicious": "Malicious",
    "suspicious": "Suspicious",
    "unknown": "No known threat",
    "benign": "Clean",
}
TYPE = {
    "ipv4-addr": "IPv4 address", "ipv6-addr": "IPv6 address", "domain-name": "Domain", "url": "URL",
    "email-addr": "Email address", "file-md5": "MD5 hash", "file-sha1": "SHA-1 hash",
    "file-sha256": "SHA-256 hash",
}  # fmt: skip
ACTION = {
    "block": "Block",
    "investigate": "Investigate",
    "monitor": "Monitor",
    "no_action": "No action needed",
}
NOT_FOUND = {
    "virustotal": "VirusTotal has never seen it",
    "greynoise": "Not seen scanning the internet",
    "malwarebazaar": "Not a known malware sample",
    "rdap": "No registration record found",
    "urlscan": "Nobody has scanned it publicly",
    "dns": "The domain doesn't resolve",
    "crtsh": "No certificates were ever issued for it",
}


def fields(enricher: str, summary: dict[str, Any] | None) -> list[tuple[str, str | list[str]]]:
    """Display rows for one provider's summary: known fields first, in plain
    words and formats, then any other short value the provider returned.
    A list value is shown one item per line."""
    if not summary:
        return []
    spec = FIELDS.get(enricher, [])
    keys = {k for _, k, _ in spec}
    rows: list[tuple[str, str | list[str]]] = []
    for label, k, fmt in spec:
        v = summary.get(k)
        if v in (None, "", [], {}):
            continue
        try:
            rows.append((label, fmt(v) if fmt else _fmt(v)))
        except (TypeError, ValueError):
            rows.append((label, _fmt(v)))
    for k, v in summary.items():
        short = isinstance(v, str | int | float | bool) and v not in ("", None)
        names = isinstance(v, list) and bool(v) and all(isinstance(x, str) for x in v)
        if k not in keys and k not in HIDDEN and (short or names) and len(rows) < 16:
            rows.append((k.replace("_", " ").capitalize(), _fmt(v)))
    return rows


def _fmt(v: Any) -> str | list[str]:
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, list):
        items = [str(x) for x in v[:10]]
        return items + ([f"and {len(v) - 10} more"] if len(v) > 10 else [])
    if isinstance(v, int | float):
        return _num(v)
    if isinstance(v, str) and len(v) >= 10 and v[4:5] == "-" and v[7:8] == "-":
        return _date(v)
    return str(v)


def headline(e: dict[str, Any]) -> tuple[str, str]:
    """(sentence, tone) summarising one provider's answer in plain words;
    tone is one of mal | sus | ok | info | off."""
    st = e.get("status")
    if st == "skipped":
        return _skip_text(e), "off"
    if st == "error" and not e.get("summary"):
        return f"Couldn't get an answer: {e.get('error') or 'unknown error'}", "off"
    s = e.get("summary") or {}
    name = e.get("enricher")
    if st == "not_found" or e.get("found") is False:
        return NOT_FOUND.get(name or "", "Nothing found"), "info"
    if name == "virustotal" and s.get("engines"):
        mal, sus = int(s.get("malicious") or 0), int(s.get("suspicious") or 0)
        if not mal and not sus:
            return f"None of {s['engines']} security engines flag it", "ok"
        tone = "mal" if mal >= 3 else "sus"
        return f"{mal} of {s['engines']} security engines flag it" + (
            f" ({sus} more suspicious)" if sus else ""
        ), tone
    if name == "abuseipdb" and s.get("abuse_confidence") is not None:
        c, n = int(s["abuse_confidence"]), int(s.get("total_reports") or 0)
        if not n:
            return "No abuse reports", "ok"
        return (f"Abuse confidence {c}/100 from {n:,} report{'s' if n != 1 else ''}",
                "mal" if c >= 75 else "sus" if c >= 25 else "ok")  # fmt: skip
    if name == "greynoise":
        if s.get("riot"):
            return f"Known business service{': ' + s['name'] if s.get('name') else ''}", "ok"
        cls = s.get("classification") or "unknown"
        return f"Scanning the internet, classified {cls}", "mal" if cls == "malicious" else "info"
    if name == "malwarebazaar" and s.get("sha256"):
        return f"Known malware sample: {s.get('signature') or 'family not attributed'}", "mal"
    if name == "ripestat":
        where = ", ".join(str(x) for x in (s.get("city"), s.get("country")) if x) or "location unknown"
        owner = s.get("as_holder") or (f"AS{s['asn']}" if s.get("asn") else None)
        return (f"{owner}, {where}" if owner else where), "info"
    if name == "rdap":
        if s.get("registrar"):
            if s.get("created"):
                age = s.get("age_days")
                ago = f" ({_days(age)} ago)" if age is not None else ""
                young = age is not None and age < 30
                return (
                    f"Registered {_date(str(s['created'])[:10])}{ago} via {s['registrar']}",
                    "sus" if young else "info",
                )
            return f"Registered via {s['registrar']}", "info"
        return f"{s.get('organization') or s.get('name') or 'Network'}", "info"
    if name == "dns":
        addrs = [*(s.get("a") or []), *(s.get("aaaa") or [])]
        if addrs:
            more = f" and {len(addrs) - 1} more" if len(addrs) > 1 else ""
            return f"Resolves to {addrs[0]}{more}", "info"
    if name == "crtsh" and s.get("certificates") is not None:
        n, names = int(s["certificates"]), int(s.get("names_total") or len(s.get("names") or []))
        since = f" since {_date(s['first_issued'])}" if s.get("first_issued") else ""
        return (
            f"{n:,} certificate{'s' if n != 1 else ''}{since}, for {names} name{'s' if names != 1 else ''}",
            "info",
        )
    kinds = {ev.get("kind") for ev in e.get("evidence") or []}
    tone = "mal" if "malicious" in kinds else "sus" if "suspicious" in kinds else "info"
    first = next((ev.get("text") for ev in e.get("evidence") or []), None)
    return (first or "Answered"), tone


def _skip_text(e: dict[str, Any]) -> str:
    reason = e.get("skipped_reason")
    title = CARD_TITLE.get(e.get("enricher") or "", e.get("title") or "This provider")
    return {
        "no_api_key": f"Not set up: {title} needs a free API key in .env",
        "tlp": f"Not asked: {title} shares what is searched with others. Choose TLP:CLEAR to include it.",
        "quota_exhausted": f"Daily quota used up; it resets in {e.get('resets_in_s') or '?'} s",
        "budget_exhausted": "Not asked: this check's call budget ran out",
        "disabled": "Switched off in the Feed catalog",
        "active_not_requested": "Not run: this check contacts the target directly",
        "not_requested": "Not asked: showing our own intel and saved answers only",
    }.get(reason or "", f"Not asked ({reason})")


def summary_line(r: dict[str, Any]) -> str:
    """'Checked in 5.2 s · 6 of 8 sources answered · not asked: VirusTotal (TLP)'."""
    es = r.get("enrichments") or []
    answered = [e for e in es if e.get("status") in ("ok", "cached", "not_found")]
    skipped = [e for e in es if e.get("status") == "skipped"]
    failed = [e for e in es if e.get("status") in ("error", "stale")]
    parts = [
        f"Checked in {r.get('took_ms', 0) / 1000:.1f} s",
        f"{len(answered)} of {len(es)} sources answered",
    ]
    if failed:
        parts.append(
            "no answer from " + ", ".join(CARD_TITLE.get(e["enricher"], e["enricher"]) for e in failed)
        )
    if skipped:
        parts.append(f"{len(skipped)} not asked")
    return " · ".join(parts)


@dataclass(frozen=True)
class Link:
    title: str
    url: str


def second_opinion(type_: str, value: str, tlp: str) -> list[Link]:
    """Public portals to open in a new tab, filtered by what the marking allows."""
    q = quote(value, safe="")
    third = tlp_rules.sink_allows("enricher:third_party", tlp)
    public = tlp_rules.sink_allows("enricher:disclosing", tlp)
    links: list[tuple[str, str, bool]] = []
    if type_ in ("ipv4-addr", "ipv6-addr"):
        links = [
            ("VirusTotal", f"https://www.virustotal.com/gui/ip-address/{q}", public),
            ("AbuseIPDB", f"https://www.abuseipdb.com/check/{q}", third),
            ("Shodan", f"https://www.shodan.io/host/{q}", third),
            ("GreyNoise", f"https://viz.greynoise.io/ip/{q}", third),
            ("Censys", f"https://search.censys.io/hosts/{q}", third),
        ]
    elif type_ == "domain-name":
        links = [
            ("VirusTotal", f"https://www.virustotal.com/gui/domain/{q}", public),
            ("urlscan.io", f"https://urlscan.io/domain/{q}", public),
            ("crt.sh", f"https://crt.sh/?q={q}", third),
        ]
    elif type_ in ("file-md5", "file-sha1", "file-sha256"):
        links = [
            ("VirusTotal", f"https://www.virustotal.com/gui/file/{q}", public),
            ("MalwareBazaar", f"https://bazaar.abuse.ch/browse.php?search=hash%3A{q}", third),
        ]
    elif type_ == "url":
        links = [("VirusTotal", f"https://www.virustotal.com/gui/search/{q}", public)]
    return [Link(t, u) for t, u, ok in links if ok]


# ── flag malicious / not malicious ───────────────────────────────────────────


class FlagError(ValueError):
    """A flag request that can't be honoured (shown to the user)."""


@dataclass
class Flagged:
    value: str
    indicator_id: int
    created: bool
    changes: list[WeightChange]


def parse(raw: str) -> Observable:
    r = guess(raw.strip()[:2000])
    if not isinstance(r, Observable):
        raise FlagError(f"{raw.strip()[:80]!r} is not an IP, domain, URL, email or file hash ({r.reason})")
    if r.type not in LOOKUP_TYPES:
        raise FlagError(f"a {r.type.value} can't be flagged here")
    return r


async def _visible_indicator(s: AsyncSession, obs: Observable, clearance: str) -> Indicator | None:
    return await s.scalar(
        select(Indicator)
        .join(ObsRow, ObsRow.id == Indicator.observable_id)
        .where(ObsRow.canonical_key == obs.key, Indicator.tlp.in_(tlp_rules.readable(clearance)))
    )


async def _submit(s: AsyncSession, obs: Observable, *, actor: str, tlp: str) -> tuple[Indicator, bool]:
    """The indicator for an analyst-submitted value (made if missing)."""
    now = datetime.now(UTC)
    row = await s.scalar(select(ObsRow).where(ObsRow.canonical_key == obs.key))
    if row is None:
        row = ObsRow(
            type=obs.type.value, value=obs.value, canonical_key=obs.key, defanged=defang(obs.value, obs.type),
            first_seen=now, last_seen=now, sightings_count=0,
        )  # fmt: skip
        s.add(row)
        await s.flush()
    ind = await s.scalar(select(Indicator).where(Indicator.observable_id == row.id))
    if ind is not None:
        return ind, False
    ind = Indicator(
        observable_id=row.id, stix_id=indicator_stix_id(obs.key), pattern=stix_pattern(obs), valid_from=now,
        confidence=80, tlp=tlp, status="active", labels=[ANALYST_LABEL], created_at=now, updated_at=now,
    )  # fmt: skip
    s.add(ind)
    await s.flush()
    s.add(AuditLog(actor=actor[:100], action="indicator.submit", target=f"indicator:{ind.id}",
                   details={"value": defang(obs.value, obs.type), "tlp": tlp}))  # fmt: skip
    return ind, True


async def flag(
    sm: async_sessionmaker[AsyncSession],
    settings: Settings,
    raw: str,
    verdict: Literal["tp", "fp"],
    *,
    actor: str,
    clearance: str,
    tlp: str = "TLP:CLEAR",
    note: str = "",
) -> Flagged:
    """Record an analyst's malicious (tp) / not malicious (fp) decision."""
    obs = parse(raw)
    tlp = tlp_rules.normalize(tlp)
    if not tlp_rules.may_read(clearance, tlp):
        raise FlagError(f"you can't mark something {tlp}: your clearance is {clearance}")
    async with sm() as s, s.begin():
        ind = await _visible_indicator(s, obs, clearance)
        created = False
        if ind is None:
            if verdict == "fp":
                raise FlagError(
                    f"{defang(obs.value, obs.type)} isn't in our intel: nothing to mark not malicious"
                )
            if await s.scalar(select(Indicator.id).join(ObsRow).where(ObsRow.canonical_key == obs.key)):
                raise FlagError("an indicator for this value exists above your clearance")
            ind, created = await _submit(s, obs, actor=actor, tlp=tlp)
        ind_id = ind.id
    changes = await give_feedback(sm, settings, ind_id, verdict, actor=actor, note=note.strip()[:500])
    return Flagged(defang(obs.value, obs.type), ind_id, created, changes)
