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

# (label, summary key) per enricher, in display order; anything missing is skipped.
FIELDS: dict[str, list[tuple[str, str]]] = {
    "virustotal": [("Malicious", "malicious"), ("Suspicious", "suspicious"), ("Engines", "engines"),
                   ("Community score", "reputation"), ("AS owner", "as_owner"), ("Country", "country"),
                   ("Threat label", "threat_label"), ("Last analysed", "last_analysis"), ("Tags", "tags")],
    "abuseipdb": [("Abuse confidence", "abuse_confidence"), ("Reports", "total_reports"),
                  ("Reporters", "distinct_reporters"), ("Last reported", "last_reported_at"),
                  ("Usage", "usage_type"), ("ISP", "isp"), ("Domain", "domain"), ("Country", "country"),
                  ("Tor exit", "is_tor"), ("Hostnames", "hostnames")],
    "greynoise": [("Classification", "classification"), ("Name", "name"), ("Internet scanner", "noise"),
                  ("Known business service", "riot"), ("Last seen", "last_seen")],
    "rdap": [("Domain", "domain"), ("Registrar", "registrar"), ("Registrant", "registrant"),
             ("Created", "created"), ("Age (days)", "age_days"), ("Expires", "expires"),
             ("Name servers", "nameservers"), ("Netblock", "name"), ("CIDR", "cidrs"), ("Range", "range"),
             ("Organisation", "organization"), ("Country", "country"), ("Abuse contact", "abuse_email"),
             ("Status", "status")],
    "ripestat": [("ASN", "asn"), ("AS holder", "as_holder"), ("Prefix", "prefix"), ("Announced", "announced"),
                 ("City", "city"), ("Country", "country")],
    "urlscan": [("Public scans", "total"), ("Tags", "tags")],
    "malwarebazaar": [("Family", "signature"), ("File name", "file_name"), ("File type", "file_type"),
                      ("Size", "file_size"), ("First seen", "first_seen"), ("Last seen", "last_seen"),
                      ("SHA-256", "sha256"), ("Tags", "tags")],
    "crtsh": [("Certificates", "certificates"), ("First issued", "first_issued"),
              ("Latest issued", "latest_issued")],
}  # fmt: skip
CARD_TITLE = {"rdap": "WHOIS (RDAP)", "ripestat": "Network & geo", "dns": "DNS"}
HIDDEN = frozenset({"latitude", "longitude", "link", "more", "raw"})  # not worth a row


def fields(enricher: str, summary: dict[str, Any] | None) -> list[tuple[str, str]]:
    """Display rows for one provider's summary: known fields first, then any
    other short scalar the provider returned."""
    if not summary:
        return []
    spec = FIELDS.get(enricher, [])
    keys = {k for _, k in spec}
    rows = [(label, _fmt(summary.get(k))) for label, k in spec if summary.get(k) not in (None, "", [], {})]
    for k, v in summary.items():
        short = isinstance(v, str | int | float | bool) and v not in ("", None)
        names = isinstance(v, list) and bool(v) and all(isinstance(x, str) for x in v)
        if k not in keys and k not in HIDDEN and (short or names) and len(rows) < 14:
            rows.append((k.replace("_", " ").capitalize(), _fmt(v)))
    return rows


def _fmt(v: Any) -> str:
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, list):
        return ", ".join(str(x) for x in v[:12]) + (f" (+{len(v) - 12})" if len(v) > 12 else "")
    if isinstance(v, str) and len(v) >= 19 and v[4] == "-" and v[10] == "T":
        return v[:16].replace("T", " ")  # ISO timestamps: minutes are enough
    return str(v)


def headline(e: dict[str, Any]) -> tuple[str, str]:
    """(text, tone) summarising one provider's answer; tone is one of
    mal | sus | ok | info | off."""
    st = e.get("status")
    if st == "skipped":
        return _skip_text(e), "off"
    if st == "error" and not e.get("summary"):
        return f"Failed: {e.get('error') or 'unknown error'}", "off"
    s = e.get("summary") or {}
    name = e.get("enricher")
    if st == "not_found" or e.get("found") is False:
        return {"virustotal": "Not in VirusTotal", "greynoise": "Not seen scanning the internet",
                "malwarebazaar": "Not a known sample", "rdap": "No registration record",
                "urlscan": "No public scans"}.get(name or "", "Nothing found"), "info"  # fmt: skip
    if name == "virustotal" and s.get("engines"):
        mal, sus = int(s.get("malicious") or 0), int(s.get("suspicious") or 0)
        tone = "mal" if mal >= 3 else "sus" if mal or sus else "ok"
        return f"{mal}/{s['engines']} engines flag it" + (f", {sus} suspicious" if sus else ""), tone
    if name == "abuseipdb" and s.get("abuse_confidence") is not None:
        c = int(s["abuse_confidence"])
        return (f"Abuse confidence {c}/100 · {s.get('total_reports') or 0} reports",
                "mal" if c >= 75 else "sus" if c >= 25 else "ok")  # fmt: skip
    if name == "greynoise":
        cls = s.get("classification") or ("business service" if s.get("riot") else "unknown")
        return f"{cls.capitalize()}{' · ' + s['name'] if s.get('name') else ''}", (
            "mal" if cls == "malicious" else "ok" if cls == "benign" or s.get("riot") else "info"
        )
    if name == "malwarebazaar" and s.get("sha256"):
        return f"Known malware: {s.get('signature') or 'unattributed'}", "mal"
    if name == "ripestat":
        where = ", ".join(str(x) for x in (s.get("city"), s.get("country")) if x) or "location unknown"
        return (f"AS{s['asn']} {s.get('as_holder') or ''} · {where}" if s.get("asn") else where), "info"
    if name == "rdap":
        if s.get("registrar"):
            age = f", {s['age_days']} days old" if s.get("age_days") is not None else ""
            return f"Registered via {s['registrar']}{age}", "sus" if (
                s.get("age_days") or 9999
            ) < 30 else "info"
        return f"{s.get('name') or 'Network'} · {s.get('organization') or 'organisation not given'}", "info"
    kinds = {ev.get("kind") for ev in e.get("evidence") or []}
    tone = "mal" if "malicious" in kinds else "sus" if "suspicious" in kinds else "info"
    first = next((ev.get("text") for ev in e.get("evidence") or []), None)
    return (first or "Answered"), tone


def _skip_text(e: dict[str, Any]) -> str:
    reason = e.get("skipped_reason")
    return {
        "no_api_key": "Needs a free API key (set it in .env)",
        "tlp": f"Not asked: the marking forbids it ({e.get('detail') or 'TLP'})",
        "quota_exhausted": f"Quota used up; resets in {e.get('resets_in_s') or '?'} s",
        "budget_exhausted": "Not asked: this lookup's call budget is spent",
        "disabled": "Disabled on the Sources page",
        "active_not_requested": "Active check: not run unless asked",
        "not_requested": "Not asked (local knowledge only)",
    }.get(reason or "", f"Skipped: {reason}")


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
