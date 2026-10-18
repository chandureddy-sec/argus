"""Rules generated from indicators (ADR 0020).

Indicators are grouped by what they are (C2 address, malware-download URL,
phishing domain, file hash) and turned into:

* **Sigma**: one rule per group and log source, compiled with pySigma to
  Splunk SPL, Microsoft Sentinel / Defender KQL and Elastic Lucene;
* **Suricata**: IP, DNS, TLS SNI and HTTP rules;
* **YARA**: hash rules (``import "hash"``) for file hashes;
* **Wazuh**: rules over the Argus CDB list exports (no pySigma Wazuh
  backend exists, so these are written natively).

Every rule carries author, date, references, ATT&CK tags, TLP, confidence
and false-positive notes, and passes a syntax check before it is returned:
pySigma's parser and validators, ``suricataparser`` plus our own checks,
``yara.compile``, and an XML parse for Wazuh.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

# Parses only XML this module generated (check_wazuh), never input from outside.
from xml.etree import ElementTree  # nosec B405

import yaml

from threatlens import tlp as tlp_rules

_NS = uuid.UUID("0c7e8c39-3a8e-4e4c-9d1e-5b7b3f1a7a00")
CHUNK = 500  # values per rule: keeps queries within SIEM limits
SID_BASE = 9_100_000  # Suricata local sid range for Argus


@dataclass(frozen=True)
class Ioc:
    id: int
    type: str
    value: str
    score: float
    tlp: str
    labels: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()


@dataclass(frozen=True)
class Purpose:
    key: str
    title: str
    tactic: str
    technique: str
    falsepositives: tuple[str, ...]


C2 = Purpose(
    "c2",
    "command-and-control infrastructure",
    "command-and-control",
    "t1071.001",
    (
        "Shared hosting or CDN addresses reused by legitimate services after the C2 moved",
        "Sinkholes and security scanners resolving or probing the listed infrastructure",
    ),
)
DOWNLOAD = Purpose(
    "download",
    "malware delivery",
    "command-and-control",
    "t1105",
    (
        "Security tools and sandboxes fetching the URL for analysis",
        "Compromised legitimate sites that have since been cleaned",
    ),
)
PHISHING = Purpose(
    "phishing",
    "phishing",
    "initial-access",
    "t1566.002",
    ("Users reporting the link to the security team", "Mail gateways rewriting or detonating links"),
)
ANONYMIZER = Purpose(
    "anonymizer",
    "anonymisation network",
    "command-and-control",
    "t1090.003",
    ("Privacy-conscious users or researchers using Tor deliberately",),
)
MALICIOUS = Purpose(
    "malicious",
    "known-bad infrastructure",
    "command-and-control",
    "t1071",
    ("Infrastructure re-assigned to a new, benign owner since it was reported",),
)
FILE = Purpose(
    "file",
    "known-bad file",
    "execution",
    "t1204.002",
    ("Malware samples handled by analysts in a lab", "Security products quarantining the file"),
)


def purpose(ioc: Ioc) -> Purpose:
    labels = " ".join(ioc.labels).lower()
    if ioc.type.startswith("file-"):
        return FILE
    if "phish" in labels:
        return PHISHING
    if "tor" in labels or "anonymi" in labels:
        return ANONYMIZER
    if "c2" in labels or "botnet" in labels:
        return C2
    if "malware" in labels or "download" in labels or ioc.type == "url":
        return DOWNLOAD
    return MALICIOUS


@dataclass
class Meta:
    author: str
    date: str
    references: list[str]
    tlp: str
    confidence: int
    count: int


@dataclass
class Rule:
    kind: str  # sigma | suricata | yara | wazuh
    name: str
    title: str
    body: str
    meta: Meta
    tags: list[str] = field(default_factory=list)
    queries: dict[str, str] = field(default_factory=dict)  # sigma only: backend -> query
    problems: list[str] = field(default_factory=list)  # validator findings (warnings)

    def view(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "name": self.name,
            "title": self.title,
            "body": self.body,
            "author": self.meta.author,
            "date": self.meta.date,
            "references": self.meta.references,
            "tlp": self.meta.tlp,
            "confidence": self.meta.confidence,
            "count": self.meta.count,
            "tags": self.tags,
            "queries": self.queries,
            "problems": self.problems,
        }


class RuleError(ValueError):
    """A generated rule failed its syntax check (a bug: never shipped)."""


def _chunks(items: Sequence[Ioc], n: int = CHUNK) -> Iterable[tuple[int, Sequence[Ioc]]]:
    for i in range(0, len(items), n):
        yield i // n, items[i : i + n]


def _tlp(items: Sequence[Ioc]) -> str:
    level = "TLP:CLEAR"
    for i in items:
        level = tlp_rules.stricter(level, i.tlp)
    return level


def _meta(items: Sequence[Ioc], author: str, base_url: str) -> Meta:
    srcs = sorted({s for i in items for s in i.sources})
    refs = [f"{base_url.rstrip('/')}/app/indicators?sort=priority", *[f"source: {s}" for s in srcs][:5]]
    return Meta(
        author,
        datetime.now(UTC).strftime("%Y-%m-%d"),
        refs,
        _tlp(items),
        round(min(i.score for i in items)),
        len(items),
    )


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")


def group(iocs: Iterable[Ioc]) -> dict[tuple[str, str], list[Ioc]]:
    """(family, purpose key) -> indicators, family one of ip | net | domain | url | md5 | sha1 | sha256."""
    fam = {
        "ipv4-addr": "ip",
        "ipv6-addr": "ip",
        "ipv4-net": "net",
        "ipv6-net": "net",
        "domain-name": "domain",
        "url": "url",
        "file-md5": "md5",
        "file-sha1": "sha1",
        "file-sha256": "sha256",
    }
    out: dict[tuple[str, str], list[Ioc]] = {}
    for i in iocs:
        f = fam.get(i.type)
        if f:
            out.setdefault((f, purpose(i).key), []).append(i)
    for v in out.values():
        v.sort(key=lambda x: (-x.score, x.value))
    return out


PURPOSES = {p.key: p for p in (C2, DOWNLOAD, PHISHING, ANONYMIZER, MALICIOUS, FILE)}


# ── Sigma ────────────────────────────────────────────────────────────────────

# (logsource, field, modifier) per indicator family; one rule per entry.
SIGMA_SHAPES: dict[str, list[tuple[dict[str, str], str, str]]] = {
    "ip": [
        ({"category": "network_connection"}, "DestinationIp", ""),
        ({"category": "firewall"}, "dst_ip", ""),
    ],
    "net": [
        ({"category": "network_connection"}, "DestinationIp", "|cidr"),
        ({"category": "firewall"}, "dst_ip", "|cidr"),
    ],
    "domain": [({"category": "dns_query"}, "QueryName", ""), ({"category": "proxy"}, "cs-host", "")],
    "url": [({"category": "proxy"}, "c-uri", "")],
    "md5": [({"category": "process_creation"}, "Hashes", "|contains")],
    "sha1": [({"category": "process_creation"}, "Hashes", "|contains")],
    "sha256": [({"category": "process_creation"}, "Hashes", "|contains")],
}
SIGMA_BACKENDS = ("splunk", "kql", "lucene")


def _sigma_values(family: str, items: Sequence[Ioc]) -> list[str]:
    if family in ("md5", "sha1", "sha256"):
        label = {"md5": "MD5", "sha1": "SHA1", "sha256": "SHA256"}[family]
        return [f"{label}={i.value.upper()}" for i in items]  # Sysmon's Hashes field: "SHA256=…,MD5=…"
    return [i.value for i in items]


def sigma_rules(iocs: Iterable[Ioc], *, author: str, base_url: str) -> list[Rule]:
    rules: list[Rule] = []
    for (family, pkey), items in sorted(group(iocs).items()):
        p = PURPOSES[pkey]
        for n, chunk in _chunks(items):
            meta = _meta(chunk, author, base_url)
            for logsource, fieldname, modifier in SIGMA_SHAPES[family]:
                cat = logsource["category"]
                ident = f"sigma|{family}|{pkey}|{cat}|{n}"
                selection: dict[str, Any] = {f"{fieldname}{modifier}": _sigma_values(family, chunk)}
                detection: dict[str, Any] = {"selection": selection, "condition": "selection"}
                if family == "domain" and cat == "dns_query":
                    # the domain itself or any subdomain of it
                    detection = {
                        "selection": selection,
                        "subdomain": {"QueryName|endswith": [f".{i.value}" for i in chunk]},
                        "condition": "selection or subdomain",
                    }
                tlp_tag = "tlp." + meta.tlp.split(":", 1)[1].lower().replace("+", "-")
                part = f" part {n + 1}" if len(items) > CHUNK else ""
                doc: dict[str, Any] = {
                    "title": f"Argus: {p.title} ({family}, {cat}){part}",
                    "id": str(uuid.uuid5(_NS, ident)),
                    "status": "experimental",
                    "description": (
                        f"Connections to {len(chunk)} {family} indicators of {p.title} scoring "
                        f"{meta.confidence} or more in Argus. Generated from threat intelligence; "
                        "review before enabling as a blocking or paging rule."
                    ),
                    "references": meta.references,
                    "author": author,
                    "date": meta.date,
                    "tags": [f"attack.{p.tactic}", f"attack.{p.technique}", tlp_tag],
                    "logsource": logsource,
                    "detection": detection,
                    "falsepositives": list(p.falsepositives),
                    "level": "high" if meta.confidence >= 60 else "medium",
                    "x_argus_confidence": meta.confidence,
                    "x_argus_indicators": len(chunk),
                }
                body = yaml.safe_dump(doc, sort_keys=False, allow_unicode=False, width=120)
                rule = Rule(
                    "sigma",
                    f"argus_{family}_{pkey}_{_slug(cat)}_{n + 1}.yml",
                    doc["title"],
                    body,
                    meta,
                    doc["tags"],
                )
                rule.queries, rule.problems = compile_sigma(body)
                rules.append(rule)
    return rules


def compile_sigma(body: str) -> tuple[dict[str, str], list[str]]:
    """Parse and validate a Sigma rule and convert it for each backend.
    A parse error raises RuleError; validator findings come back as warnings."""
    from sigma.collection import SigmaCollection
    from sigma.exceptions import SigmaError

    try:
        coll = SigmaCollection.from_yaml(body)
    except SigmaError as e:
        raise RuleError(f"Sigma: {e}") from e
    problems = validate_sigma(coll)
    for rule in coll.rules:
        problems += [
            f"attack tag not in ATT&CK v20: {t}" for t in check_attack_tags(str(x) for x in rule.tags)
        ]
    queries: dict[str, str] = {}
    for name in SIGMA_BACKENDS:
        try:
            out = _backend(name).convert(coll)
            queries[name] = "\n".join(str(q) for q in out)
        except SigmaError as e:
            queries[name] = ""
            problems.append(f"{name}: {e}")
    return queries, problems


def _backend(name: str) -> Any:
    if name == "splunk":
        from sigma.backends.splunk import SplunkBackend  # type: ignore[attr-defined]

        return SplunkBackend()
    if name == "kql":
        from sigma.backends.kusto import KustoBackend  # type: ignore[attr-defined]

        return KustoBackend()
    from sigma.backends.elasticsearch import LuceneBackend  # type: ignore[attr-defined]

    return LuceneBackend()


# Validators that object to things we do on purpose (our x_ attributes), that need a
# whole rule repository (duplicates), that check TLP 1.0 (we tag TLP 2.0), or that
# download MITRE data at run time (attacktag: all outbound traffic goes through the
# guarded client, so ATT&CK tags are checked offline by check_attack_tags instead).
_SKIP_VALIDATORS = {
    "custom_attributes",
    "duplicate_filename",
    "duplicate_title",
    "filename_length",
    "identifier_uniqueness",
    "tlpv1_tag",
    "attacktag",
    "d3_fendtag",  # downloads D3FEND data at run time, like attacktag
}
# Enterprise ATT&CK v20 tactics (v18 split Defense Evasion into Stealth and Defense Impairment).
ATTACK_TACTICS = frozenset(
    {
        "reconnaissance",
        "resource-development",
        "initial-access",
        "execution",
        "persistence",
        "privilege-escalation",
        "stealth",
        "defense-impairment",
        "credential-access",
        "discovery",
        "lateral-movement",
        "collection",
        "command-and-control",
        "exfiltration",
        "impact",
    }
)
_TECHNIQUE_TAG = re.compile(r"^t\d{4}(\.\d{3})?$")


def check_attack_tags(tags: Iterable[str]) -> list[str]:
    """ATT&CK tags that are neither a v20 tactic nor a technique id."""
    bad = []
    for t in tags:
        ns, _, name = str(t).partition(".")
        if ns == "attack" and name not in ATTACK_TACTICS and not _TECHNIQUE_TAG.match(name):
            bad.append(str(t))
    return bad


def validate_sigma(coll: Any) -> list[str]:
    from sigma.validators.core import validators

    found: list[str] = []
    for name, cls in validators.items():
        if name in _SKIP_VALIDATORS:
            continue
        try:
            v = cls()
        except TypeError:
            continue
        for rule in coll.rules:
            try:
                for issue in v.validate(rule):
                    found.append(f"{name}: {issue}")
            except Exception as e:
                found.append(f"{name}: validator error {type(e).__name__}")
    return found


# ── Suricata ─────────────────────────────────────────────────────────────────


SID_SPAN = 899_999


def _sid(ident: str, used: set[int] | None = None) -> int:
    """A stable sid from the rule's identity; on a collision within one
    generation, the next free one (inputs are sorted, so still deterministic)."""
    sid = SID_BASE + int(hashlib.sha256(ident.encode()).hexdigest(), 16) % SID_SPAN
    if used is not None:
        while sid in used:
            sid = SID_BASE + (sid - SID_BASE + 1) % SID_SPAN
        used.add(sid)
    return sid


def _esc(v: str) -> str:
    """A Suricata content string: ; \\ " and | must be escaped or hex-encoded."""
    return "".join(f"|{ord(c):02X}|" if c in ';\\"|' else c for c in v)


def _msg(s: str) -> str:
    return re.sub(r'[;"\\]', " ", s)[:200]


def suricata_rules(iocs: Iterable[Ioc], *, author: str) -> list[Rule]:
    rules: list[Rule] = []
    used: set[int] = set()  # sids across every file of this generation
    date = datetime.now(UTC).strftime("%Y_%m_%d")
    for (family, pkey), items in sorted(group(iocs).items()):
        p = PURPOSES[pkey]
        lines: list[str] = []
        for i in items:
            meta_kw = (
                f"metadata: created_at {date}, author {_slug(author)}, confidence {round(i.score)}, "
                f"tlp {i.tlp.split(':')[1].lower().replace('+', '_')}, "
                f"mitre_technique_id {p.technique.upper()}, "
                f"argus_indicator {i.id};"
            )
            head = f"Argus {p.title}"
            if family in ("ip", "net"):
                for proto in ("ip",):
                    ident = f"suricata|{family}|{i.value}|{proto}"
                    lines.append(
                        f'alert {proto} $HOME_NET any -> {i.value} any (msg:"{_msg(f"{head} {i.value}")}"; '
                        f"classtype:trojan-activity; sid:{_sid(ident, used)}; rev:1; {meta_kw})"
                    )
            elif family == "domain":
                d = _esc(i.value.lower())
                lines.append(
                    f'alert dns $HOME_NET any -> any any (msg:"{_msg(f"{head} DNS query {i.value}")}"; '
                    f'dns.query; content:"{d}"; nocase; endswith; classtype:trojan-activity; '
                    f"sid:{_sid('suricata|dns|' + i.value, used)}; rev:1; {meta_kw})"
                )
                lines.append(
                    f'alert tls $HOME_NET any -> any any (msg:"{_msg(f"{head} TLS SNI {i.value}")}"; '
                    f'tls.sni; content:"{d}"; nocase; endswith; classtype:trojan-activity; '
                    f"sid:{_sid('suricata|sni|' + i.value, used)}; rev:1; {meta_kw})"
                )
            elif family == "url":
                m = re.match(r"^https?://([^/:]+)(?::\d+)?(/[^?#]*)?", i.value, re.I)
                if not m:
                    continue
                host, path = m.group(1), m.group(2) or "/"
                url_sid = _sid("suricata|url|" + i.value, used)
                lines.append(
                    f'alert http $HOME_NET any -> any any (msg:"{_msg(f"{head} URL {host}{path[:60]}")}"; '
                    f'http.host; content:"{_esc(host.lower())}"; http.uri; content:"{_esc(path)}"; '
                    f"startswith; classtype:trojan-activity; sid:{url_sid}; rev:1; "
                    f"{meta_kw})"
                )
        if not lines:
            continue
        body = (
            f"# Argus: {p.title} ({family}), {len(items)} indicators, generated {date} by {author}\n"
            f"# False positives: {'; '.join(p.falsepositives)}\n" + "\n".join(lines) + "\n"
        )
        meta = _meta(items, author, "")
        rule = Rule(
            "suricata",
            f"argus_{family}_{pkey}.rules",
            f"Argus {p.title} ({family})",
            body,
            meta,
            [f"attack.{p.technique}"],
        )
        check_suricata(body)
        rules.append(rule)
    return rules


_SURICATA_HEAD = re.compile(r"^alert (ip|tcp|udp|dns|tls|http) \S+ \S+ -> \S+ \S+ \(.*\)$")


_MSG = re.compile(r'\(msg:"([^"]*)";')


def check_suricata(body: str) -> None:
    """Parse every rule with suricataparser and check what it doesn't (it accepts
    a msg with a raw ; or " that Suricata itself rejects, so msg is checked here)."""
    from suricataparser import parse_rule

    sids: set[int] = set()
    for line in body.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        if not _SURICATA_HEAD.match(line):
            raise RuleError(f"Suricata: malformed header in {line[:80]}")
        m = _MSG.search(line)
        if not m or any(c in m.group(1) for c in ";\\"):
            raise RuleError(f'Suricata: msg must be quoted text without ; \\ or " in {line[:80]}')
        r = parse_rule(line)
        if r is None:
            raise RuleError(f"Suricata: unparseable rule {line[:80]}")
        if not r.sid or r.sid in sids:
            raise RuleError(f"Suricata: missing or duplicate sid in {line[:80]}")
        sids.add(r.sid)
        names = {o.name for o in r.options}
        if not {"msg", "sid", "rev", "classtype", "metadata"} <= names:
            raise RuleError(f"Suricata: rule {r.sid} lacks msg/sid/rev/classtype/metadata")


# ── YARA ─────────────────────────────────────────────────────────────────────


def yara_rules(iocs: Iterable[Ioc], *, author: str) -> list[Rule]:
    """``import "hash"`` rules for known-bad file hashes. They read the whole
    file, so use them for retro-scans and triage, not on every file write."""
    rules: list[Rule] = []
    date = datetime.now(UTC).strftime("%Y-%m-%d")
    for (family, pkey), items in sorted(group(iocs).items()):
        if family not in ("md5", "sha1", "sha256"):
            continue
        p = PURPOSES[pkey]
        fn = {"md5": "hash.md5", "sha1": "hash.sha1", "sha256": "hash.sha256"}[family]
        blocks = []
        for n, chunk in _chunks(items, 200):
            meta = _meta(chunk, author, "")
            cond = " or\n        ".join(f'{fn}(0, filesize) == "{i.value.lower()}"' for i in chunk)
            srcs = _msg(", ".join(sorted({s for i in chunk for s in i.sources})) or "analyst")
            blocks.append(
                f"rule argus_{family}_{pkey}_{n + 1}\n{{\n    meta:\n"
                f'        author = "{_msg(author)}"\n        date = "{date}"\n'
                f'        description = "Argus: {len(chunk)} known-bad files ({p.title}), by {family}"\n'
                f'        reference = "Argus indicators, sources: {srcs}"\n'
                f'        tlp = "{meta.tlp}"\n        confidence = {meta.confidence}\n'
                f'        mitre_att = "{p.technique.upper()}"\n'
                f'        false_positives = "{_msg("; ".join(p.falsepositives))}"\n'
                f"    condition:\n        {cond}\n}}\n"
            )
        body = 'import "hash"\n\n' + "\n".join(blocks)
        check_yara(body)
        rules.append(
            Rule(
                "yara",
                f"argus_{family}_{pkey}.yar",
                f"Argus known-bad files ({family})",
                body,
                _meta(items, author, ""),
                [f"attack.{p.technique}"],
            )
        )
    return rules


def check_yara(body: str) -> None:
    import yara

    try:
        yara.compile(source=body)
    except yara.SyntaxError as e:
        raise RuleError(f"YARA: {e}") from e


# ── Wazuh ────────────────────────────────────────────────────────────────────

WAZUH_BASE_ID = 100_900  # local rule ids 100000-120000 are reserved for custom rules


def wazuh_rules(author: str) -> Rule:
    """Rules over the Argus CDB exports (docs/INTEGRATIONS.md): any event whose
    source/destination address, DNS query or URL is on an Argus list."""
    date = datetime.now(UTC).strftime("%Y-%m-%d")
    specs = [
        (0, "dstip", "argus-ip", "address_match_key", "Connection to an IP on the Argus list", "T1071"),
        (1, "srcip", "argus-ip", "address_match_key", "Connection from an IP on the Argus list", "T1071"),
        (
            2,
            "dns.question.name",
            "argus-domain",
            "match_key",
            "DNS query for a domain on the Argus list",
            "T1071.004",
        ),
        (3, "url", "argus-url", "match_key", "Request for a URL on the Argus list", "T1105"),
    ]
    rules = []
    for n, fieldname, lst, lookup, desc, tech in specs:
        rules.append(
            f'  <rule id="{WAZUH_BASE_ID + n}" level="10">\n'
            f'    <list field="{fieldname}" lookup="{lookup}">etc/lists/{lst}</list>\n'
            f"    <description>Argus: {desc} ($({fieldname}))</description>\n"
            f"    <mitre>\n      <id>{tech}</id>\n    </mitre>\n"
            f"    <group>argus,threat_intel,</group>\n"
            f"  </rule>\n"
        )
    body = (
        f"<!-- Argus threat-intel rules, generated {date} by {_msg(author)}.\n"
        "     Needs the lists /var/ossec/etc/lists/argus-ip, argus-domain, argus-url from\n"
        "     /feeds/<token>/indicators/wazuh-{ip,domain,url}.cdb, declared in ossec.conf <ruleset>.\n"
        "     False positives: infrastructure re-assigned since it was reported; security tools. -->\n"
        '<group name="argus,threat_intel,">\n' + "".join(rules) + "</group>\n"
    )
    check_wazuh(body)
    meta = Meta(author, date, ["docs/INTEGRATIONS.md#wazuh"], "TLP:CLEAR", 60, len(specs))
    return Rule(
        "wazuh",
        "argus_rules.xml",
        "Argus CDB list rules for Wazuh",
        body,
        meta,
        ["attack.t1071", "attack.t1105"],
    )


def check_wazuh(body: str) -> None:
    try:
        root = ElementTree.fromstring(body)  # noqa: S314 # nosec B314
    except ElementTree.ParseError as e:
        raise RuleError(f"Wazuh: {e}") from e
    ids = [r.get("id") for r in root.iter("rule")]
    if len(ids) != len(set(ids)) or not all(i and 100_000 <= int(i) <= 120_000 for i in ids):
        raise RuleError("Wazuh: rule ids must be unique custom ids (100000-120000)")
    for r in root.iter("rule"):
        if r.find("description") is None or r.find("list") is None:
            raise RuleError(f"Wazuh: rule {r.get('id')} lacks a description or list")
