"""Phase 1 connectors. Terms, endpoints and formats verified 2026-10-08
(details and evidence in docs/SOURCES.md)."""

from __future__ import annotations

import csv
import json
from collections.abc import Iterator, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

from threatlens.connectors.base import (
    Connector,
    Item,
    MissingKeyError,
    SchemaDriftError,
    SourceInfo,
    clip,
    parse_time,
    register,
    require,
)
from threatlens.ioc.types import IOCType
from threatlens.net.http import FetchResult, SafeHttp

VERIFIED = "2026-10-08"
H = timedelta(hours=1)
M = timedelta(minutes=1)


def _json(body: bytes, where: str) -> Any:
    try:
        return json.loads(body)
    except (ValueError, UnicodeDecodeError) as e:
        raise SchemaDriftError(f"{where}: not JSON ({e})") from e


# ── CISA Known Exploited Vulnerabilities ──────────────────────────────────────


@register
class CisaKev(Connector):
    info = SourceInfo(
        name="cisa_kev",
        title="CISA Known Exploited Vulnerabilities",
        kind="vulnerability",
        homepage="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        reliability="A",
        reliability_note="US government catalog; entries require evidence of active exploitation.",
        license="CC0 1.0",
        license_url="https://www.cisa.gov/sites/default/files/licenses/kev/license.txt",
        commercial_use=True,
        redistribution=True,
        upstream="cisa",
        interval=6 * H,
        min_interval=H,
        default_confidence=100,
        credibility=1,
        verified=VERIFIED,
    )

    def parse(self, body: bytes) -> Iterator[Item]:
        doc = _json(body, "KEV")
        if not isinstance(doc, dict):
            raise SchemaDriftError("KEV: top level is not an object")
        require(doc, "vulnerabilities", "catalogVersion", where="KEV")
        for v in doc["vulnerabilities"]:
            require(v, "cveID", "dateAdded", where="KEV entry")
            ransomware = v.get("knownRansomwareCampaignUse") == "Known"
            yield Item(
                value=v["cveID"],
                type=IOCType.CVE,
                seen_at=parse_time(v["dateAdded"]),
                labels=("kev", "exploited") + (("ransomware",) if ransomware else ()),
                context={
                    "vendor": v.get("vendorProject"),
                    "product": v.get("product"),
                    "name": clip(v.get("vulnerabilityName"), 300),
                    "description": clip(v.get("shortDescription")),
                    "required_action": clip(v.get("requiredAction"), 300),
                    "due_date": v.get("dueDate"),
                    "ransomware_use": v.get("knownRansomwareCampaignUse"),
                    "cwes": v.get("cwes", []),
                    "catalog_version": doc["catalogVersion"],
                },
            )


# ── abuse.ch ─────────────────────────────────────────────────────────────────

_ABUSECH_TERMS = "https://abuse.ch/terms-of-use/"


@register
class UrlHaus(Connector):
    info = SourceInfo(
        name="urlhaus",
        title="abuse.ch URLhaus (recent URLs)",
        kind="malware-url",
        homepage="https://urlhaus.abuse.ch/",
        url="https://urlhaus.abuse.ch/downloads/csv_recent/",
        reliability="B",
        reliability_note="Curated malware-distribution URLs; community-reported, reviewed by abuse.ch.",
        license="abuse.ch terms of use (fair use; commercial use needs a subscription)",
        license_url=_ABUSECH_TERMS,
        commercial_use=False,
        redistribution=False,
        upstream="abuse.ch",
        interval=H,
        min_interval=5 * M,
        default_confidence=80,
        credibility=2,
        key_setting="abusech_auth_key",
        key_required=False,  # dump downloads still work anonymously (2026-10-08)
        verified=VERIFIED,
    )
    COLUMNS: ClassVar[list[str]] = [
        "id",
        "dateadded",
        "url",
        "url_status",
        "last_online",
        "threat",
        "tags",
        "urlhaus_link",
        "reporter",
    ]

    async def fetch(self, http: SafeHttp, checkpoint: Mapping[str, Any]) -> FetchResult:
        headers = {"Auth-Key": self.api_key} if self.api_key else None
        return await http.get(
            self.info.url,
            headers=headers,
            etag=checkpoint.get("etag"),
            last_modified=checkpoint.get("last_modified"),
            max_bytes=self.info.max_bytes,
        )

    def parse(self, body: bytes) -> Iterator[Item]:
        text = body.decode("utf-8", errors="replace")
        header = next((ln for ln in text.splitlines() if ln.startswith("# id,")), None)
        if header is None or header[2:].split(",") != self.COLUMNS:
            raise SchemaDriftError(f"URLhaus: unexpected CSV header {header!r}")
        rows = csv.reader(ln for ln in text.splitlines() if ln and not ln.startswith("#"))
        for row in rows:
            if len(row) != len(self.COLUMNS):
                raise SchemaDriftError(f"URLhaus: row has {len(row)} columns, expected {len(self.COLUMNS)}")
            r = dict(zip(self.COLUMNS, row, strict=True))
            online = r["url_status"] == "online"
            tags = tuple(t for t in r["tags"].split(",") if t and t != "None")
            yield Item(
                value=r["url"],
                type=IOCType.URL,
                seen_at=parse_time(r["dateadded"]),
                confidence=85 if online else 60,
                labels=("malware-distribution", *tags),
                context={
                    "threat": r["threat"],
                    "url_status": r["url_status"],
                    "last_online": r["last_online"] or None,
                    "reference": r["urlhaus_link"],
                    "reporter": r["reporter"],
                },
            )


_THREATFOX_TYPES = {
    "ip:port": IOCType.IPV4,
    "domain": IOCType.DOMAIN,
    "url": IOCType.URL,
    "md5_hash": IOCType.MD5,
    "sha1_hash": IOCType.SHA1,
    "sha256_hash": IOCType.SHA256,
}


@register
class ThreatFox(Connector):
    info = SourceInfo(
        name="threatfox",
        title="abuse.ch ThreatFox",
        kind="ioc",
        homepage="https://threatfox.abuse.ch/",
        url="https://threatfox-api.abuse.ch/api/v1/",
        reliability="B",
        reliability_note="Community IOCs with a per-IOC confidence level, moderated by abuse.ch.",
        license="abuse.ch terms of use (fair use; commercial use needs a subscription)",
        license_url=_ABUSECH_TERMS,
        commercial_use=False,
        redistribution=False,
        upstream="abuse.ch",
        interval=H,
        min_interval=15 * M,
        default_confidence=75,
        credibility=3,
        key_setting="abusech_auth_key",
        key_required=True,  # the API answers 401 without Auth-Key (2026-10-08)
        verified=VERIFIED,
    )

    async def fetch(self, http: SafeHttp, checkpoint: Mapping[str, Any]) -> FetchResult:
        # One day of data when we ran recently, the API's maximum (7) otherwise.
        last = parse_time(checkpoint.get("last_success"))
        days = 1 if last and datetime.now(UTC) - last < timedelta(hours=20) else 7
        if not self.api_key:  # enforced in __init__; re-checked so -O can't drop it
            raise MissingKeyError(f"{self.info.name} needs TL_ABUSECH_AUTH_KEY")
        return await http.post_json(
            self.info.url, {"query": "get_iocs", "days": days}, headers={"Auth-Key": self.api_key}
        )

    def next_checkpoint(self, result: FetchResult, checkpoint: Mapping[str, Any]) -> dict[str, Any]:
        return {**checkpoint, "last_success": datetime.now(UTC).isoformat()}

    def parse(self, body: bytes) -> Iterator[Item]:
        doc = _json(body, "ThreatFox")
        if not isinstance(doc, dict):
            raise SchemaDriftError("ThreatFox: top level is not an object")
        require(doc, "query_status", where="ThreatFox")
        if doc["query_status"] == "no_result":
            return
        if doc["query_status"] != "ok" or not isinstance(doc.get("data"), list):
            raise SchemaDriftError(f"ThreatFox: query_status={doc['query_status']!r}")
        for d in doc["data"]:
            require(d, "ioc", "ioc_type", where="ThreatFox IOC")
            ioc_type = _THREATFOX_TYPES.get(d["ioc_type"])
            value, port = d["ioc"], None
            if d["ioc_type"] == "ip:port":
                value, _, port = value.rpartition(":")
                ioc_type = IOCType.IPV6 if ":" in value else IOCType.IPV4
            conf = d.get("confidence_level")
            yield Item(
                value=value,
                type=ioc_type,  # unknown types → None → guessed, or rejected
                seen_at=parse_time(d.get("first_seen")),
                confidence=conf if isinstance(conf, int) else None,
                labels=tuple(x for x in (d.get("threat_type"), *(d.get("tags") or [])) if x),
                context={
                    "malware": d.get("malware_printable") or d.get("malware"),
                    "malpedia": d.get("malware_malpedia"),
                    "threat_type": d.get("threat_type"),
                    "port": int(port) if port and port.isdigit() else None,
                    "reporter": d.get("reporter"),
                    "reference": d.get("reference"),
                    "last_seen": d.get("last_seen"),
                    "threatfox_id": d.get("id"),
                },
            )


@register
class FeodoTracker(Connector):
    info = SourceInfo(
        name="feodo",
        title="abuse.ch Feodo Tracker (botnet C2, last 30 days)",
        kind="botnet-c2",
        homepage="https://feodotracker.abuse.ch/",
        url="https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        reliability="B",
        reliability_note="Botnet C2 servers verified by abuse.ch tracking infrastructure.",
        license="CC0 1.0",
        license_url="https://feodotracker.abuse.ch/blocklist/",
        commercial_use=True,
        redistribution=True,
        upstream="abuse.ch",
        interval=30 * M,
        min_interval=5 * M,
        default_confidence=85,
        credibility=2,
        verified=VERIFIED,
    )

    def parse(self, body: bytes) -> Iterator[Item]:
        doc = _json(body, "Feodo")
        if not isinstance(doc, list):
            raise SchemaDriftError("Feodo: top level is not a list")
        for d in doc:
            require(d, "ip_address", "status", where="Feodo entry")
            online = d["status"] == "online"
            malware = d.get("malware")
            yield Item(
                value=d["ip_address"],
                type=None,
                seen_at=parse_time(d.get("first_seen")),
                confidence=90 if online else 70,
                labels=("botnet-c2", *((malware.lower(),) if malware else ())),
                context={
                    "malware": malware,
                    "port": d.get("port"),
                    "status": d["status"],
                    "last_online": d.get("last_online"),
                    "as_number": d.get("as_number"),
                    "as_name": d.get("as_name"),
                    "country": d.get("country"),
                },
            )


# ── AlienVault OTX ───────────────────────────────────────────────────────────

_OTX_TYPES = {
    "IPv4": IOCType.IPV4,
    "IPv6": IOCType.IPV6,
    "CIDR": IOCType.IPV4_NET,
    "domain": IOCType.DOMAIN,
    "hostname": IOCType.DOMAIN,
    "URL": IOCType.URL,
    "email": IOCType.EMAIL,
    "FileHash-MD5": IOCType.MD5,
    "FileHash-SHA1": IOCType.SHA1,
    "FileHash-SHA256": IOCType.SHA256,
    "CVE": IOCType.CVE,
}
_OTX_TLP = {
    "white": "TLP:CLEAR",
    "clear": "TLP:CLEAR",
    "green": "TLP:GREEN",
    "amber": "TLP:AMBER",
    "red": "TLP:RED",
}
OTX_MAX_PAGES = 20


@register
class Otx(Connector):
    info = SourceInfo(
        name="otx",
        title="AlienVault OTX (subscribed pulses)",
        kind="pulse",
        homepage="https://otx.alienvault.com/",
        url="https://otx.alienvault.com/api/v1/pulses/subscribed",
        reliability="C",
        reliability_note="Community pulses of varying quality; trust depends on the author.",
        license="OTX terms of service",
        license_url="https://otx.alienvault.com/",
        commercial_use=False,  # not confirmed; treated conservatively until verified with a key
        redistribution=False,
        upstream="otx-community",
        interval=H,
        min_interval=15 * M,
        default_confidence=50,
        credibility=3,
        key_setting="otx_api_key",
        key_required=True,  # 403 without X-OTX-API-KEY (2026-10-08)
        verified=VERIFIED,
    )

    async def fetch(self, http: SafeHttp, checkpoint: Mapping[str, Any]) -> FetchResult:
        if not self.api_key:
            raise MissingKeyError(f"{self.info.name} needs TL_OTX_API_KEY")
        since = checkpoint.get("modified_since") or (datetime.now(UTC) - timedelta(days=7)).isoformat()
        pages: list[Any] = []
        url: str | None = self.info.url
        params: dict[str, str] | None = {"modified_since": since, "limit": "50"}
        last: FetchResult | None = None
        while url and len(pages) < OTX_MAX_PAGES:
            last = await http.get(url, params=params, headers={"X-OTX-API-KEY": self.api_key})
            page = _json(last.body, "OTX page")
            pages.append(page)
            url, params = (page.get("next") if isinstance(page, dict) else None), None
        if last is None:  # the loop always runs once; this satisfies the type checker
            raise SchemaDriftError("OTX returned no pages")
        # Pages are combined into one raw document, archived as fetched.
        body = json.dumps({"pages": pages, "modified_since": since}).encode()
        return FetchResult(last.url, 200, body, "application/json", None, None)

    def next_checkpoint(self, result: FetchResult, checkpoint: Mapping[str, Any]) -> dict[str, Any]:
        doc = json.loads(result.body)
        modified = [p.get("modified", "") for page in doc["pages"] for p in page.get("results", [])]
        newest = max(modified, default=None)
        return {**checkpoint, "modified_since": newest or doc["modified_since"]}

    def parse(self, body: bytes) -> Iterator[Item]:
        doc = _json(body, "OTX")
        require(doc, "pages", where="OTX")
        for page in doc["pages"]:
            require(page, "results", where="OTX page")
            for pulse in page["results"]:
                require(pulse, "id", "indicators", where="OTX pulse")
                tlp = _OTX_TLP.get(str(pulse.get("tlp", "")).lower(), "TLP:AMBER")  # unknown → cautious
                labels = tuple(t for t in (pulse.get("tags") or [])[:10] if isinstance(t, str))
                for ind in pulse["indicators"]:
                    require(ind, "indicator", "type", where="OTX indicator")
                    if ind.get("is_active") == 0:
                        continue
                    yield Item(
                        value=ind["indicator"],
                        type=_OTX_TYPES.get(ind["type"]),
                        seen_at=parse_time(ind.get("created")),
                        labels=labels,
                        tlp=tlp,
                        context={
                            "pulse_id": pulse["id"],
                            "pulse": clip(pulse.get("name"), 200),
                            "author": pulse.get("author_name"),
                            "adversary": pulse.get("adversary") or None,
                            "malware_families": pulse.get("malware_families") or [],
                            "attack_ids": pulse.get("attack_ids") or [],
                            # Pulse targeting (array fields per ThreatQ/Elastic OTX integration docs,
                            # 2026-10-11; not yet seen live: no OTX key). Used for PIR relevance.
                            "targeted_countries": [
                                c for c in pulse.get("targeted_countries") or [] if isinstance(c, str)
                            ][:20],
                            "industries": [x for x in pulse.get("industries") or [] if isinstance(x, str)][
                                :20
                            ],
                            "otx_type": ind["type"],
                        },
                    )


# ── Spamhaus DROP ────────────────────────────────────────────────────────────


@register
class SpamhausDrop(Connector):
    info = SourceInfo(
        name="spamhaus_drop",
        title="Spamhaus DROP (IPv4 + IPv6)",
        kind="netblock",
        homepage="https://www.spamhaus.org/blocklists/do-not-route-or-peer/",
        url="https://www.spamhaus.org/drop/drop_v4.json",
        reliability="A",
        reliability_note=(
            "Netblocks hijacked or operated by criminals; long-established, low false-positive list."
        ),
        # "no cost, regardless of size or business type"; credit Spamhaus and keep
        # the date and (c) text with the data. The terms grant no licence to the
        # list itself, so we don't redistribute it (exports exclude it).
        license="Spamhaus DROP terms (free incl. commercial, attribution required, no redistribution)",
        license_url="https://www.spamhaus.org/drop/terms/",
        commercial_use=True,
        redistribution=False,
        attribution="Spamhaus DROP list, (c) The Spamhaus Project SLU",
        upstream="spamhaus",
        # The product page says both "not more than once per hour" and "not more
        # than once per day"; we honour the stricter one.
        interval=24 * H,
        min_interval=24 * H,
        default_confidence=95,
        credibility=2,
        verified=VERIFIED,
    )
    URLS = ("https://www.spamhaus.org/drop/drop_v4.json", "https://www.spamhaus.org/drop/drop_v6.json")

    async def fetch(self, http: SafeHttp, checkpoint: Mapping[str, Any]) -> FetchResult:
        parts = [await http.get(u, max_bytes=self.info.max_bytes) for u in self.URLS]
        body = b"\n".join(p.body.strip() for p in parts) + b"\n"
        return FetchResult(parts[0].url, 200, body, "application/x-ndjson", None, None)

    def parse(self, body: bytes) -> Iterator[Item]:
        metadata = 0
        for n, line in enumerate(body.decode("utf-8").splitlines(), 1):
            if not line.strip():
                continue
            rec = _json(line.encode(), f"DROP line {n}")
            if rec.get("type") == "metadata":
                metadata += 1
                continue
            require(rec, "cidr", where=f"DROP line {n}")
            yield Item(
                value=rec["cidr"],
                type=IOCType.IPV6_NET if ":" in rec["cidr"] else IOCType.IPV4_NET,
                labels=("drop", "hijacked-or-criminal-netblock"),
                context={"sblid": rec.get("sblid"), "rir": rec.get("rir")},
            )
        if metadata == 0:
            raise SchemaDriftError("DROP: no metadata record (format changed?)")


# ── Tor exit nodes ───────────────────────────────────────────────────────────


@register
class TorExits(Connector):
    info = SourceInfo(
        name="tor_exits",
        title="Tor Project bulk exit list",
        kind="anonymizer",
        homepage="https://check.torproject.org/",
        url="https://check.torproject.org/torbulkexitlist",
        reliability="A",
        reliability_note="Authoritative for 'is a Tor exit'; being a Tor exit is not itself malicious.",
        license="Public list; no explicit licence published at the endpoint",
        license_url="https://www.torproject.org/",
        commercial_use=True,
        redistribution=True,
        upstream="torproject",
        interval=H,
        min_interval=30 * M,
        # Confidence that an exit is a *threat* is low: it is context, not guilt.
        default_confidence=30,
        credibility=1,
        verified=VERIFIED,
    )

    def parse(self, body: bytes) -> Iterator[Item]:
        lines = [ln.strip() for ln in body.decode("utf-8", errors="replace").splitlines() if ln.strip()]
        if lines and any(c.isalpha() and c not in "abcdefABCDEF" for c in lines[0]):
            raise SchemaDriftError("Tor list: expected one IP per line")
        for ln in lines:
            yield Item(value=ln, type=None, labels=("tor-exit", "anonymizer"))


# ── OpenPhish ────────────────────────────────────────────────────────────────


@register
class OpenPhish(Connector):
    info = SourceInfo(
        name="openphish",
        title="OpenPhish Community feed",
        kind="phishing",
        homepage="https://openphish.com/phishing_feeds.html",
        url="https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
        reliability="B",
        reliability_note="Automated phishing detection; URLs are short-lived.",
        license="OpenPhish terms of use (community feed: non-commercial only)",
        license_url="https://openphish.com/terms.html",
        commercial_use=False,
        redistribution=False,
        upstream="openphish",
        interval=12 * H,  # the community feed updates every 12 hours
        min_interval=H,
        default_confidence=80,
        credibility=2,
        verified=VERIFIED,
    )

    def parse(self, body: bytes) -> Iterator[Item]:
        lines = [ln.strip() for ln in body.decode("utf-8", errors="replace").splitlines() if ln.strip()]
        if lines and not lines[0].lower().startswith(("http://", "https://")):
            raise SchemaDriftError("OpenPhish: expected one URL per line")
        for ln in lines:
            yield Item(value=ln, type=IOCType.URL, labels=("phishing",))
