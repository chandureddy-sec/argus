"""Reputation services: AbuseIPDB, GreyNoise, VirusTotal, urlscan.io and
MalwareBazaar. All passive (they answer from their own data), all third
party. Weights below are the v0 evidence weights (ADR 0005); Phase 4 scoring
recalibrates them.
"""

from __future__ import annotations

import base64
import re
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

from threatlens.enrich.base import (
    HASHES,
    IPS,
    Enricher,
    EnricherInfo,
    EnrichError,
    Evidence,
    Outcome,
    Quota,
    cap_raw,
    load_json,
    rate_from_headers,
    register,
)
from threatlens.ioc.types import IOCType
from threatlens.net.http import SafeHttp

DAY = 86400
WEEK = 7 * DAY


# ── AbuseIPDB ────────────────────────────────────────────────────────────────


@register
class AbuseIpdb(Enricher):
    info = EnricherInfo(
        name="abuseipdb",
        title="AbuseIPDB",
        homepage="https://docs.abuseipdb.com/",
        applies_to=IPS,
        mode="passive",
        third_party=True,
        discloses=False,
        reliability="C",
        reliability_note=(
            "Crowd-sourced abuse reports; the confidence score weighs reporter trust and recency."
        ),
        license="AbuseIPDB Terms of Service (free plan: non-commercial)",
        license_url="https://www.abuseipdb.com/legal",
        commercial_use=False,
        redistribution=False,
        upstream="abuseipdb",
        ttl=timedelta(hours=24),
        negative_ttl=timedelta(hours=24),
        verified="2026-10-10",
        key_setting="abuseipdb_api_key",
        key_required=True,
        quotas=(Quota(1000, DAY),),
        metered=True,
    )

    URL = "https://api.abuseipdb.com/api/v2/check"

    async def query(self, http: SafeHttp, type_: IOCType, value: str) -> Outcome:
        res = await http.get(
            self.URL,
            params={"ipAddress": value, "maxAgeInDays": "90"},
            headers={"Key": self.api_key or "", "Accept": "application/json"},
            max_bytes=512 * 1024,
        )
        doc = load_json(res, "AbuseIPDB")
        d = doc.get("data") if isinstance(doc, dict) else None
        if not isinstance(d, dict) or "abuseConfidenceScore" not in d:
            raise EnrichError("AbuseIPDB: no data.abuseConfidenceScore in response")
        score = int(d.get("abuseConfidenceScore") or 0)
        summary = {
            "abuse_confidence": score,
            "total_reports": d.get("totalReports"),
            "distinct_reporters": d.get("numDistinctUsers"),
            "last_reported_at": d.get("lastReportedAt"),
            "country": d.get("countryCode"),
            "usage_type": d.get("usageType"),
            "isp": d.get("isp"),
            "domain": d.get("domain"),
            "hostnames": (d.get("hostnames") or [])[:10],
            "is_tor": d.get("isTor"),
            "is_whitelisted": d.get("isWhitelisted"),
        }
        ref = f"https://www.abuseipdb.com/check/{value}"
        n, users = summary["total_reports"] or 0, summary["distinct_reporters"] or 0
        reports = f"{n} reports from {users} users in 90 days"
        ev = []
        if d.get("isWhitelisted"):
            ev.append(
                Evidence(
                    "abuseipdb", "benign", 60, "On AbuseIPDB's whitelist (known good infrastructure)", ref
                )
            )
        if score >= 75:
            ev.append(
                Evidence("abuseipdb", "malicious", score, f"Abuse confidence {score}% ({reports})", ref)
            )
        elif score >= 25:
            ev.append(
                Evidence("abuseipdb", "suspicious", score, f"Abuse confidence {score}% ({reports})", ref)
            )
        else:
            ev.append(Evidence("abuseipdb", "info", 0, f"Abuse confidence {score}% ({reports})", ref))
        if d.get("isTor"):
            ev.append(Evidence("abuseipdb", "info", 0, "Tor exit node", ref))
        rate = rate_from_headers(res.headers, "x-ratelimit-remaining", "x-ratelimit-reset")
        return Outcome(
            "ok",
            summary,
            ev,
            raw=cap_raw(doc),
            query=f"{self.URL}?ipAddress={value}&maxAgeInDays=90",
            http_status=res.status,
            rate=rate,
        )


# ── GreyNoise Community ──────────────────────────────────────────────────────


@register
class GreyNoise(Enricher):
    info = EnricherInfo(
        name="greynoise",
        title="GreyNoise Community",
        homepage="https://docs.greynoise.io/docs/using-the-greynoise-community-api",
        applies_to=frozenset({IOCType.IPV4}),
        mode="passive",
        third_party=True,
        discloses=False,
        reliability="B",
        reliability_note="Sensor-observed internet scanning plus a curated list of business services (RIOT).",
        license="GreyNoise EULA (internal business or non-commercial use)",
        license_url="https://www.greynoise.io/terms",
        commercial_use=True,  # internal business purposes only
        redistribution=False,
        upstream="greynoise",
        ttl=timedelta(days=3),
        negative_ttl=timedelta(days=3),
        verified="2026-10-10",
        key_setting="greynoise_api_key",
        # Observed live 2026-10-10: X-Ratelimit-Limit 25, reset a week out.
        # Docs: free accounts get 50 searches a week (shared with the Visualizer).
        quotas=(Quota(25, WEEK),),
        keyed_quotas=(Quota(50, WEEK),),
        metered=True,
        concurrency=2,
    )

    URL = "https://api.greynoise.io/v3/community/{}"

    async def query(self, http: SafeHttp, type_: IOCType, value: str) -> Outcome:
        url = self.URL.format(value)
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["key"] = self.api_key
        res = await http.get(url, headers=headers, accept=frozenset({404}), max_bytes=64 * 1024)
        doc = load_json(res, "GreyNoise")
        if not isinstance(doc, dict) or "noise" not in doc:
            raise EnrichError("GreyNoise: unexpected response")
        rate = rate_from_headers(res.headers, "x-ratelimit-remaining", "x-ratelimit-reset")
        summary = {
            k: doc.get(k) for k in ("noise", "riot", "classification", "name", "last_seen", "link", "message")
        }
        if res.status == 404:
            return Outcome(
                "not_found",
                summary,
                [
                    Evidence(
                        "greynoise",
                        "info",
                        0,
                        "Not seen scanning the internet and not a known business service",
                    )
                ],
                raw=doc,
                query=url,
                http_status=404,
                rate=rate,
            )
        ref = doc.get("link") if isinstance(doc.get("link"), str) else None
        name, cls = doc.get("name") or "unknown", doc.get("classification")
        ev = []
        if doc.get("riot"):
            ev.append(Evidence("greynoise", "benign", 70, f"Common business service: {name}", ref))
        if cls == "malicious":
            ev.append(
                Evidence(
                    "greynoise",
                    "malicious",
                    70,
                    f"Classified malicious (last seen {doc.get('last_seen')})",
                    ref,
                )
            )
        elif cls == "benign" and doc.get("noise"):
            ev.append(Evidence("greynoise", "benign", 50, f"Known benign scanner: {name}", ref))
        elif doc.get("noise"):
            ev.append(
                Evidence(
                    "greynoise",
                    "suspicious",
                    20,
                    f"Mass-scanning the internet (last seen {doc.get('last_seen')})",
                    ref,
                )
            )
        return Outcome("ok", summary, ev, raw=doc, query=url, http_status=res.status, rate=rate)


# ── VirusTotal ───────────────────────────────────────────────────────────────


def vt_url_id(url: str) -> str:
    """VirusTotal URL identifier: unpadded URL-safe base64 of the URL."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


@register
class VirusTotal(Enricher):
    info = EnricherInfo(
        name="virustotal",
        title="VirusTotal",
        homepage="https://docs.virustotal.com/reference/overview",
        applies_to=frozenset({IOCType.DOMAIN, IOCType.URL}) | IPS | HASHES,
        mode="passive",
        third_party=True,
        # VirusTotal: an IP looked up through the API "is scanned and added to
        # the VirusTotal dataset". Lookups are disclosures.
        discloses=True,
        reliability="B",
        reliability_note=(
            "Aggregated verdicts of ~70 engines; detections by one or two engines are often false positives."
        ),
        license="VirusTotal Terms of Service (public API: no commercial products or business workflows)",
        license_url="https://docs.virustotal.com/reference/public-vs-premium-api",
        commercial_use=False,
        redistribution=False,
        upstream="virustotal",
        ttl=timedelta(hours=24),
        negative_ttl=timedelta(hours=24),
        verified="2026-10-10",
        key_setting="virustotal_api_key",
        key_required=True,
        quotas=(Quota(4, 60), Quota(500, DAY)),
        metered=True,
        concurrency=2,
    )

    API = "https://www.virustotal.com/api/v3/"
    PATHS: ClassVar[dict[IOCType, str]] = {
        IOCType.IPV4: "ip_addresses",
        IOCType.IPV6: "ip_addresses",
        IOCType.DOMAIN: "domains",
        IOCType.URL: "urls",
    }
    GUI: ClassVar[dict[str, str]] = {
        "ip_addresses": "ip-address",
        "domains": "domain",
        "urls": "url",
        "files": "file",
    }

    async def query(self, http: SafeHttp, type_: IOCType, value: str) -> Outcome:
        kind = self.PATHS.get(type_, "files")
        ident = vt_url_id(value) if type_ == IOCType.URL else value
        url = f"{self.API}{kind}/{ident}"
        res = await http.get(
            url,
            headers={"x-apikey": self.api_key or "", "Accept": "application/json"},
            accept=frozenset({404}),
            max_bytes=4 * 1024 * 1024,
        )
        if res.status == 404:
            return Outcome("not_found", {"message": "not in VirusTotal"}, query=url, http_status=404)
        doc = load_json(res, "VirusTotal")
        attrs = doc.get("data", {}).get("attributes") if isinstance(doc, dict) else None
        if not isinstance(attrs, dict):
            raise EnrichError("VirusTotal: no data.attributes in response")
        stats = attrs.get("last_analysis_stats") or {}
        mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
        engines = sum(int(v) for v in stats.values() if isinstance(v, int))
        last = attrs.get("last_analysis_date")
        summary: dict[str, Any] = {
            "malicious": mal,
            "suspicious": sus,
            "engines": engines,
            "reputation": attrs.get("reputation"),
            "tags": (attrs.get("tags") or [])[:20],
            "last_analysis": datetime.fromtimestamp(last, UTC).isoformat() if isinstance(last, int) else None,
        }
        if kind == "ip_addresses":
            summary |= {k: attrs.get(k) for k in ("as_owner", "asn", "country", "network")}
        elif kind == "domains":
            summary |= {
                "registrar": attrs.get("registrar"),
                "categories": sorted(set((attrs.get("categories") or {}).values()))[:10],
            }
        elif kind == "urls":
            summary |= {k: attrs.get(k) for k in ("last_final_url", "title")}
        else:
            ptc = attrs.get("popular_threat_classification") or {}
            summary |= {
                "name": attrs.get("meaningful_name"),
                "file_type": attrs.get("type_description"),
                "size": attrs.get("size"),
                "threat_label": ptc.get("suggested_threat_label") if isinstance(ptc, dict) else None,
            }
        ref = f"https://www.virustotal.com/gui/{self.GUI[kind]}/{doc['data'].get('id', ident)}"
        verdicts = f"{mal} of {engines} engines flag it malicious" + (f", {sus} suspicious" if sus else "")
        ev = []
        if mal >= 5:
            ev.append(Evidence("virustotal", "malicious", min(95, 50 + 5 * mal), verdicts, ref))
        elif mal + sus >= 1:
            ev.append(Evidence("virustotal", "suspicious", min(60, 20 + 10 * (mal + sus)), verdicts, ref))
        else:
            ev.append(Evidence("virustotal", "info", 0, verdicts, ref))
        return Outcome("ok", summary, ev, raw=cap_raw(doc), query=url, http_status=res.status)


# ── urlscan.io ───────────────────────────────────────────────────────────────

_SUSPECT_TAG = re.compile(r"phish|malicious|scam|malware|fraud", re.I)


def _es_quote(v: str) -> str:
    return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'


@register
class UrlScan(Enricher):
    info = EnricherInfo(
        name="urlscan",
        title="urlscan.io (public scans)",
        homepage="https://urlscan.io/docs/api/",
        applies_to=frozenset({IOCType.DOMAIN, IOCType.URL}) | IPS,
        mode="passive",  # searches existing public scans; never submits a scan
        third_party=True,
        discloses=False,
        reliability="C",
        reliability_note="Public scans submitted by anyone; tags are the submitter's claim.",
        license="urlscan.io Terms of Service (commercial use needs written permission)",
        license_url="https://urlscan.io/terms/",
        commercial_use=False,
        redistribution=False,
        upstream="urlscan",
        ttl=timedelta(hours=12),
        negative_ttl=timedelta(hours=12),
        verified="2026-10-10",
        key_setting="urlscan_api_key",
        # Observed live 2026-10-10 without a key: 30 searches per minute per IP.
        # Keyed quotas are per account; the response headers keep us honest.
        quotas=(Quota(30, 60),),
        metered=True,
        concurrency=2,
    )

    URL = "https://urlscan.io/api/v1/search/"

    @staticmethod
    def search_for(type_: IOCType, value: str) -> str:
        q = _es_quote(value)
        if type_ == IOCType.DOMAIN:
            return f"page.domain:{q} OR task.domain:{q}"
        if type_ == IOCType.URL:
            return f"page.url:{q} OR task.url:{q}"
        return f"page.ip:{q}"

    async def query(self, http: SafeHttp, type_: IOCType, value: str) -> Outcome:
        q = self.search_for(type_, value)
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["API-Key"] = self.api_key
        res = await http.get(
            self.URL, params={"q": q, "size": "10"}, headers=headers, max_bytes=4 * 1024 * 1024
        )
        doc = load_json(res, "urlscan")
        if not isinstance(doc, dict) or not isinstance(doc.get("results"), list):
            raise EnrichError("urlscan: no results list in response")
        rate = rate_from_headers(
            res.headers, "x-rate-limit-remaining", "x-rate-limit-reset", reset_is_epoch=False
        )
        query = f"{self.URL}?q={q}"
        if not doc["results"]:
            return Outcome("not_found", {"total": 0}, query=query, http_status=res.status, rate=rate)
        scans: list[dict[str, Any]] = []
        tags: list[str] = []
        for r in doc["results"]:
            task, page = r.get("task") or {}, r.get("page") or {}
            scans.append(
                {
                    "time": task.get("time"),
                    "url": task.get("url"),
                    "final_url": page.get("url"),
                    "ip": page.get("ip"),
                    "asn": page.get("asn"),
                    "as_name": page.get("asnname"),
                    "country": page.get("country"),
                    "server": page.get("server"),
                    "title": str(page.get("title") or "")[:200],
                    "status": page.get("status"),
                    "tags": task.get("tags") or [],
                    "link": f"https://urlscan.io/result/{r.get('_id')}/" if r.get("_id") else None,
                }
            )
            tags += [t for t in task.get("tags") or [] if isinstance(t, str) and t not in tags]
        total = doc.get("total", len(scans))
        summary = {
            "total": total,
            "more": bool(doc.get("has_more")),
            "tags": tags[:20],
            "latest": scans[0],
            "scans": scans[:5],
        }
        latest = scans[0]
        bad = [t for t in tags if _SUSPECT_TAG.search(t)]
        ev = []
        if bad:
            ev.append(
                Evidence(
                    "urlscan",
                    "suspicious",
                    35,
                    f"Public scans tagged {', '.join(bad[:3])} by their submitters",
                    latest["link"],
                )
            )
        ev.append(
            Evidence(
                "urlscan",
                "info",
                0,
                f"In {total}{'+' if summary['more'] else ''} public scans; latest {latest['time']} "
                f"served from {latest['ip']} ({latest['as_name']})",
                latest["link"],
            )
        )
        return Outcome("ok", summary, ev, raw=cap_raw(doc), query=query, http_status=res.status, rate=rate)


# ── MalwareBazaar ────────────────────────────────────────────────────────────


@register
class MalwareBazaar(Enricher):
    info = EnricherInfo(
        name="malwarebazaar",
        title="abuse.ch MalwareBazaar",
        homepage="https://bazaar.abuse.ch/api/",
        applies_to=HASHES,
        mode="passive",  # metadata lookup only; samples are never downloaded
        third_party=True,
        discloses=False,
        reliability="B",
        reliability_note="Curated malware sample repository; a hit means the file is a known sample.",
        license="abuse.ch terms (fair use; commercial use needs a subscription)",
        license_url="https://abuse.ch/terms-of-use/",
        commercial_use=False,
        redistribution=False,
        upstream="abusech",
        ttl=timedelta(days=7),
        negative_ttl=timedelta(days=1),
        verified="2026-10-10",
        key_setting="abusech_auth_key",
        key_required=True,
        concurrency=2,
    )

    URL = "https://mb-api.abuse.ch/api/v1/"

    async def query(self, http: SafeHttp, type_: IOCType, value: str) -> Outcome:
        res = await http.post_form(
            self.URL,
            {"query": "get_info", "hash": value},
            headers={"Auth-Key": self.api_key or ""},
            max_bytes=2 * 1024 * 1024,
        )
        doc = load_json(res, "MalwareBazaar")
        status = doc.get("query_status") if isinstance(doc, dict) else None
        query = f"{self.URL} query=get_info hash={value}"
        if status == "hash_not_found":
            return Outcome("not_found", {"query_status": status}, query=query, http_status=res.status)
        data = doc.get("data") if status == "ok" else None
        if not isinstance(data, list) or not data or not isinstance(data[0], dict):
            raise EnrichError(f"MalwareBazaar: query_status {status!r}")
        d = data[0]
        summary = {
            "sha256": d.get("sha256_hash"),
            "md5": d.get("md5_hash"),
            "sha1": d.get("sha1_hash"),
            "file_name": d.get("file_name"),
            "file_type": d.get("file_type"),
            "file_size": d.get("file_size"),
            "signature": d.get("signature"),
            "tags": (d.get("tags") or [])[:20],
            "first_seen": d.get("first_seen"),
            "last_seen": d.get("last_seen"),
            "reporter": d.get("reporter"),
            "delivery_method": d.get("delivery_method"),
        }
        ref = f"https://bazaar.abuse.ch/sample/{summary['sha256']}/" if summary["sha256"] else None
        family = summary["signature"] or "unattributed malware"
        ev = [
            Evidence(
                "malwarebazaar",
                "malicious",
                85,
                f"Known malware sample: {family} ({summary['file_type'] or 'unknown type'}), "
                f"first seen {summary['first_seen']}",
                ref,
            )
        ]
        return Outcome("ok", summary, ev, raw=cap_raw(doc), query=query, http_status=res.status)
