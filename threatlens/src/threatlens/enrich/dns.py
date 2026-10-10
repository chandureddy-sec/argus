"""DNS records over HTTPS (Cloudflare's JSON API).

This is an **active** enricher (ADR 0005): resolving a domain makes the
recursive resolver ask the domain's own authoritative servers, which the
owner of a malicious domain can watch. It only runs when a lookup explicitly
asks for active enrichment. Going through DoH keeps every query on the one
hardened HTTP client instead of the host's resolver.
"""

from __future__ import annotations

import asyncio
import ipaddress
from datetime import timedelta
from typing import Any

from threatlens.enrich.base import Enricher, EnricherInfo, EnrichError, Evidence, Outcome, load_json, register
from threatlens.ioc.types import IOCType
from threatlens.net.guard import is_public
from threatlens.net.http import SafeHttp

DOH = "https://cloudflare-dns.com/dns-query"
RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT")
NXDOMAIN = 3


def _answers(doc: dict[str, Any], rtype: str) -> list[str]:
    code = {"A": 1, "AAAA": 28, "MX": 15, "NS": 2, "TXT": 16}[rtype]
    out = []
    for a in doc.get("Answer") or []:
        if isinstance(a, dict) and a.get("type") == code and isinstance(a.get("data"), str):
            out.append(a["data"].rstrip(".") if rtype in ("NS", "MX") else a["data"])
    return out


@register
class Dns(Enricher):
    info = EnricherInfo(
        name="dns",
        title="DNS records (DNS over HTTPS)",
        homepage="https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/",
        applies_to=frozenset({IOCType.DOMAIN}),
        mode="active",
        third_party=True,
        discloses=False,
        reliability="A",
        reliability_note="Live answers from the domain's own name servers, via Cloudflare 1.1.1.1.",
        license="Cloudflare 1.1.1.1 public resolver",
        license_url="https://developers.cloudflare.com/1.1.1.1/privacy/public-dns-resolver/",
        commercial_use=True,
        redistribution=True,
        upstream="dns",
        ttl=timedelta(hours=1),
        negative_ttl=timedelta(hours=1),
        verified="2026-10-10",
        concurrency=4,
    )

    async def _one(self, http: SafeHttp, name: str, rtype: str) -> dict[str, Any]:
        res = await http.get(
            DOH,
            params={"name": name, "type": rtype},
            headers={"Accept": "application/dns-json"},
            max_bytes=256 * 1024,
        )
        doc = load_json(res, "DoH")
        if not isinstance(doc, dict) or "Status" not in doc:
            raise EnrichError("DoH: unexpected response")
        return doc

    async def query(self, http: SafeHttp, type_: IOCType, value: str) -> Outcome:
        docs = await asyncio.gather(*(self._one(http, value, t) for t in RECORD_TYPES))
        query = f"{DOH}?name={value}&type={'|'.join(RECORD_TYPES)}"
        if docs[0].get("Status") == NXDOMAIN:
            return Outcome(
                "not_found",
                {"rcode": "NXDOMAIN"},
                [Evidence("dns", "info", 0, "Domain does not resolve (NXDOMAIN)")],
                query=query,
                http_status=200,
                calls=len(docs),
            )
        records = {t.lower(): _answers(d, t)[:20] for t, d in zip(RECORD_TYPES, docs, strict=True)}
        records["txt"] = [t[:300] for t in records["txt"]]
        evidence = []
        addrs = records["a"] + records["aaaa"]
        odd = []
        for a in addrs:
            try:
                if not is_public(ipaddress.ip_address(a)):
                    odd.append(a)
            except ValueError:
                continue
        if odd:
            evidence.append(
                Evidence(
                    "dns",
                    "info",
                    0,
                    f"Resolves to non-routable {', '.join(odd[:3])}: possibly sinkholed or parked",
                )
            )
        elif addrs:
            evidence.append(
                Evidence("dns", "info", 0, f"Resolves to {len(addrs)} address(es): {', '.join(addrs[:3])}")
            )
        else:
            evidence.append(Evidence("dns", "info", 0, "Domain exists but has no A/AAAA records"))
        return Outcome(
            "ok",
            records,
            evidence,
            raw=[{"type": t, "answer": d.get("Answer")} for t, d in zip(RECORD_TYPES, docs, strict=True)],
            query=query,
            http_status=200,
            calls=len(docs),
        )
