"""RIPEstat: the AS announcing an IP and its GeoLite2 location.

Two data calls per IP: ``prefix-overview`` (originating ASN, announced
prefix) and ``maxmind-geo-lite`` (MaxMind GeoLite2 city data served by
RIPEstat, so no MaxMind account or local database is needed; ADR 0005).
RIPEstat allows 8 concurrent requests per IP address and asks regular users
to identify themselves with ``sourceapp``.
"""

from __future__ import annotations

import asyncio
from datetime import timedelta
from typing import Any

from threatlens.enrich.base import (
    IPS,
    Enricher,
    EnricherInfo,
    EnrichError,
    Evidence,
    Outcome,
    load_json,
    register,
)
from threatlens.ioc.types import IOCType
from threatlens.net.http import SafeHttp
from threatlens.settings import get_settings

BASE = "https://stat.ripe.net/data/{}/data.json"


@register
class RipeStat(Enricher):
    info = EnricherInfo(
        name="ripestat",
        title="RIPEstat (ASN and GeoLite2 location)",
        homepage="https://stat.ripe.net/docs/data-api/",
        applies_to=IPS,
        mode="passive",
        third_party=True,
        discloses=False,
        reliability="A",
        reliability_note=(
            "BGP data from RIPE RIS; location is MaxMind GeoLite2 "
            "(country-level is reliable, city often is not)."
        ),
        license="RIPEstat Service Terms and Conditions; GeoLite2 data by MaxMind",
        license_url="https://www.ripe.net/about-us/legal/ripestat-service-terms-and-conditions",
        commercial_use=False,  # needs written permission from the RIPE NCC
        redistribution=False,
        upstream="ripe",
        ttl=timedelta(days=1),
        negative_ttl=timedelta(days=1),
        verified="2026-10-10",
        concurrency=4,  # RIPEstat allows 8 per client IP; leave room for the worker
        auto=True,
        attribution="RIPEstat, RIPE NCC; includes GeoLite2 data created by MaxMind",
    )

    async def _call(self, http: SafeHttp, name: str, resource: str) -> dict[str, Any]:
        res = await http.get(
            BASE.format(name),
            params={"resource": resource, "sourceapp": get_settings().ripestat_sourceapp},
            max_bytes=1024 * 1024,
        )
        doc = load_json(res, f"RIPEstat {name}")
        if not isinstance(doc, dict) or doc.get("status") != "ok" or not isinstance(doc.get("data"), dict):
            raise EnrichError(
                f"RIPEstat {name}: status {doc.get('status') if isinstance(doc, dict) else '?'}"
            )
        data: dict[str, Any] = doc["data"]
        return data

    async def query(self, http: SafeHttp, type_: IOCType, value: str) -> Outcome:
        prefix, geo = await asyncio.gather(
            self._call(http, "prefix-overview", value), self._call(http, "maxmind-geo-lite", value)
        )
        asns = [a for a in prefix.get("asns") or [] if isinstance(a, dict)]
        locations = [
            loc
            for r in geo.get("located_resources") or []
            if isinstance(r, dict)
            for loc in r.get("locations") or []
            if isinstance(loc, dict)
        ]
        loc: dict[str, Any] = locations[0] if locations else {}
        summary = {
            "asn": asns[0].get("asn") if asns else None,
            "as_holder": asns[0].get("holder") if asns else None,
            "prefix": prefix.get("resource"),
            "announced": bool(prefix.get("announced")),
            "country": loc.get("country") or None,
            "city": loc.get("city") or None,
            "latitude": loc.get("latitude"),
            "longitude": loc.get("longitude"),
        }
        query = f"{BASE.format('prefix-overview')}?resource={value} + maxmind-geo-lite"
        if not asns and not loc:
            return Outcome(
                "not_found",
                summary,
                [Evidence("ripestat", "info", 0, "Not announced in BGP and no location data")],
                query=query,
                http_status=200,
                calls=2,
            )
        where = ", ".join(str(x) for x in (summary["city"], summary["country"]) if x) or "location unknown"
        asn = f"AS{summary['asn']} {summary['as_holder']}" if summary["asn"] else "no originating AS"
        evidence = [Evidence("ripestat", "info", 0, f"{asn}; prefix {summary['prefix']}; {where}")]
        if not summary["announced"]:
            evidence.append(Evidence("ripestat", "info", 0, "Prefix is not announced in BGP right now"))
        return Outcome(
            "ok",
            summary,
            evidence,
            raw={"prefix_overview": prefix, "geo": geo},
            query=query,
            http_status=200,
            calls=2,
        )
