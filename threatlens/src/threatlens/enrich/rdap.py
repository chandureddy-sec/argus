"""RDAP: who registered a domain, and which network an IP belongs to.

RDAP (RFC 9082/9083) replaced WHOIS with JSON over HTTPS. There is no single
server: IANA publishes bootstrap files mapping TLDs and address ranges to the
authoritative registry, which we cache for a day (RFC 9224). Domains are
looked up by registrable domain (registries don't know subdomains).
"""

from __future__ import annotations

import ipaddress
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

from threatlens.enrich.base import (
    IPS,
    Enricher,
    EnricherInfo,
    EnrichError,
    Evidence,
    Outcome,
    cap_raw,
    load_json,
    parse_dt,
    register,
)
from threatlens.ioc.normalize import registrable_domain
from threatlens.ioc.types import IOCType
from threatlens.net.http import SafeHttp

BOOTSTRAP = "https://data.iana.org/rdap/{}.json"
BOOTSTRAP_TTL_S = 24 * 3600
NEW_DOMAIN_DAYS = 30


def _vcard(entity: dict[str, Any], prop: str) -> str | None:
    card = entity.get("vcardArray")
    if not isinstance(card, list) or len(card) < 2 or not isinstance(card[1], list):
        return None
    for item in card[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == prop and isinstance(item[3], str):
            return item[3]
    return None


def _entities(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """Top-level entities plus one level of nesting (abuse contacts often sit
    under the registrar or registrant)."""
    out: list[dict[str, Any]] = []
    for e in doc.get("entities") or []:
        if isinstance(e, dict):
            out.append(e)
            out += [x for x in e.get("entities") or [] if isinstance(x, dict)]
    return out


def _by_role(doc: dict[str, Any], role: str, prop: str = "fn") -> str | None:
    for e in _entities(doc):
        if role in (e.get("roles") or []):
            v = _vcard(e, prop)
            if v:
                return v
    return None


def _events(doc: dict[str, Any]) -> dict[str, datetime]:
    out = {}
    for ev in doc.get("events") or []:
        if isinstance(ev, dict):
            dt = parse_dt(ev.get("eventDate"))
            if dt and isinstance(ev.get("eventAction"), str):
                out[ev["eventAction"]] = dt
    return out


def _https(urls: list[Any]) -> str | None:
    for u in urls:
        if isinstance(u, str) and u.startswith("https://"):
            return u if u.endswith("/") else u + "/"
    return None


@register
class Rdap(Enricher):
    info = EnricherInfo(
        name="rdap",
        title="RDAP (registration data)",
        homepage="https://www.iana.org/assignments/rdap-dns/",
        applies_to=frozenset({IOCType.DOMAIN}) | IPS,
        mode="passive",
        third_party=True,
        discloses=False,
        reliability="A",
        reliability_note="Authoritative registry and RIR records; registrant details are often redacted.",
        license="Registry terms of use (returned in each response's notices)",
        license_url="https://www.icann.org/rdap",
        commercial_use=True,
        redistribution=False,
        upstream="registries",
        ttl=timedelta(days=7),
        negative_ttl=timedelta(days=1),
        verified="2026-10-10",
        concurrency=4,
    )

    _bootstrap: dict[str, tuple[float, list[Any]]] = {}  # noqa: RUF012 - process-wide cache

    async def _services(self, http: SafeHttp, kind: str) -> list[Any]:
        hit = self._bootstrap.get(kind)
        if hit and time.monotonic() - hit[0] < BOOTSTRAP_TTL_S:
            return hit[1]
        doc = load_json(await http.get(BOOTSTRAP.format(kind), max_bytes=2 * 1024 * 1024), f"IANA {kind}")
        services = doc.get("services") if isinstance(doc, dict) else None
        if not isinstance(services, list):
            raise EnrichError(f"IANA {kind} bootstrap: no services list")
        self._bootstrap[kind] = (time.monotonic(), services)
        return services

    async def _base_for_domain(self, http: SafeHttp, domain: str) -> str | None:
        labels = domain.split(".")
        best: tuple[int, str] | None = None
        for entry in await self._services(http, "dns"):
            tlds, urls = entry[0], entry[1]
            base = _https(urls)
            for tld in tlds:
                n = tld.count(".") + 1
                if ".".join(labels[-n:]) == tld.lower() and base and (best is None or n > best[0]):
                    best = (n, base)
        return best[1] if best else None

    async def _base_for_ip(
        self, http: SafeHttp, ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    ) -> str | None:
        kind = "ipv4" if ip.version == 4 else "ipv6"
        best: tuple[int, str] | None = None
        for entry in await self._services(http, kind):
            base = _https(entry[1])
            for cidr in entry[0]:
                net = ipaddress.ip_network(cidr, strict=False)
                if ip in net and base and (best is None or net.prefixlen > best[0]):
                    best = (net.prefixlen, base)
        return best[1] if best else None

    async def query(self, http: SafeHttp, type_: IOCType, value: str) -> Outcome:
        if type_ == IOCType.DOMAIN:
            name = registrable_domain(value)
            base = await self._base_for_domain(http, name)
            path = f"domain/{quote(name)}"
        else:
            ip = ipaddress.ip_address(value)
            base = await self._base_for_ip(http, ip)
            path = f"ip/{ip}"
        if base is None:
            return Outcome("not_found", {"reason": "no RDAP service for this TLD or range"}, calls=0)
        url = base + path
        res = await http.get(
            url,
            headers={"Accept": "application/rdap+json"},
            accept=frozenset({404}),
            max_bytes=2 * 1024 * 1024,
        )
        if res.status == 404:
            return Outcome(
                "not_found",
                {"queried": name if type_ == IOCType.DOMAIN else value},
                query=url,
                http_status=404,
            )
        doc = load_json(res, "RDAP")
        if not isinstance(doc, dict):
            raise EnrichError("RDAP: unexpected response")
        if type_ == IOCType.DOMAIN:
            summary, evidence = self._domain(doc)
        else:
            summary, evidence = self._network(doc)
        return Outcome("ok", summary, evidence, raw=cap_raw(doc), query=url, http_status=res.status)

    def _domain(self, doc: dict[str, Any]) -> tuple[dict[str, Any], list[Evidence]]:
        ev = _events(doc)
        created = ev.get("registration")
        age = (datetime.now(UTC) - created).days if created else None
        status = [s for s in doc.get("status") or [] if isinstance(s, str)]
        summary = {
            "domain": str(doc.get("ldhName", "")).lower(),
            "registrar": _by_role(doc, "registrar"),
            "registrant": _by_role(doc, "registrant"),
            "abuse_email": _by_role(doc, "abuse", "email"),
            "created": created.isoformat() if created else None,
            "expires": ev["expiration"].isoformat() if "expiration" in ev else None,
            "updated": ev["last changed"].isoformat() if "last changed" in ev else None,
            "age_days": age,
            "status": status,
            "nameservers": sorted(
                str(n.get("ldhName", "")).lower() for n in doc.get("nameservers") or [] if isinstance(n, dict)
            ),
        }
        out = []
        if age is not None and age < NEW_DOMAIN_DAYS:
            out.append(
                Evidence("rdap", "suspicious", 30, f"Domain registered {age} days ago (newly registered)")
            )
        elif age is not None:
            out.append(
                Evidence(
                    "rdap",
                    "info",
                    0,
                    f"Domain registered {age} days ago via {summary['registrar'] or 'unknown registrar'}",
                )
            )
        holds = [s for s in status if "hold" in s]
        if holds:
            out.append(
                Evidence(
                    "rdap", "info", 0, f"Registry status {', '.join(holds)}: often follows an abuse takedown"
                )
            )
        return summary, out

    def _network(self, doc: dict[str, Any]) -> tuple[dict[str, Any], list[Evidence]]:
        cidrs = []
        for c in doc.get("cidr0_cidrs") or []:
            if isinstance(c, dict) and c.get("length") is not None:
                cidrs.append(f"{c.get('v4prefix') or c.get('v6prefix')}/{c['length']}")
        org = _by_role(doc, "registrant") or _by_role(doc, "administrative")
        summary = {
            "handle": doc.get("handle"),
            "name": doc.get("name"),
            "range": f"{doc.get('startAddress')} - {doc.get('endAddress')}",
            "cidrs": cidrs,
            "type": doc.get("type"),
            "country": doc.get("country"),
            "organization": org,
            "abuse_email": _by_role(doc, "abuse", "email"),
        }
        where = ", ".join(cidrs) or summary["range"]
        text = f"Network {summary['name']} ({org or 'organization not given'}), {where}"
        return summary, [Evidence("rdap", "info", 0, text)]
