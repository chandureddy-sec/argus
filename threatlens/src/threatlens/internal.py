"""Local-only lookup for internal (private, reserved) IP addresses.

Threat intel has nothing to say about 10.0.0.5 or 192.168.1.1: millions of
networks use them, so providers and feeds only judge public addresses, and
sending an internal address out would describe your network to them. The
normalizer therefore refuses these addresses as indicators (ADR 0002).

This module answers the question an analyst actually has instead: what is
this address, and does anything we hold mention it? It reads only our own
data and never calls a provider:

* the range it belongs to and what that means (RFC 1918, CGNAT, loopback, ...);
* public DNS names from our ReconX scans that resolve to it: an internal
  address published in public DNS leaks the network layout;
* other scanned names pointing into the same /24 (IPv4) or /64 (IPv6);
* cases that mention it, within the reader's clearance.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any

from sqlalchemy import String, cast, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from threatlens import cases as cases_mod
from threatlens.ioc.defang import refang
from threatlens.models import Asset, Case, CaseItem
from threatlens.net.guard import is_public

IP = ipaddress.IPv4Address | ipaddress.IPv6Address

# Most specific first; the first range that contains the address names it.
_RANGES: list[tuple[str, str, str, str]] = [
    # (network, label, standard, what it means)
    (
        "0.0.0.0/8",
        "This network",
        "RFC 1122",
        "Means 'this host' or 'any address'; it never appears on a wire.",
    ),
    (
        "10.0.0.0/8",
        "Private network",
        "RFC 1918",
        "Used inside an organisation; not reachable from the internet.",
    ),
    (
        "100.64.0.0/10",
        "Carrier-grade NAT",
        "RFC 6598",
        "Shared address space an ISP uses between its NAT and customers.",
    ),
    ("127.0.0.0/8", "Loopback", "RFC 1122", "The machine itself; traffic never leaves the host."),
    (
        "169.254.0.0/16",
        "Link-local",
        "RFC 3927",
        "Self-assigned when DHCP fails (APIPA); also cloud metadata (169.254.169.254).",
    ),
    (
        "172.16.0.0/12",
        "Private network",
        "RFC 1918",
        "Used inside an organisation; not reachable from the internet.",
    ),
    ("192.0.0.0/24", "IETF protocol assignments", "RFC 6890", "Reserved for protocol use."),
    ("192.0.2.0/24", "Documentation (TEST-NET-1)", "RFC 5737", "Only for examples in documentation."),
    (
        "192.168.0.0/16",
        "Private network",
        "RFC 1918",
        "Used inside an organisation; not reachable from the internet.",
    ),
    ("198.18.0.0/15", "Benchmarking", "RFC 2544", "Reserved for network device testing."),
    ("198.51.100.0/24", "Documentation (TEST-NET-2)", "RFC 5737", "Only for examples in documentation."),
    ("203.0.113.0/24", "Documentation (TEST-NET-3)", "RFC 5737", "Only for examples in documentation."),
    ("224.0.0.0/4", "Multicast", "RFC 5771", "One-to-many delivery inside a network; not a single host."),
    ("255.255.255.255/32", "Broadcast", "RFC 919", "Every host on the local network segment."),
    ("240.0.0.0/4", "Reserved", "RFC 1112", "Reserved for future use; not routed."),
    ("::/128", "Unspecified", "RFC 4291", "Means 'no address'; it never appears on a wire."),
    ("::1/128", "Loopback", "RFC 4291", "The machine itself; traffic never leaves the host."),
    ("64:ff9b::/96", "NAT64", "RFC 6052", "An IPv4 address carried inside IPv6 by a NAT64 gateway."),
    ("100::/64", "Discard-only", "RFC 6666", "Traffic sent here is dropped."),
    ("2001:db8::/32", "Documentation", "RFC 3849", "Only for examples in documentation."),
    (
        "fc00::/7",
        "Unique local",
        "RFC 4193",
        "IPv6's private range: used inside an organisation, not routed.",
    ),
    (
        "fe80::/10",
        "Link-local",
        "RFC 4291",
        "Valid only on one network segment; every IPv6 interface has one.",
    ),
    ("ff00::/8", "Multicast", "RFC 4291", "One-to-many delivery inside a network; not a single host."),
]
_NETS = [(ipaddress.ip_network(n), label, std, note) for n, label, std, note in _RANGES]


@dataclass(frozen=True)
class Internal:
    ip: IP
    network: str
    label: str
    standard: str
    note: str


def classify(raw: str) -> Internal | None:
    """The address and its range if *raw* is a single non-public IP, else None."""
    text = refang(raw.strip()).strip().strip("[]")
    try:
        ip = ipaddress.ip_address(text.split("%", 1)[0])  # drop an IPv6 zone id
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped  # ::ffff:10.0.0.5 is 10.0.0.5
    if is_public(ip):
        return None
    for net, label, std, note in _NETS:
        if net.version == ip.version and ip in net:
            return Internal(ip, str(net), label, std, note)
    return Internal(
        ip, str(ip), "Not routed on the internet", "", "Reserved or special-purpose address space."
    )


def _mentions(text: str, ip: str) -> bool:
    """True if *ip* appears in *text* as a whole address (10.0.0.1 is not 10.0.0.12)."""
    return re.search(rf"(?<![\w.:]){re.escape(ip)}(?![\w:]|\.\d)", refang(text)) is not None


def _subnet(ip: IP) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    return ipaddress.ip_network(f"{ip}/{24 if ip.version == 4 else 64}", strict=False)


async def lookup(s: AsyncSession, raw: str, clearance: str) -> dict[str, Any] | None:
    """Everything we hold about an internal address; None if it isn't one."""
    found = classify(raw)
    if found is None:
        return None
    ip, addr = found.ip, str(found.ip)
    subnet = _subnet(ip)

    # Scanned public names that resolve into the address's subnet. The JSON text
    # prefilter keeps this to a few rows; the exact check happens in Python.
    prefix = addr.rsplit(".", 1)[0] + "." if ip.version == 4 else addr.split(":")[0]
    rows = (
        await s.execute(
            select(Asset)
            .where(Asset.kind == "host", cast(Asset.details, String).like(f"%{prefix}%"))
            .limit(500)
        )
    ).scalars()
    exact: list[dict[str, Any]] = []
    nearby: list[dict[str, Any]] = []
    for a in rows:
        ips = [x for x in (a.details or {}).get("ips") or [] if isinstance(x, str)]
        parsed = []
        for x in ips:
            try:
                parsed.append(ipaddress.ip_address(x))
            except ValueError:
                continue
        entry = {"name": a.value, "target": a.target, "assetId": a.id, "lastSeen": a.last_seen}
        if ip in parsed:
            exact.append(entry)
        elif hits := sorted(str(x) for x in parsed if x.version == ip.version and x in subnet):
            nearby.append({**entry, "ips": hits[:4]})

    # Cases (within clearance) whose title, summary, conclusion or items mention it.
    likes = [f"%{addr}%", f"%{addr.replace('.', '[.]')}%"] if ip.version == 4 else [f"%{addr}%"]

    def mention(col: Any) -> Any:
        return or_(*(col.like(x) for x in likes))

    item_hit = select(CaseItem.case_id).where(
        or_(mention(CaseItem.ref), mention(CaseItem.label), mention(CaseItem.note))
    )
    found_cases = (
        await s.execute(
            select(Case)
            .where(
                cases_mod.visible(clearance),
                or_(
                    mention(Case.title),
                    mention(Case.summary),
                    mention(Case.conclusion),
                    Case.id.in_(item_hit),
                ),
            )
            .order_by(Case.updated_at.desc())
            .limit(50)
        )
    ).scalars()
    case_rows = []
    for c in found_cases:
        texts = [c.title, c.summary, c.conclusion]
        items = (await s.execute(select(CaseItem).where(CaseItem.case_id == c.id))).scalars().all()
        texts += [t for i in items for t in (i.ref, i.label, i.note)]
        if any(_mentions(t or "", addr) for t in texts):  # LIKE also matches 10.0.0.12 for 10.0.0.1
            case_rows.append(
                {"id": c.id, "title": c.title, "status": c.status, "severity": c.severity, "tlp": c.tlp}
            )
        if len(case_rows) >= 20:
            break

    return {
        "address": addr,
        "version": ip.version,
        "range": {
            "network": found.network,
            "label": found.label,
            "standard": found.standard,
            "note": found.note,
        },
        "subnet": str(subnet),
        "publicNames": exact[:50],
        "nearbyNames": nearby[:20],
        "cases": case_rows,
    }
