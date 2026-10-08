"""Allowlist engine: keep known-good and own infrastructure out of the
active indicator set.

Entry origins and how they apply (ADR 0003):

=============  =======================================================  ==========
origin         matches                                                   effect
=============  =======================================================  ==========
org_profile    our own domains (and subdomains) and IP ranges            suppress
manual         analyst-added domains (and subdomains) / CIDRs            as entered
tranco         popular registrable domains, exact registrable match      suppress
cloudflare,    CDN edge ranges: one IP serves thousands of sites, so     flag
fastly         blocking it is collateral damage, but malware *is*
               served through CDNs, so it is flagged, not hidden
=============  =======================================================  ==========

URLs and emails on a popular (Tranco) domain are **flagged**, not suppressed:
malware hosted on github.com or a Google Drive link is still malware. Our own
and manually allow-listed domains suppress everything under them.

Tranco matching uses the *private-aware* registrable domain, so
``evil.s3.amazonaws.com`` is not hidden by the popular ``amazonaws.com``.
"""

from __future__ import annotations

import io
import ipaddress
import json
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Literal

from threatlens.ioc.normalize import registrable_domain
from threatlens.ioc.types import IOCType, Observable
from threatlens.net.http import SafeHttp

Effect = Literal["suppress", "flag"]
OWN_ORIGINS = frozenset({"org_profile", "manual"})


@dataclass(frozen=True)
class Entry:
    kind: Literal["domain", "cidr"]
    value: str
    effect: Effect
    reason: str
    origin: str


@dataclass(frozen=True)
class Verdict:
    effect: Effect | None = None
    reasons: tuple[str, ...] = ()
    labels: tuple[str, ...] = ()

    @property
    def suppressed(self) -> bool:
        return self.effect == "suppress"


@dataclass
class _Acc:
    effect: Effect | None = None
    reasons: list[str] = field(default_factory=list)
    labels: list[str] = field(default_factory=list)

    def add(self, effect: Effect, reason: str, label: str | None = None) -> None:
        if effect == "suppress" or self.effect is None:
            self.effect = effect
        if reason not in self.reasons:
            self.reasons.append(reason)
        if label and label not in self.labels:
            self.labels.append(label)

    def verdict(self) -> Verdict:
        return Verdict(self.effect, tuple(self.reasons), tuple(self.labels))


Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class Allowlist:
    def __init__(self, entries: Iterable[Entry]) -> None:
        self._exact: dict[str, Entry] = {}  # tranco: registrable domain → entry
        self._tree: dict[str, Entry] = {}  # own/manual: domain covers subdomains
        # Networks grouped by (version, prefix length): checking an address is
        # one masked lookup per prefix length present, not a scan of every range.
        self._nets: dict[tuple[int, int], dict[int, Entry]] = {}
        self._net_list: list[tuple[Network, Entry]] = []
        for e in entries:
            if e.kind == "domain":
                (self._tree if e.origin in OWN_ORIGINS else self._exact)[e.value.lower()] = e
            else:
                net = ipaddress.ip_network(e.value, strict=False)
                self._nets.setdefault((net.version, net.prefixlen), {})[int(net.network_address)] = e
                self._net_list.append((net, e))

    def __len__(self) -> int:
        return len(self._exact) + len(self._tree) + len(self._net_list)

    def _domain_matches(self, domain: str) -> list[Entry]:
        out = []
        labels = domain.split(".")
        for i in range(len(labels) - 1):
            e = self._tree.get(".".join(labels[i:]))
            if e:
                out.append(e)
        e = self._exact.get(registrable_domain(domain))
        if e:
            out.append(e)
        return out

    def _ip_matches(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> list[Entry]:
        bits = 32 if ip.version == 4 else 128
        out = []
        for (version, plen), table in self._nets.items():
            if version != ip.version:
                continue
            masked = int(ip) & (((1 << plen) - 1) << (bits - plen))
            e = table.get(masked)
            if e:
                out.append(e)
        return out

    def check(self, obs: Observable) -> Verdict:
        acc = _Acc()
        t = obs.type
        if t == IOCType.DOMAIN:
            for e in self._domain_matches(obs.value):
                acc.add(e.effect, e.reason, _label(e))
        elif t in (IOCType.URL, IOCType.EMAIL):
            host = _host(obs)
            try:
                ip = ipaddress.ip_address(host.strip("[]"))
            except ValueError:
                entries = self._domain_matches(host)
            else:
                entries = self._ip_matches(ip)
            for e in entries:
                # Content on a popular or CDN host is still suspect: flag only.
                effect: Effect = e.effect if e.origin in OWN_ORIGINS else "flag"
                acc.add(effect, f"host: {e.reason}", _label(e, host=True))
        elif t in (IOCType.IPV4, IOCType.IPV6):
            for e in self._ip_matches(ipaddress.ip_address(obs.value)):
                acc.add(e.effect, e.reason, _label(e))
        elif t in (IOCType.IPV4_NET, IOCType.IPV6_NET):
            net = ipaddress.ip_network(obs.value)
            for other, e in self._net_list:
                if other.version != net.version:
                    continue
                if net.subnet_of(other):  # type: ignore[arg-type]
                    acc.add(e.effect, e.reason, _label(e))
                elif other.subnet_of(net) and e.origin in OWN_ORIGINS:  # type: ignore[arg-type]
                    # Blocking this range would block us: never let it go active.
                    acc.add("suppress", f"contains own range {other} ({e.reason})", "contains-own-assets")
        return acc.verdict()


def _host(obs: Observable) -> str:
    if obs.type == IOCType.EMAIL:
        return obs.value.rpartition("@")[2]
    rest = obs.value.split("://", 1)[1]
    host = rest.split("/", 1)[0]
    if host.startswith("["):
        return host.split("]", 1)[0] + "]"
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


def _label(e: Entry, host: bool = False) -> str:
    base = {
        "tranco": "popular-domain",
        "cloudflare": "shared-cdn",
        "fastly": "shared-cdn",
        "org_profile": "own-asset",
        "manual": "allowlisted",
    }.get(e.origin, "allowlisted")
    return f"{base}-host" if host and base == "popular-domain" else base


# ── refreshing entries from their sources ────────────────────────────────────

TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
CLOUDFLARE_URLS = ("https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6")
FASTLY_URL = "https://api.fastly.com/public-ip-list"
_MAX_TRANCO_UNZIPPED = 64 * 1024 * 1024  # the full list is ~22 MB


async def fetch_tranco(http: SafeHttp, top: int) -> list[Entry]:
    if top <= 0:
        return []
    r = await http.get(TRANCO_URL, max_bytes=32 * 1024 * 1024)
    with zipfile.ZipFile(io.BytesIO(r.body)) as z:
        info = z.infolist()[0]
        if info.file_size > _MAX_TRANCO_UNZIPPED:  # zip bomb guard
            raise ValueError(f"Tranco archive member is {info.file_size} bytes; refusing")
        entries: list[Entry] = []
        with z.open(info) as f:
            for raw in io.TextIOWrapper(f, encoding="utf-8"):
                rank, _, domain = raw.strip().partition(",")
                if not domain:
                    continue
                entries.append(
                    Entry("domain", domain.lower(), "suppress", f"Tranco top {top} (#{rank})", "tranco")
                )
                if len(entries) >= top:
                    break
    return entries


async def fetch_cloudflare(http: SafeHttp) -> list[Entry]:
    entries = []
    for url in CLOUDFLARE_URLS:
        r = await http.get(url, max_bytes=1024 * 1024)
        for line in r.body.decode().split():
            net = ipaddress.ip_network(line.strip())
            entries.append(Entry("cidr", str(net), "flag", "Cloudflare edge range", "cloudflare"))
    return entries


async def fetch_fastly(http: SafeHttp) -> list[Entry]:
    r = await http.get(FASTLY_URL, max_bytes=1024 * 1024)
    data = json.loads(r.body)
    nets = [*data.get("addresses", []), *data.get("ipv6_addresses", [])]
    return [Entry("cidr", str(ipaddress.ip_network(n)), "flag", "Fastly edge range", "fastly") for n in nets]


def org_profile_entries(domains: Iterable[str], ip_ranges: Iterable[str]) -> list[Entry]:
    out = [Entry("domain", d.lower(), "suppress", "own domain (org profile)", "org_profile") for d in domains]
    out += [Entry("cidr", r, "suppress", "own IP range (org profile)", "org_profile") for r in ip_ranges]
    return out
