"""Own assets, imported from ReconX scans (Phase 3b, ADR 0006).

A ReconX scan of one of the organization's domains knows what is really
deployed: the hosts that resolve, their IPs, and the software Shodan saw on
them (CPEs). Importing it gives ThreatLens two things the hand-written org
profile can't keep current:

* **assets**: feeds that list one of our own hosts or IPs are the strongest
  signal there is (compromise, abuse, or a shared IP), so lookups say "own
  asset" and the assets page puts them first. Assets are watched, never
  allowlisted: hiding them would hide exactly those cases.
* an **observed tech stack**: PIR-2 ("vulnerabilities in our stack") and the
  NVD scope use the profile's tech stack *plus* what was observed.

Only scans of the organization's own targets should be imported; ReconX
sends them only with ``--threatlens-assets``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import unquote

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from threatlens.connectors.base import clip, parse_time
from threatlens.ioc.normalize import normalize
from threatlens.ioc.types import IOCType, Observable
from threatlens.kb.nvd import stack_cpes
from threatlens.models import Asset, AssetImport, AssetProduct, AuditLog, Indicator, Sighting, Source
from threatlens.models import Observable as ObsRow
from threatlens.settings import Settings

MAX_HOSTS = 20_000
MAX_IPS = 20_000
_CPE_PART = re.compile(r"^[a-z0-9._\-~%+!]{1,200}$")
SHODAN = "shodan-internetdb (via reconx)"


class ImportFormatError(ValueError):
    """The document is not a ReconX scan report this importer understands."""


def parse_cpe(raw: str) -> tuple[str, str, str, str | None, str] | None:
    """(part, vendor, product, version, CPE 2.3 string) from a CPE 2.2 URI
    (``cpe:/a:nginx:nginx:1.18.0``, what Shodan reports) or a CPE 2.3 string.
    Anything else, or wildcards in vendor/product, gives None."""
    s = raw.strip().lower()
    if s.startswith("cpe:2.3:"):
        fields = s.split(":")[2:]
    elif s.startswith("cpe:/"):
        fields = [unquote(f) for f in s[5:].split(":")]
    else:
        return None
    if len(fields) < 3 or fields[0] not in ("a", "o", "h"):
        return None
    part, vendor, product = fields[0], fields[1], fields[2]
    version = fields[3] if len(fields) > 3 and fields[3] not in ("", "*", "-") else None
    for f in (vendor, product):
        if f in ("", "*", "-") or not _CPE_PART.match(f):
            return None
    if version is not None and not _CPE_PART.match(version):
        version = None
    cpe23 = f"cpe:2.3:{part}:{vendor}:{product}:{version or '*'}"
    return part, vendor, product, version, cpe23


@dataclass
class ImportSummary:
    target: str
    scanned_at: datetime | None
    duplicate: bool = False
    import_id: int | None = None
    hosts: int = 0
    ips: int = 0
    products: int = 0
    new_assets: int = 0
    updated_assets: int = 0
    rejected: list[dict[str, str]] = field(default_factory=list)


@dataclass
class _Found:
    obs: Observable
    kind: str
    details: dict[str, Any]
    products: list[tuple[str, str, str, str | None, str]] = field(default_factory=list)


def _str(v: object, n: int = 200) -> str | None:
    return clip(v, n) if isinstance(v, str) and v else None


def _strs(v: object, n: int = 20) -> list[str]:
    return [clip(x, 200) for x in v[:n] if isinstance(x, str)] if isinstance(v, list) else []


def read_reconx(doc: Any) -> tuple[str, str, datetime | None, list[_Found], list[dict[str, str]]]:
    """Parse a ReconX ``ScanReport`` JSON document; raises ImportFormatError."""
    if not isinstance(doc, dict) or not isinstance(doc.get("target"), dict):
        raise ImportFormatError("not a ReconX scan report: no 'target' object")
    target, ttype = doc["target"].get("value"), doc["target"].get("type")
    if not isinstance(target, str) or ttype not in ("domain", "ipv4", "ipv6"):
        raise ImportFormatError("only scans of a domain or an IP can be imported as assets")
    pi = doc.get("passive_intel")
    pi = {} if pi is None else pi
    if not isinstance(pi, dict):
        raise ImportFormatError("'passive_intel' must be an object")
    hosts = [] if pi.get("hosts") is None else pi["hosts"]
    ips = [] if pi.get("ips") is None else pi["ips"]
    if not isinstance(hosts, list) or not isinstance(ips, list):
        raise ImportFormatError("'passive_intel.hosts' and '.ips' must be lists")
    if len(hosts) > MAX_HOSTS or len(ips) > MAX_IPS:
        raise ImportFormatError(f"too large: at most {MAX_HOSTS} hosts and {MAX_IPS} IPs per scan")

    found: list[_Found] = []
    rejected: list[dict[str, str]] = []
    skipped: list[dict[str, str]] = []

    def add(t: IOCType, value: str, kind: str, details: dict[str, Any]) -> _Found | None:
        r = normalize(t, value)
        if not isinstance(r, Observable):
            rejected.append({"value": clip(value, 200), "reason": r.reason})
            return None
        f = _Found(r, kind, {k: v for k, v in details.items() if v not in (None, "", [], {})})
        found.append(f)
        return f

    if ttype == "domain":
        add(IOCType.DOMAIN, target, "domain", {"role": "scan target"})
    else:
        add(IOCType.IPV4 if ttype == "ipv4" else IOCType.IPV6, target, "ip", {"role": "scan target"})
    for h in hosts:
        if not isinstance(h, dict) or not isinstance(h.get("hostname"), str):
            continue
        if h.get("dns_status") != "resolves":
            continue  # gone or never live: not a running asset
        add(
            IOCType.DOMAIN,
            h["hostname"],
            "host",
            {
                "ips": _strs(h.get("ips")),
                "asn": _str(h.get("asn")),
                "organization": _str(h.get("organization")),
                "country": _str(h.get("country"), 64),
                "cloud": _str(h.get("cloud")),
                "cdn": _str(h.get("cdn")),
                "role": _str(h.get("role")),
                "lifecycle": _str(h.get("lifecycle"), 32),
                "sources": _strs(h.get("sources")),
            },
        )
    # Only addresses our live hosts resolve to (or the scanned IP) are ours.
    # ReconX's IP list also holds the domain's name and mail servers (usually
    # a provider's), and a shared CDN edge serves thousands of sites: a feed
    # listing one says nothing about our servers, and its software isn't our
    # stack.
    served = {
        ip
        for h in hosts
        if isinstance(h, dict) and h.get("dns_status") == "resolves"
        for ip in _strs(h.get("ips"), 100)
    }
    if ttype in ("ipv4", "ipv6"):
        served.add(target)
    for ip in ips:
        if not isinstance(ip, dict) or not isinstance(ip.get("ip"), str):
            continue
        if ip["ip"] not in served:
            skipped.append(
                {
                    "value": clip(ip["ip"], 200),
                    "reason": "not an address of a scanned host (name/mail server)",
                }
            )
            continue
        if ip.get("provider_kind") == "cdn" and ip["ip"] != target:
            skipped.append(
                {
                    "value": clip(ip["ip"], 200),
                    "reason": f"shared CDN edge ({_str(ip.get('provider')) or 'CDN'})",
                }
            )
            continue
        exposure: dict[str, Any] = ip["exposure"] if isinstance(ip.get("exposure"), dict) else {}
        version = IOCType.IPV6 if ":" in ip["ip"] else IOCType.IPV4
        ports = [p for p in exposure.get("ports") or [] if isinstance(p, int)][:100]
        f = add(
            version,
            ip["ip"],
            "ip",
            {
                "asn": _str(ip.get("asn")),
                "as_name": _str(ip.get("as_name")),
                "country": _str(ip.get("country"), 64),
                "provider": _str(ip.get("provider")),
                "provider_kind": _str(ip.get("provider_kind"), 32),
                "hostnames": _strs(ip.get("hostnames")),
                "ports": ports,
                "shodan_tags": _strs(exposure.get("tags")),
            },
        )
        if f is None:
            continue
        for raw in exposure.get("cpes") or []:
            p = parse_cpe(raw) if isinstance(raw, str) else None
            if p and p[4] not in {x[4] for x in f.products}:
                f.products.append(p)
    # Duplicates (the apex is often also a resolving host): keep the richer entry.
    merged: dict[str, _Found] = {}
    for f in found:
        old = merged.get(f.obs.key)
        if old is None:
            merged[f.obs.key] = f
        else:
            old.details = {**f.details, **old.details}
            old.products += [p for p in f.products if p[4] not in {x[4] for x in old.products}]
    return target.lower(), ttype, parse_time(doc.get("timestamp")), list(merged.values()), rejected + skipped


async def import_reconx(
    sm: async_sessionmaker[AsyncSession], doc: Any, sha256: str, actor: str, now: datetime | None = None
) -> ImportSummary:
    """Import one ReconX scan. Re-importing the same file changes nothing."""
    target, _, scanned_at, found, rejected = read_reconx(doc)
    when = scanned_at or now or datetime.now(UTC)
    summary = ImportSummary(target=target, scanned_at=scanned_at, rejected=rejected[:100])
    summary.hosts = sum(1 for f in found if f.kind in ("domain", "host"))
    summary.ips = sum(1 for f in found if f.kind == "ip")
    summary.products = sum(len(f.products) for f in found)
    async with sm() as s, s.begin():
        dup = await s.scalar(select(AssetImport).where(AssetImport.sha256 == sha256))
        if dup is not None:
            summary.duplicate, summary.import_id = True, dup.id
            return summary
        imp = AssetImport(
            source="reconx",
            target=target,
            scanned_at=scanned_at,
            sha256=sha256,
            imported_by=actor[:100],
            counts={},
        )
        s.add(imp)
        await s.flush()
        existing = {
            a.canonical_key: a
            for a in (
                await s.scalars(select(Asset).where(Asset.canonical_key.in_([f.obs.key for f in found])))
            ).all()
        }
        for f in found:
            a = existing.get(f.obs.key)
            if a is None:
                a = Asset(
                    kind=f.kind,
                    value=f.obs.value,
                    canonical_key=f.obs.key,
                    target=target,
                    origin="reconx",
                    details=f.details,
                    first_seen=when,
                    last_seen=when,
                    last_import_id=imp.id,
                )
                s.add(a)
                summary.new_assets += 1
            else:
                last = a.last_seen if a.last_seen.tzinfo else a.last_seen.replace(tzinfo=UTC)
                if when >= last:  # an older scan never overwrites newer facts
                    a.details, a.last_seen, a.last_import_id, a.target = f.details, when, imp.id, target
                summary.updated_assets += 1
            await s.flush()
            have = {
                p.cpe: p
                for p in (await s.scalars(select(AssetProduct).where(AssetProduct.asset_id == a.id))).all()
            }
            for part, vendor, product, version, cpe in f.products:
                row = have.get(cpe)
                if row is None:
                    s.add(
                        AssetProduct(
                            asset_id=a.id,
                            cpe=cpe,
                            part=part,
                            vendor=vendor,
                            product=product,
                            version=version,
                            source=SHODAN,
                            first_seen=when,
                            last_seen=when,
                        )
                    )
                else:
                    row.last_seen = max(
                        row.last_seen if row.last_seen.tzinfo else row.last_seen.replace(tzinfo=UTC), when
                    )
        imp.counts = {
            "hosts": summary.hosts,
            "ips": summary.ips,
            "products": summary.products,
            "new": summary.new_assets,
            "updated": summary.updated_assets,
            "rejected": len(rejected),
        }
        s.add(
            AuditLog(
                actor=actor[:100],
                action="assets.import",
                target=f"reconx:{target}",
                details={"sha256": sha256, **imp.counts},
            )
        )
        summary.import_id = imp.id
    return summary


# ── read side ────────────────────────────────────────────────────────────────


async def observed_stack(s: AsyncSession) -> list[tuple[str, str, str]]:
    """(CPE 2.3 prefix, vendor, product) for every product seen on an asset."""
    rows = (
        await s.execute(select(AssetProduct.part, AssetProduct.vendor, AssetProduct.product).distinct())
    ).all()
    return sorted((f"cpe:2.3:{p}:{v}:{pr}", v, pr) for p, v, pr in rows)


async def org_stack(s: AsyncSession, settings: Settings) -> list[tuple[str, str, str]]:
    """The org profile's tech stack plus the observed one, deduplicated."""
    out: dict[tuple[str, str], tuple[str, str, str]] = {}
    for prefix, vendor, product in stack_cpes(settings) + await observed_stack(s):
        out.setdefault((vendor, product), (prefix, vendor, product))
    return list(out.values())


async def asset_for(s: AsyncSession, key: str) -> dict[str, Any] | None:
    a = await s.scalar(select(Asset).where(Asset.canonical_key == key))
    if a is None:
        return None
    return {
        "kind": a.kind,
        "target": a.target,
        "origin": a.origin,
        "first_seen": a.first_seen if a.first_seen.tzinfo else a.first_seen.replace(tzinfo=UTC),
        "last_seen": a.last_seen if a.last_seen.tzinfo else a.last_seen.replace(tzinfo=UTC),
        "details": a.details,
    }


def _flag_join() -> Any:
    return and_(ObsRow.canonical_key == Asset.canonical_key)


async def flagged_keys(s: AsyncSession) -> dict[str, dict[str, Any]]:
    """Assets that are also indicators: canonical key → indicator facts."""
    rows = (
        await s.execute(
            select(Asset.canonical_key, Indicator.id, Indicator.status, Indicator.confidence)
            .join(ObsRow, _flag_join())
            .join(Indicator, Indicator.observable_id == ObsRow.id)
        )
    ).all()
    out: dict[str, dict[str, Any]] = {}
    for key, ind_id, status, conf in rows:
        out[key] = {"indicator_id": ind_id, "status": status, "confidence": conf, "sources": []}
    if out:
        ids = {v["indicator_id"]: k for k, v in out.items()}
        for ind_id, name in (
            await s.execute(
                select(Sighting.indicator_id, Source.name)
                .join(Source)
                .where(Sighting.indicator_id.in_(list(ids)))
            )
        ).all():
            out[ids[ind_id]]["sources"].append(name)
    return out


async def counts(s: AsyncSession) -> dict[str, int]:
    rows = dict((await s.execute(select(Asset.kind, func.count()).group_by(Asset.kind))).all())
    flagged = await flagged_keys(s)
    return {
        "domains": int(rows.get("domain", 0)),
        "hosts": int(rows.get("host", 0)),
        "ips": int(rows.get("ip", 0)),
        "flagged": sum(1 for v in flagged.values() if v["status"] in ("active", "new")),
        "products": int(await s.scalar(select(func.count(func.distinct(AssetProduct.cpe)))) or 0),
    }
