"""Vulnerability records: NVD parsing, stubs, KEV flags, exploit signals.

A CVE row is created as soon as anything names it: a KEV entry, a feed
indicator, an ATT&CK description. NVD fills in the details later, EPSS
adds a probability, and OSV adds package-level advisories. Every source
writes its own columns, so a refresh from one never erases another's data.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from threatlens.connectors.base import SchemaDriftError, clip, parse_time
from threatlens.db import upsert_insert
from threatlens.kb.ids import is_cve, vulnerability_stix_id
from threatlens.models import (
    Indicator,
    Observable,
    Sighting,
    Source,
    Vulnerability,
    VulnerabilityProduct,
)

# Highest CVSS version first. Within a version NVD's own ("Primary") score
# wins over the CNA's ("Secondary").
_CVSS_KEYS = (
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)
MAX_CPES = 200
MAX_REFS = 50
MAX_EXPLOIT_REFS = 20


def _date(value: object) -> date | None:
    dt = parse_time(value)
    return dt.date() if dt else None


@dataclass
class NvdRecord:
    cve_id: str
    values: dict[str, Any]
    products: set[tuple[str, str, str]] = field(default_factory=set)


def parse_cpe(criteria: str) -> tuple[str, str, str] | None:
    """'cpe:2.3:o:fortinet:fortios:7.0.1:*:…' → ('o', 'fortinet', 'fortios')."""
    parts = criteria.split(":")
    if len(parts) < 5 or parts[0] != "cpe" or parts[2] not in ("a", "o", "h"):
        return None
    vendor, product = parts[3].lower(), parts[4].lower()
    if vendor in ("*", "-", "") or product in ("*", "-", ""):
        return None
    return parts[2], vendor[:200], product[:200]


def parse_nvd(cve: Mapping[str, Any]) -> NvdRecord:
    """Map one NVD API 2.0 ``cve`` object onto vulnerability columns."""
    if not isinstance(cve.get("id"), str) or not is_cve(cve["id"]):
        raise SchemaDriftError(f"NVD: record without a CVE id: {str(cve.get('id'))[:40]!r}")
    cve_id = cve["id"].upper()
    desc = next(
        (d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"),
        "",
    )

    metrics = cve.get("metrics") or {}
    scores: list[dict[str, Any]] = []
    for key, version in _CVSS_KEYS:
        for m in metrics.get(key) or []:
            data = m.get("cvssData") or {}
            scores.append(
                {
                    "version": data.get("version", version),
                    "source": clip(m.get("source"), 100),
                    "type": m.get("type"),
                    "score": data.get("baseScore"),
                    "severity": data.get("baseSeverity") or m.get("baseSeverity"),
                    "vector": data.get("vectorString"),
                }
            )
    best = None
    for _, version in _CVSS_KEYS:
        same = [x for x in scores if x["version"] == version and x["score"] is not None]
        if same:
            best = next((x for x in same if x["type"] == "Primary"), same[0])
            break

    ssvc: dict[str, Any] = {}
    for m in metrics.get("ssvcV203") or []:
        data = m.get("ssvcData") or {}
        for opt in data.get("options") or []:
            if isinstance(opt, dict):
                ssvc.update({k: v for k, v in opt.items() if isinstance(v, str)})
        if ssvc:
            ssvc["role"] = data.get("role")
            ssvc["timestamp"] = data.get("timestamp")
            break

    cwes: list[str] = []
    for w in cve.get("weaknesses") or []:
        for d in w.get("description") or []:
            v = d.get("value", "")
            if v.startswith("CWE-") and v not in cwes:
                cwes.append(v)

    cpes: list[str] = []
    products: set[tuple[str, str, str]] = set()
    for cfg in cve.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable"):
                    continue
                crit = match.get("criteria", "")
                p = parse_cpe(crit)
                if p:
                    products.add(p)
                if crit and crit not in cpes and len(cpes) < MAX_CPES:
                    cpes.append(crit)

    refs: list[dict[str, Any]] = []
    exploit: list[str] = []
    for r in cve.get("references") or []:
        url = r.get("url")
        if not isinstance(url, str) or not url.startswith(("https://", "http://")):
            continue
        tags = [t for t in r.get("tags") or [] if isinstance(t, str)]
        if len(refs) < MAX_REFS:
            refs.append({"url": url[:2000], "tags": tags})
        if "Exploit" in tags and len(exploit) < MAX_EXPLOIT_REFS:
            exploit.append(url[:2000])

    values: dict[str, Any] = {
        "description": desc,
        "published": parse_time(cve.get("published")),
        "nvd_modified": parse_time(cve.get("lastModified")),
        "vuln_status": clip(cve.get("vulnStatus"), 32) or None,
        "cvss_version": best["version"] if best else None,
        "cvss_score": float(best["score"]) if best else None,
        "cvss_severity": best["severity"] if best else None,
        "cvss_vector": best["vector"] if best else None,
        "cvss": scores,
        "cwes": cwes,
        "cpes": cpes,
        "references": refs,
        "exploit_refs": exploit,
        "ssvc": ssvc,
    }
    if cve.get("cisaExploitAdd"):
        values.update(
            kev=True,
            kev_date_added=_date(cve.get("cisaExploitAdd")),
            kev_due_date=_date(cve.get("cisaActionDue")),
            kev_name=clip(cve.get("cisaVulnerabilityName"), 300) or None,
            kev_required_action=clip(cve.get("cisaRequiredAction"), 500) or None,
        )
    return NvdRecord(cve_id, values, products)


async def ensure_stubs(s: AsyncSession, cves: Iterable[str]) -> dict[str, int]:
    """Make sure a row exists for each CVE; returns cve_id → row id."""
    wanted = sorted({c.upper() for c in cves if is_cve(c)})
    out: dict[str, int] = {}
    for i in range(0, len(wanted), 500):
        chunk = wanted[i : i + 500]
        await s.execute(
            upsert_insert(s, Vulnerability)
            .values(
                [
                    {
                        "cve_id": c,
                        "stix_id": vulnerability_stix_id(c),
                        "description": "",
                        "cvss": [],
                        "cwes": [],
                        "cpes": [],
                        "references": [],
                        "exploit_refs": [],
                        "ssvc": {},
                        "kev": False,
                        "osv_ids": [],
                        "packages": [],
                        "created_at": datetime.now(UTC),
                        "updated_at": datetime.now(UTC),
                    }
                    for c in chunk
                ]
            )
            .on_conflict_do_nothing(index_elements=["cve_id"])
        )
        rows = await s.execute(
            select(Vulnerability.cve_id, Vulnerability.id).where(Vulnerability.cve_id.in_(chunk))
        )
        out.update({c: i for c, i in rows.all()})  # noqa: C416
    return out


async def upsert_nvd(s: AsyncSession, records: Sequence[NvdRecord]) -> tuple[int, int]:
    """Write NVD columns (and products) for each record; returns (new, updated)."""
    if not records:
        return 0, 0
    existing = set(
        (
            await s.scalars(
                select(Vulnerability.cve_id).where(Vulnerability.cve_id.in_([r.cve_id for r in records]))
            )
        ).all()
    )
    ids = await ensure_stubs(s, [r.cve_id for r in records])
    rows = {
        v.id: v
        for v in (
            await s.scalars(select(Vulnerability).where(Vulnerability.id.in_(list(ids.values()))))
        ).all()
    }
    for r in records:
        v = rows[ids[r.cve_id]]
        for k, val in r.values.items():
            setattr(v, k, val)
        v.updated_at = datetime.now(UTC)
    vids = [ids[r.cve_id] for r in records]
    old = {
        (p.vulnerability_id, p.part, p.vendor, p.product): p
        for p in (
            await s.scalars(
                select(VulnerabilityProduct).where(VulnerabilityProduct.vulnerability_id.in_(vids))
            )
        ).all()
    }
    want = {(ids[r.cve_id], *p) for r in records for p in r.products}
    for key, p in old.items():
        if key not in want:
            await s.delete(p)
    for key in want - set(old):
        s.add(VulnerabilityProduct(vulnerability_id=key[0], part=key[1], vendor=key[2], product=key[3]))
    new = sum(1 for r in records if r.cve_id not in existing)
    return new, len(records) - new


async def apply_kev(sm: async_sessionmaker[AsyncSession]) -> int:
    """Copy CISA KEV facts from the KEV connector's sightings onto CVE rows.

    The KEV connector (Phase 1) already collects the catalogue as indicators,
    so the knowledge base reads it from there instead of downloading it again.
    Returns how many rows were created or changed."""
    changed = 0
    async with sm() as s, s.begin():
        rows = (
            await s.execute(
                select(Observable.value, Sighting.first_seen, Sighting.context)
                .join(Indicator, Indicator.observable_id == Observable.id)
                .join(Sighting, Sighting.indicator_id == Indicator.id)
                .join(Source, Source.id == Sighting.source_id)
                .where(Source.name == "cisa_kev", Observable.type == "vulnerability")
            )
        ).all()
        ids = await ensure_stubs(s, [r[0] for r in rows])
        vulns = {
            v.cve_id: v
            for v in (
                await s.scalars(select(Vulnerability).where(Vulnerability.id.in_(list(ids.values()))))
            ).all()
        }
        for cve, first_seen, ctx in rows:
            v = vulns.get(cve.upper())
            if v is None:
                continue
            ctx = ctx or {}
            before = (v.kev, v.kev_date_added, v.kev_due_date, v.kev_ransomware)
            v.kev = True
            v.kev_date_added = v.kev_date_added or (first_seen.date() if first_seen else None)
            v.kev_due_date = _date(ctx.get("due_date")) or v.kev_due_date
            v.kev_ransomware = clip(ctx.get("ransomware_use"), 16) or v.kev_ransomware
            v.kev_name = v.kev_name or (clip(ctx.get("name"), 300) or None)
            v.kev_required_action = v.kev_required_action or (clip(ctx.get("required_action"), 500) or None)
            if not v.description and ctx.get("description"):
                v.description = clip(ctx.get("description"), 2000)
            if not v.cwes and isinstance(ctx.get("cwes"), list):
                v.cwes = [c for c in ctx["cwes"] if isinstance(c, str)][:20]
            if before != (v.kev, v.kev_date_added, v.kev_due_date, v.kev_ransomware):
                changed += 1
    return changed


def exploit_signals(v: Vulnerability) -> list[dict[str, Any]]:
    """Evidence that a CVE is being exploited or is easy to exploit, each
    with its source. Computed on read, so it never goes stale."""
    out: list[dict[str, Any]] = []
    if v.kev:
        out.append(
            {
                "signal": "exploited-in-the-wild",
                "source": "cisa_kev",
                "detail": f"added to KEV {v.kev_date_added.isoformat()}" if v.kev_date_added else "in KEV",
            }
        )
    if v.kev_ransomware == "Known":
        out.append(
            {"signal": "ransomware-use", "source": "cisa_kev", "detail": "known ransomware campaign use"}
        )
    exploitation = (v.ssvc or {}).get("exploitation")
    if exploitation in ("active", "poc"):
        out.append(
            {
                "signal": "exploitation-active" if exploitation == "active" else "proof-of-concept",
                "source": "cisa-adp-ssvc",
                "detail": f"SSVC exploitation: {exploitation}",
            }
        )
    if v.exploit_refs:
        out.append(
            {
                "signal": "public-exploit-reference",
                "source": "nvd",
                "detail": f"{len(v.exploit_refs)} reference(s) tagged Exploit",
                "urls": v.exploit_refs[:3],
            }
        )
    return out
