"""OSV.dev: open-source package advisories (GitHub Advisory Database and others)
for the CVEs this platform tracks.

``GET /v1/vulns/{CVE}`` returns OSV's record for the CVE: its aliases
(``GHSA-...``) and, sometimes, affected packages. When the CVE record names
no package but has a GHSA alias, the GHSA record is fetched for the package
list. A 404 means OSV has no open-source advisory for the CVE (normal for
appliance and OS bugs). OSV publishes no rate limit; requests are still
spaced out, and each run handles at most ``TL_OSV_MAX_PER_RUN`` CVEs,
KEV first, then by EPSS. A CVE is checked again after 7 days.
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

from sqlalchemy import or_, select

from threatlens.connectors.base import SchemaDriftError, SourceInfo, clip
from threatlens.kb.base import KbContext, KbResult, KnowledgeSource, register_kb
from threatlens.models import Vulnerability
from threatlens.net.http import FetchError

OSV_API = "https://api.osv.dev/v1/vulns/"
RECHECK = timedelta(days=7)
MAX_PACKAGES = 50


def _packages(rec: dict[str, Any]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for a in rec.get("affected") or []:
        pkg = a.get("package") if isinstance(a, dict) else None
        if not isinstance(pkg, dict) or not pkg.get("name") or not pkg.get("ecosystem"):
            continue
        key = (str(pkg["ecosystem"]), str(pkg["name"]))
        if key in seen:
            continue
        seen.add(key)
        out.append(
            {
                "ecosystem": clip(key[0], 50),
                "name": clip(key[1], 200),
                **({"purl": clip(pkg["purl"], 300)} if pkg.get("purl") else {}),
            }
        )
        if len(out) >= MAX_PACKAGES:
            break
    return out


@register_kb
class Osv(KnowledgeSource):
    info = SourceInfo(
        name="osv",
        title="OSV.dev (GitHub Advisory Database and other OSS advisories)",
        kind="vulnerability",
        homepage="https://osv.dev/",
        url=OSV_API,
        reliability="A",
        reliability_note="Curated open-source advisories; GHSA records are reviewed by GitHub.",
        license="Per upstream database (GHSA: CC-BY 4.0; others vary); only ids and package names kept",
        license_url="https://google.github.io/osv.dev/data/",
        commercial_use=True,
        redistribution=False,  # mixed upstream licences (one is CC-BY-SA); kept conservative
        attribution="OSV.dev and the GitHub Advisory Database (CC-BY 4.0)",
        upstream="osv",
        interval=timedelta(hours=24),
        min_interval=timedelta(hours=1),
        default_confidence=85,
        max_bytes=8 * 1024 * 1024,
        verified="2026-10-09",
    )

    async def _get(self, ctx: KbContext, ident: str) -> dict[str, Any] | None:
        try:
            r = await ctx.http.get(OSV_API + ident, max_bytes=self.info.max_bytes)
        except FetchError as e:
            if e.status == 404:
                return None
            raise
        try:
            rec = json.loads(r.body)
        except ValueError as e:
            raise SchemaDriftError(f"OSV: not JSON ({e})") from e
        if not isinstance(rec, dict) or "id" not in rec:
            raise SchemaDriftError("OSV: record without id")
        return rec

    async def sync(self, ctx: KbContext) -> KbResult:
        res = KbResult(checkpoint=dict(ctx.checkpoint))
        limit = ctx.settings.osv_max_per_run
        if limit == 0:
            res.note = "TL_OSV_MAX_PER_RUN is 0"
            return res
        due_before = ctx.now - RECHECK
        async with ctx.sm() as s:
            cves = (
                await s.scalars(
                    select(Vulnerability.cve_id)
                    .where(
                        or_(Vulnerability.osv_checked_at.is_(None), Vulnerability.osv_checked_at < due_before)
                    )
                    .order_by(Vulnerability.kev.desc(), Vulnerability.epss.desc(), Vulnerability.cve_id)
                    .limit(limit)
                )
            ).all()
        for n, cve in enumerate(cves):
            if n:
                await ctx.sleep(0.2)
            rec = await self._get(ctx, cve)
            ids: list[str] = []
            packages: list[dict[str, str]] = []
            if rec is not None:
                ids = [str(a) for a in rec.get("aliases") or [] if isinstance(a, str)][:20]
                packages = _packages(rec)
                ghsa = next((a for a in ids if a.startswith("GHSA-")), None)
                if not packages and ghsa:
                    alias = await self._get(ctx, ghsa)
                    packages = _packages(alias) if alias else []
            async with ctx.sm() as s, s.begin():
                v = await s.scalar(select(Vulnerability).where(Vulnerability.cve_id == cve))
                if v is None:
                    continue
                changed = (v.osv_ids or []) != ids or (v.packages or []) != packages
                v.osv_ids, v.packages, v.osv_checked_at = ids, packages, ctx.now
            res.items_total += 1
            res.items_updated += int(changed)
        res.note = f"checked {res.items_total} CVE(s)"
        return res
