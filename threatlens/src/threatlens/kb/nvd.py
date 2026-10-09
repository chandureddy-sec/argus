"""NVD API 2.0: CVE details (CVSS, CWE, CPE, references, CISA KEV fields).

What gets mirrored (``TL_NVD_SCOPE``):

* ``relevant`` (default): a first run fetches every KEV CVE (``hasKev``);
  each tech-stack CPE from the org profile gets one full pass
  (``virtualMatchString``), also when added later. Later runs read NVD's change feed
  (``lastModStartDate``/``lastModEndDate``, at most 120 days per query) and
  keep the changes that matter: CVEs already known here, KEV CVEs, and CVEs
  matching the stack. Then they fill in stub rows (CVEs named by feeds or
  ATT&CK) one ``cveId`` request at a time.
* ``all``: the same, but every changed CVE is kept, building a full mirror.

Pacing: without a key NVD allows few requests per rolling 30 s window, so
requests are spaced 6.5 s apart (0.7 s with a key), and each run stops at
``TL_NVD_MAX_REQUESTS``. A run that stops early keeps its checkpoint, so
the next run resumes where it left off.
"""

from __future__ import annotations

import json
from datetime import UTC, timedelta
from typing import Any
from urllib.parse import urlencode

from sqlalchemy import select

from threatlens.connectors.base import SchemaDriftError, SourceInfo, parse_time, require
from threatlens.kb.base import (
    BudgetExhaustedError,
    KbContext,
    KbResult,
    KnowledgeSource,
    archive,
    register_kb,
)
from threatlens.kb.vulns import NvdRecord, parse_nvd, upsert_nvd
from threatlens.logs import get_logger
from threatlens.models import Vulnerability
from threatlens.net.http import FetchError
from threatlens.profile import ProfileError, load_profile
from threatlens.settings import Settings

log = get_logger("threatlens.kb.nvd")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE = 2000  # NVD's maximum resultsPerPage
MAX_WINDOW = timedelta(days=120)  # NVD's maximum lastMod range
MISSING_RETRY = timedelta(days=7)
_TS = "%Y-%m-%dT%H:%M:%S.000Z"


def stack_cpes(settings: Settings) -> list[tuple[str, str, str]]:
    """(cpe prefix for virtualMatchString, vendor, product) for each tech-stack item."""
    try:
        org = load_profile(settings.profile_path).org
    except (ProfileError, OSError) as e:
        log.warning("nvd.no_profile", error=str(e)[:200])
        return []
    out = []
    for t in org.tech_stack:
        parts = t.cpe.split(":")
        if len(parts) >= 5 and parts[3] not in ("*", "") and parts[4] not in ("*", ""):
            out.append((":".join(parts[:5]), parts[3], parts[4]))
    return out


class _Pager:
    """Paced, budgeted NVD requests; every page body is archived."""

    def __init__(self, ctx: KbContext, api_key: str | None) -> None:
        self.ctx = ctx
        self.api_key = api_key
        self.pace = 0.7 if api_key else 6.5
        self.budget = ctx.settings.nvd_max_requests
        self.used = 0

    async def get(self, params: dict[str, str]) -> dict[str, Any]:
        if self.used >= self.budget:
            raise BudgetExhaustedError(f"used {self.used} NVD requests")
        if self.used:
            await self.ctx.sleep(self.pace)
        self.used += 1
        headers = {"apiKey": self.api_key} if self.api_key else {}
        try:
            r = await self.ctx.http.get(NVD_URL, params=params, headers=headers, max_bytes=64 * 1024 * 1024)
        except FetchError as e:
            if e.status == 404 and self.api_key:
                raise FetchError("NVD answered 404: the API key is probably invalid", 404) from e
            raise
        try:
            doc: dict[str, Any] = json.loads(r.body)
        except ValueError as e:
            raise SchemaDriftError(f"NVD: not JSON ({e})") from e
        require(doc, "totalResults", "vulnerabilities", where="NVD response")
        await archive(
            self.ctx, f"{NVD_URL}?{urlencode(params)}", r.body, r.content_type, len(doc["vulnerabilities"])
        )
        return doc

    async def pages(self, params: dict[str, str]) -> Any:
        start = 0
        while True:
            doc = await self.get({**params, "resultsPerPage": str(PAGE), "startIndex": str(start)})
            yield [parse_nvd(v["cve"]) for v in doc["vulnerabilities"] if "cve" in v]
            start += len(doc["vulnerabilities"])
            if not doc["vulnerabilities"] or start >= int(doc["totalResults"]):
                return


@register_kb
class Nvd(KnowledgeSource):
    info = SourceInfo(
        name="nvd",
        title="NIST National Vulnerability Database (API 2.0)",
        kind="vulnerability",
        homepage="https://nvd.nist.gov/",
        url=NVD_URL,
        reliability="A",
        reliability_note="Authoritative CVE enrichment (CVSS, CWE, CPE) by NIST; analysis can lag.",
        license="US government work (no copyright); NVD asks for a non-endorsement notice",
        license_url="https://nvd.nist.gov/developers/terms-of-use",
        commercial_use=True,
        redistribution=True,
        attribution="This product uses the NVD API but is not endorsed or certified by the NVD.",
        upstream="nist",
        interval=timedelta(hours=2),
        min_interval=timedelta(hours=2),
        default_confidence=90,
        key_setting="nvd_api_key",
        key_required=False,
        verified="2026-10-09",
    )

    async def sync(self, ctx: KbContext) -> KbResult:
        pager = _Pager(ctx, self.api_key)
        cp = dict(ctx.checkpoint)
        res = KbResult(checkpoint=cp)
        stack = stack_cpes(ctx.settings)
        try:
            if not cp.get("baseline_done"):  # the KEV catalogue, once
                await self._ingest_all(ctx, pager, {"hasKev": ""}, res)
                cp["baseline_done"] = True
                cp["last_mod"] = ctx.now.isoformat()
            else:
                await self._changes(ctx, pager, cp, stack, res)
            # Each tech-stack CPE gets one full pass, including CPEs added to the
            # profile later. Progress is kept per CPE, so a run that runs out of
            # budget resumes instead of starting over.
            done = set(cp.get("stack_done") or [])
            for prefix, _, _ in stack:
                if prefix not in done:
                    await self._ingest_all(ctx, pager, {"virtualMatchString": prefix}, res)
                    done.add(prefix)
                    cp["stack_done"] = sorted(done)
            await self._stubs(ctx, pager, cp, res)
        except BudgetExhaustedError as e:
            res.status = "partial"
            res.note = f"{e}; continuing next run"
        return res

    async def _ingest_all(self, ctx: KbContext, pager: _Pager, params: dict[str, str], res: KbResult) -> None:
        async for records in pager.pages(params):
            await self._write(ctx, records, res)

    async def _write(self, ctx: KbContext, records: list[NvdRecord], res: KbResult) -> None:
        async with ctx.sm() as s, s.begin():
            new, upd = await upsert_nvd(s, records)
        res.items_total += len(records)
        res.items_new += new
        res.items_updated += upd

    async def _changes(
        self,
        ctx: KbContext,
        pager: _Pager,
        cp: dict[str, Any],
        stack: list[tuple[str, str, str]],
        res: KbResult,
    ) -> None:
        start = parse_time(cp.get("last_mod")) or ctx.now - timedelta(days=1)
        end = ctx.now
        if end - start > MAX_WINDOW:
            res.note = f"change feed gap: skipped changes before {(end - MAX_WINDOW).date()}"
            start = end - MAX_WINDOW
        params = {
            "lastModStartDate": start.astimezone(UTC).strftime(_TS),
            "lastModEndDate": end.astimezone(UTC).strftime(_TS),
        }
        wanted = {(v, p) for _, v, p in stack}
        keep_all = ctx.settings.nvd_scope == "all"
        async for records in pager.pages(params):
            if not keep_all:
                async with ctx.sm() as s:
                    known = set(
                        (
                            await s.scalars(
                                select(Vulnerability.cve_id).where(
                                    Vulnerability.cve_id.in_([r.cve_id for r in records])
                                )
                            )
                        ).all()
                    )
                records = [
                    r
                    for r in records
                    if r.cve_id in known
                    or r.values.get("kev")
                    or any((v, p) in wanted for _, v, p in r.products)
                ]
            await self._write(ctx, records, res)
        cp["last_mod"] = end.isoformat()  # only after every page arrived

    async def _stubs(self, ctx: KbContext, pager: _Pager, cp: dict[str, Any], res: KbResult) -> None:
        missing: dict[str, str] = dict(cp.get("missing") or {})
        retry_after = ctx.now - MISSING_RETRY
        skip = {c for c, when in missing.items() if (parse_time(when) or ctx.now) > retry_after}
        async with ctx.sm() as s:
            stubs = (
                await s.scalars(
                    select(Vulnerability.cve_id)
                    .where(Vulnerability.nvd_modified.is_(None))
                    .order_by(Vulnerability.kev.desc(), Vulnerability.epss.desc(), Vulnerability.cve_id)
                    .limit(pager.budget + len(skip))
                )
            ).all()
        for cve in stubs:
            if cve in skip:
                continue
            doc = await pager.get({"cveId": cve})
            records = [parse_nvd(v["cve"]) for v in doc["vulnerabilities"] if "cve" in v]
            if records:
                missing.pop(cve, None)
                await self._write(ctx, records, res)
            else:  # reserved, rejected or not yet in NVD: ask again in a week
                missing[cve] = ctx.now.isoformat()
            cp["missing"] = missing
