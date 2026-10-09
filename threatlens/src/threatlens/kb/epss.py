"""FIRST EPSS: the daily probability that a CVE is exploited in the next 30 days.

One gzipped CSV holds every scored CVE (~385 k rows). FIRST's docs say the
API is meant for lookups and the CSV for bulk use, so this downloads the CSV
with a conditional GET every 6 hours and updates the CVEs this platform
already tracks; when the file is unchanged, CVEs added since are scored from
the archived copy. It doesn't
create rows: EPSS scores context, it doesn't decide what's relevant.

Format (checked 2026-10-09)::

    #model_version:v2026.06.15,score_date:2026-10-08T12:00:21Z
    cve,epss,percentile
    CVE-1999-0001,0.03351,0.88354
"""

from __future__ import annotations

import csv
import gzip
import io
from datetime import timedelta

from sqlalchemy import select, update

from threatlens.connectors.base import SchemaDriftError, SourceInfo, parse_time
from threatlens.kb.base import KbContext, KbResult, KnowledgeSource, archive, register_kb
from threatlens.models import RawDocument, Vulnerability
from threatlens.rawstore import RawStoreError

EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
_MAX_UNZIPPED = 128 * 1024 * 1024  # ~20 MB today; guards against a decompression bomb


def parse_epss(body: bytes) -> tuple[dict[str, str], dict[str, tuple[float, float]]]:
    """Return (metadata, {CVE: (epss, percentile)})."""
    try:
        raw = gzip.decompress(body) if body[:2] == b"\x1f\x8b" else body
    except (OSError, EOFError) as e:
        raise SchemaDriftError(f"EPSS: not gzip ({e})") from e
    if len(raw) > _MAX_UNZIPPED:
        raise SchemaDriftError(f"EPSS: {len(raw)} bytes unzipped; refusing")
    text = io.StringIO(raw.decode("utf-8"))
    first = text.readline().strip()
    meta: dict[str, str] = {}
    if first.startswith("#"):
        for part in first[1:].split(","):
            k, _, v = part.partition(":")
            meta[k.strip()] = v.strip()
        header = text.readline().strip()
    else:
        header = first
    if header.split(",")[:3] != ["cve", "epss", "percentile"]:
        raise SchemaDriftError(f"EPSS: unexpected header {header[:80]!r}")
    scores: dict[str, tuple[float, float]] = {}
    for row in csv.reader(text):
        if len(row) < 3:
            continue
        try:
            prob, pct = float(row[1]), float(row[2])
        except ValueError:
            continue
        if 0.0 <= prob <= 1.0 and 0.0 <= pct <= 1.0:
            scores[row[0].strip().upper()] = (prob, pct)
    if not scores:
        raise SchemaDriftError("EPSS: no scores parsed")
    return meta, scores


@register_kb
class Epss(KnowledgeSource):
    info = SourceInfo(
        name="epss",
        title="FIRST Exploit Prediction Scoring System (daily CSV)",
        kind="vulnerability",
        homepage="https://www.first.org/epss/",
        url=EPSS_URL,
        reliability="B",
        reliability_note="Model of the 30-day exploitation probability; a strong prior, not proof.",
        license="Published freely by FIRST, no registration; attribution requested in products",
        license_url="https://www.first.org/epss/faq",
        commercial_use=True,
        redistribution=False,  # not addressed by FIRST; treated conservatively
        attribution="EPSS scores by FIRST.org (https://www.first.org/epss/)",
        upstream="first",
        interval=timedelta(hours=6),  # a cheap conditional GET; new CVEs get scored within hours
        min_interval=timedelta(hours=1),
        default_confidence=80,
        max_bytes=32 * 1024 * 1024,
        verified="2026-10-09",
    )

    async def sync(self, ctx: KbContext) -> KbResult:
        r = await ctx.http.get(EPSS_URL, etag=ctx.checkpoint.get("etag"), max_bytes=self.info.max_bytes)
        cp = {**ctx.checkpoint, **({"etag": r.etag} if r.etag else {})}
        if r.not_modified:
            # Same file as last time: CVEs added since then (by NVD, KEV, feeds)
            # still get today's score, read back from the raw archive.
            body = await _latest_archived(ctx)
            if body is None:
                return KbResult(status="not_modified", http_status=304, checkpoint=cp)
            meta, scores = parse_epss(body)
            filled = await _apply(ctx, meta, scores, only_missing=True)
            return KbResult(
                status="not_modified",
                http_status=304,
                items_total=len(scores),
                items_updated=filled,
                checkpoint=cp,
                note=f"unchanged file; scored {filled} new CVE(s) from the archive",
            )
        meta, scores = parse_epss(r.body)
        raw_id = await archive(ctx, r.url, r.body, r.content_type, len(scores))
        updated = await _apply(ctx, meta, scores, only_missing=False)
        cp["model_version"] = meta.get("model_version")
        cp["score_date"] = meta.get("score_date")
        return KbResult(
            items_total=len(scores),
            items_updated=updated,
            http_status=r.status,
            raw_id=raw_id,
            checkpoint=cp,
            note=f"model {meta.get('model_version')}, scores of {meta.get('score_date')}",
        )


async def _latest_archived(ctx: KbContext) -> bytes | None:
    async with ctx.sm() as s:
        doc = await s.scalar(
            select(RawDocument)
            .where(RawDocument.source_id == ctx.source_id)
            .order_by(RawDocument.fetched_at.desc(), RawDocument.id.desc())
            .limit(1)
        )
    if doc is None:
        return None
    try:
        return ctx.store.get(doc.payload_ref, doc.sha256)
    except (OSError, RawStoreError):
        return None


async def _apply(
    ctx: KbContext, meta: dict[str, str], scores: dict[str, tuple[float, float]], *, only_missing: bool
) -> int:
    day = parse_time(meta.get("score_date"))
    async with ctx.sm() as s, s.begin():
        stmt = select(Vulnerability.id, Vulnerability.cve_id)
        if only_missing:
            stmt = stmt.where(Vulnerability.epss.is_(None))
        batch = [
            {
                "id": vid,
                "epss": scores[cve][0],
                "epss_percentile": scores[cve][1],
                "epss_date": day.date() if day else None,
            }
            for vid, cve in (await s.execute(stmt)).all()
            if cve in scores
        ]
        for i in range(0, len(batch), 1000):
            await s.execute(update(Vulnerability), batch[i : i + 1000])
    return len(batch)
