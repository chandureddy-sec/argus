"""Detection engineering API (Phase 7, ADR 0020).

* ``POST /api/v1/detections/generate`` (analyst): Sigma (+ SPL, KQL, Lucene),
  Suricata, YARA and Wazuh rules from the indicators you may read; also as a
  zip (``/detections/pack.zip``) with the marking in its README.
* ``GET /api/v1/detections/hunts``: the hunt library per ATT&CK technique.
* ``GET /api/v1/detections/navigator/{ref}``: an ATT&CK Navigator layer for
  an actor, malware, tool or campaign.
* ``/detections/inventory`` (import: analyst) and ``/detections/coverage``:
  our own Sigma rules against the techniques that matter to us.
* ``/detections/retro``: retro-hunt packs for new high-priority indicators.
"""

from __future__ import annotations

import io
import json
import zipfile
from typing import Annotated, Any, Literal

from fastapi import APIRouter, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import delete, select

from threatlens import tlp as tlp_rules
from threatlens.api.v1 import Analyst, Viewer, _app_settings, _sm
from threatlens.detect import attack, hunts, retro
from threatlens.detect import rules as gen
from threatlens.kb import graph
from threatlens.models import AuditLog, DetectionRule, Entity, Indicator, RetroHunt
from threatlens.models import Observable as ObsRow

router = APIRouter(prefix="/api/v1/detections", tags=["detections"])
MAX_IOCS = 20_000
MAX_UPLOAD = 5 * 1024 * 1024
Format = Literal["sigma", "suricata", "yara", "wazuh"]


class GenerateIn(BaseModel):
    min_score: float = Field(default=60.0, ge=0, le=100)
    max_tlp: Literal["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"] = "TLP:GREEN"
    types: list[str] = Field(default_factory=list, max_length=10)
    formats: list[Format] = Field(default=["sigma", "suricata", "yara", "wazuh"], min_length=1)


async def _iocs(request: Request, who: Any, body: GenerateIn) -> list[gen.Ioc]:
    cap = body.max_tlp if tlp_rules.rank(body.max_tlp) <= tlp_rules.rank(who.clearance) else who.clearance
    levels = list(tlp_rules.readable(cap))
    stmt = (
        select(Indicator, ObsRow)
        .join(ObsRow, ObsRow.id == Indicator.observable_id)
        .where(
            Indicator.status == "active",
            Indicator.priority_score >= body.min_score,
            Indicator.tlp.in_(levels),
        )
    )
    if body.types:
        stmt = stmt.where(ObsRow.type.in_(body.types))
    async with _sm(request)() as s:
        rows = (await s.execute(stmt.order_by(Indicator.priority_score.desc()).limit(MAX_IOCS))).all()
        return await retro.iocs(s, [(i, o) for i, o in rows])


async def _generate(request: Request, who: Any, body: GenerateIn) -> list[gen.Rule]:
    found = await _iocs(request, who, body)
    settings = _app_settings(request)
    out: list[gen.Rule] = []
    try:
        if "sigma" in body.formats:
            out += gen.sigma_rules(found, author=settings.org_identity, base_url=settings.public_url)
        if "suricata" in body.formats:
            out += gen.suricata_rules(found, author=settings.org_identity)
        if "yara" in body.formats:
            out += gen.yara_rules(found, author=settings.org_identity)
        if "wazuh" in body.formats:
            out.append(gen.wazuh_rules(settings.org_identity))
    except gen.RuleError as e:  # a generator bug: say so plainly, never ship the rule
        raise HTTPException(500, f"a generated rule failed its syntax check: {e}") from e
    async with _sm(request)() as s, s.begin():
        s.add(
            AuditLog(
                actor=who.name[:100],
                action="detections.generate",
                target="detections",
                details={
                    "min_score": body.min_score,
                    "max_tlp": body.max_tlp,
                    "formats": body.formats,
                    "indicators": len(found),
                    "rules": len(out),
                },
            )
        )
    return out


@router.post("/generate")
async def generate(who: Analyst, request: Request, body: GenerateIn) -> dict[str, Any]:
    rules = await _generate(request, who, body)
    return {"count": len(rules), "rules": [r.view() for r in rules]}


@router.get("/pack.zip")
async def pack(
    who: Analyst,
    request: Request,
    min_score: Annotated[float, Query(ge=0, le=100)] = 60.0,
    max_tlp: Annotated[str, Query(max_length=20)] = "TLP:GREEN",
    formats: Annotated[str, Query(max_length=60)] = "sigma,suricata,yara,wazuh",
) -> Response:
    body = GenerateIn(
        min_score=min_score,
        max_tlp=max_tlp,
        formats=[f for f in formats.split(",") if f in ("sigma", "suricata", "yara", "wazuh")] or ["sigma"],
    )
    rules = await _generate(request, who, body)
    marking = "TLP:CLEAR"
    for r in rules:
        marking = tlp_rules.stricter(marking, r.meta.tlp)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for r in rules:
            z.writestr(f"{r.kind}/{r.name}", r.body)
            if r.kind == "sigma":
                for backend, q in r.queries.items():
                    if q:
                        z.writestr(f"{r.kind}/{backend}/{r.name.rsplit('.', 1)[0]}.txt", q + "\n")
        z.writestr(
            "README.txt",
            (
                f"{marking}\n\nArgus detection pack: {len(rules)} rules "
                f"from indicators scoring {min_score:g}+.\n"
                "Folders: sigma (+ splunk, kql, lucene conversions), suricata, yara, wazuh.\n"
                "Review before enabling; every rule lists its false positives.\n"
                f"Handle under {marking}: the rules contain the indicator values.\n"
            ),
        )
    return Response(
        buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="argus-detections.zip"'},
    )


@router.get("/hunts")
async def hunt_library(
    who: Viewer, technique: Annotated[str | None, Query(max_length=20)] = None
) -> list[dict[str, Any]]:
    lib = hunts.for_techniques({technique}) if technique else list(hunts.library())
    return lib


@router.get("/navigator/{ref}")
async def navigator(who: Viewer, request: Request, ref: str) -> Response:
    async with _sm(request)() as s:
        node = await graph.resolve(s, ref, clearance=who.clearance)
        if node is None or node.kind != "entity":
            raise HTTPException(404, "no such actor, malware, tool or campaign")
        ent = await s.scalar(select(Entity).where(Entity.stix_id == node.ref))
        if ent is None:
            raise HTTPException(404, "no such entity")
        layer = await attack.entity_layer(s, ent)
    name = (ent.external_id or ent.name).replace(" ", "_")[:60]
    return Response(
        json.dumps(layer, indent=1),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{name}_layer.json"'},
    )


# ── inventory and coverage ───────────────────────────────────────────────────


@router.post("/inventory")
async def import_inventory(
    who: Analyst, request: Request, files: Annotated[list[UploadFile] | None, File()] = None
) -> dict[str, Any]:
    """Sigma rules from the SOC's repository: .yml/.yaml files, or zips of them."""
    if not files:
        raise HTTPException(422, "attach .yml/.yaml Sigma rules or a zip of them")
    texts: list[tuple[str, str]] = []
    total = 0
    for f in files[:200]:
        data = await f.read(MAX_UPLOAD + 1)
        total += len(data)
        if len(data) > MAX_UPLOAD or total > 4 * MAX_UPLOAD:
            raise HTTPException(413, "upload at most 5 MB per file and 20 MB in all")
        name = f.filename or "upload"
        if name.lower().endswith(".zip"):
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    for info in z.infolist()[:5000]:
                        if info.filename.lower().endswith((".yml", ".yaml")) and info.file_size <= MAX_UPLOAD:
                            texts.append((info.filename, z.read(info).decode("utf-8", "replace")))
            except zipfile.BadZipFile as e:
                raise HTTPException(422, f"{name}: not a zip file") from e
        else:
            texts.append((name, data.decode("utf-8", "replace")))
    records, errors = attack.parse_inventory(texts)
    async with _sm(request)() as s, s.begin():
        result = await attack.import_rules(s, records, actor=who.name)
    return {**result, "rules": len(records), "errors": errors[:50]}


@router.get("/inventory")
async def inventory(who: Viewer, request: Request) -> list[dict[str, Any]]:
    async with _sm(request)() as s:
        rows = (await s.scalars(select(DetectionRule).order_by(DetectionRule.title))).all()
    return [
        {
            "id": r.id,
            "origin": r.origin,
            "title": r.title,
            "status": r.status,
            "level": r.level,
            "logsource": r.logsource,
            "techniques": r.techniques,
        }
        for r in rows
    ]


@router.delete("/inventory", status_code=204)
async def clear_inventory(who: Analyst, request: Request) -> Response:
    async with _sm(request)() as s, s.begin():
        await s.execute(delete(DetectionRule).where(DetectionRule.origin == "imported"))
        s.add(AuditLog(actor=who.name[:100], action="detections.clear", target="detection_rules", details={}))
    return Response(status_code=204)


@router.get("/coverage")
async def coverage(who: Viewer, request: Request) -> dict[str, Any]:
    async with _sm(request)() as s:
        return await attack.coverage(s, _app_settings(request), who.clearance)


# ── retro-hunts ──────────────────────────────────────────────────────────────


@router.get("/retro")
async def retro_packs(who: Viewer, request: Request) -> list[dict[str, Any]]:
    async with _sm(request)() as s:
        rows = (
            await s.scalars(
                select(RetroHunt)
                .where(RetroHunt.tlp.in_(tlp_rules.readable(who.clearance)))
                .order_by(RetroHunt.created_at.desc())
                .limit(50)
            )
        ).all()
    return [retro.view(p) for p in rows]


@router.post("/retro/run")
async def retro_run(who: Analyst, request: Request) -> dict[str, Any]:
    pack_id = await retro.build(_sm(request), _app_settings(request))
    return {"created": pack_id}
