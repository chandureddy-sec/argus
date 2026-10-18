"""STIX 2.1 objects for what we share (ADR 0019).

* Indicators keep the deterministic id they were given at ingestion
  (``indicator--uuid5(canonical key)``), so a consumer that receives the same
  indicator twice updates it instead of duplicating it. ``modified`` moves
  with every change; an analyst false positive is re-sent with
  ``revoked: true``.
* TLP uses the **TLP 2.0** marking definitions published by OASIS
  (cti-stix-common-objects, extension
  ``extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d``, verified
  2026-10-18). A bundle carries the definitions it references.
* The producer is one ``identity`` (Settings.org_identity) with a stable id.
* Malware, actors and campaigns an indicator ``indicates`` go along as minimal
  SDOs plus the ``relationship``, when the source that asserted the link
  allows redistribution.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from threatlens.models import Entity, Relationship, Source
from threatlens.share.select import Row, aware

TLP2_EXTENSION = "extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d"
TLP2: dict[str, tuple[str, str]] = {
    "TLP:CLEAR": ("marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487", "clear"),
    "TLP:GREEN": ("marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb", "green"),
    "TLP:AMBER": ("marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421", "amber"),
    "TLP:AMBER+STRICT": ("marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003", "amber+strict"),
    "TLP:RED": ("marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1", "red"),
}
# TLP 1.0 ids (STIX 2.1 §7.2.1.4) still used by many producers; read-side only.
TLP1: dict[str, str] = {
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9": "TLP:CLEAR",
    "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": "TLP:GREEN",
    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": "TLP:AMBER",
    "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed": "TLP:RED",
}
MARKING_TLP: dict[str, str] = {**TLP1, **{mid: lv for lv, (mid, _) in TLP2.items()}}
_NS = uuid.UUID("2f2a3c55-4f5e-4a8f-9a77-6b0f6f9b1d10")
SHAREABLE_ENTITY_TYPES = ("malware", "intrusion-set", "threat-actor", "campaign", "tool")


def ts(v: datetime | None) -> str | None:
    """STIX timestamps: UTC, millisecond precision, Z suffix."""
    if v is None:
        return None
    return aware(v).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.") + f"{aware(v).microsecond // 1000:03d}Z"


def marking(tlp: str) -> dict[str, Any]:
    mid, name = TLP2[tlp]
    return {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": mid,
        "created": "2022-10-01T00:00:00.000Z",
        "name": tlp,
        "extensions": {TLP2_EXTENSION: {"extension_type": "property-extension", "tlp_2_0": name}},
    }


def identity(name: str) -> dict[str, Any]:
    return {
        "type": "identity",
        "spec_version": "2.1",
        "id": f"identity--{uuid.uuid5(_NS, 'identity:' + name)}",
        "created": "2026-10-18T00:00:00.000Z",
        "modified": "2026-10-18T00:00:00.000Z",
        "name": name,
        "identity_class": "organization",
    }


def _indicator_types(row: Row) -> list[str]:
    if row.ind.status == "false_positive":
        return ["benign"]
    return ["malicious-activity"] if (row.ind.priority_score or 0) >= 60 else ["anomalous-activity"]


def _describe(row: Row) -> str:
    if row.ind.status == "false_positive":
        return "Withdrawn: an analyst found this value is not malicious."
    names = ", ".join(sorted(src.title for src in row.sources)) or "our analysts"
    return f"Priority {round(row.ind.priority_score or 0)}/100, reported by {names}."


def indicator(row: Row, producer_id: str) -> dict[str, Any]:
    """One indicator. ``revoked`` signals an analyst false positive."""
    ind, obs = row.ind, row.obs
    created = aware(ind.created_at)
    modified = max(aware(ind.updated_at), created)
    valid_from = aware(ind.valid_from)
    out: dict[str, Any] = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": ind.stix_id,
        "created_by_ref": producer_id,
        "created": ts(created),
        "modified": ts(modified),
        "name": f"{obs.type}: {obs.defanged}",
        "description": _describe(row),
        "indicator_types": _indicator_types(row),
        "pattern": ind.pattern,
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": ts(valid_from),
        "confidence": max(0, min(100, round(ind.priority_score or 0))),
        "object_marking_refs": [TLP2[ind.tlp][0]],
    }
    if ind.valid_until and aware(ind.valid_until) > valid_from:
        out["valid_until"] = ts(ind.valid_until)
    labels = [str(lb)[:100] for lb in (ind.labels or []) if str(lb).strip()][:20]
    if labels:
        out["labels"] = labels
    refs = [
        {"source_name": src.title, "url": src.homepage} if src.homepage else {"source_name": src.title}
        for src in sorted(row.sources, key=lambda x: x.name)
        if src.redistribution
    ]
    if refs:
        out["external_references"] = refs
    if ind.status == "false_positive":
        out["revoked"] = True
    return out


async def related(s: AsyncSession, rows: Sequence[Row]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(entity SDOs, relationships) for the ``indicates`` links of ``rows``
    that a redistributable source (or ATT&CK) asserted."""
    by_ref = {r.ind.stix_id: r for r in rows if r.ind.stix_id}
    if not by_ref:
        return [], []
    rels = (
        await s.execute(
            select(Relationship, Source.redistribution)
            .outerjoin(Source, Source.id == Relationship.source_id)
            .where(
                Relationship.src_ref.in_(list(by_ref)),
                Relationship.rel_type == "indicates",
                Relationship.revoked.is_(False),
                or_(Relationship.origin == "attack", Source.redistribution.is_(True)),
            )
        )
    ).all()
    targets = {r.dst_ref for r, _ in rels}
    ents = {
        e.stix_id: e
        for e in (
            await s.scalars(
                select(Entity).where(
                    Entity.stix_id.in_(list(targets)), Entity.type.in_(SHAREABLE_ENTITY_TYPES)
                )
            )
        ).all()
    }
    sdos = [entity(e) for e in ents.values()]
    out: list[dict[str, Any]] = []
    for r, _ in rels:
        ind_row = by_ref.get(r.src_ref)
        if ind_row is None or r.dst_ref not in ents:
            continue
        out.append(
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{uuid.uuid5(_NS, f'{r.src_ref}|indicates|{r.dst_ref}')}",
                "created": ts(r.first_seen),
                "modified": ts(max(aware(r.last_seen), aware(r.first_seen))),
                "relationship_type": "indicates",
                "source_ref": r.src_ref,
                "target_ref": r.dst_ref,
                "object_marking_refs": [TLP2[ind_row.ind.tlp][0]],
            }
        )
    return sdos, out


def entity(e: Entity) -> dict[str, Any]:
    created = aware(e.created_at)
    obj: dict[str, Any] = {
        "type": e.type,
        "spec_version": "2.1",
        "id": e.stix_id,
        "created": ts(created),
        "modified": ts(max(aware(e.updated_at), created)),
        "name": e.name,
        "object_marking_refs": [TLP2["TLP:CLEAR"][0]],
    }
    if e.type == "malware":
        obj["is_family"] = True
    if e.aliases and e.type in ("malware", "intrusion-set", "threat-actor", "campaign", "tool"):
        obj["aliases"] = [a for a in e.aliases if a and a != e.name][:20] or None
        if obj["aliases"] is None:
            del obj["aliases"]
    if e.external_id:
        obj["external_references"] = [
            {"source_name": "mitre-attack", "external_id": e.external_id,
             "url": f"https://attack.mitre.org/software/{e.external_id}/" if e.external_id.startswith("S")
             else f"https://attack.mitre.org/groups/{e.external_id}/" if e.external_id.startswith("G")
             else f"https://attack.mitre.org/campaigns/{e.external_id}/"}
        ]  # fmt: skip
    return obj


def markings_for(objects: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    used = {m for o in objects for m in o.get("object_marking_refs", [])}
    return [marking(lv) for lv, (mid, _) in TLP2.items() if mid in used]


def bundle(objects: list[dict[str, Any]]) -> dict[str, Any]:
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


async def build(s: AsyncSession, rows: Sequence[Row], producer: str) -> dict[str, Any]:
    """A self-contained bundle: producer identity, the markings used, indicators,
    and the malware/actors they indicate."""
    ident = identity(producer)
    inds = [indicator(r, ident["id"]) for r in rows]
    sdos, rels = await related(s, rows)
    body = [*inds, *sdos, *rels]
    return bundle([ident, *markings_for(body), *body])
