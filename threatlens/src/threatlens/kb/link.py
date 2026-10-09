"""Turn what feeds say about an indicator into graph edges.

Feeds name things in their own fields: ThreatFox and Feodo give a malware
family, OTX pulses give malware families, an adversary and ATT&CK technique
ids. Each name is resolved to an ATT&CK entity by name or alias ("QakBot",
"Qbot", "Pinkslipbot" are one entity). If ATT&CK has no match, a local
entity is created, marked ``origin=feed`` and attributed to the feed.

Edges created (all ``origin=feed`` unless noted, with the feed field as evidence):

* indicator ``indicates`` malware / intrusion-set / attack-pattern
* intrusion-set ``uses`` malware, and malware ``uses`` attack-pattern, when
  one OTX pulse names both (a community author's claim: low confidence)
* indicator ``related-to`` vulnerability (``origin=identity``) when the
  indicator *is* a CVE, so feeds, KEV and NVD meet in one graph.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import datetime
from typing import Any

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from threatlens.connectors.base import clip
from threatlens.db import upsert_insert
from threatlens.kb.ids import alias_key, edge_stix_id, indicator_stix_id, stix_id, vulnerability_stix_id
from threatlens.kb.vulns import ensure_stubs
from threatlens.models import Entity, EntityAlias, Indicator, Observable, Relationship, Sighting, Source

LINKED_SOURCES = {"threatfox", "feodo", "otx"}
BATCH = 1000
_TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")
_UNKNOWN = {"unknown", "unknownmalware", "na", "none", "other"}
# What a feed's free-text name may resolve to, in order of preference.
KIND_TYPES = {"malware": ("malware", "tool"), "intrusion-set": ("intrusion-set",)}


def _names(value: Any, key: str = "display_name") -> Iterator[str]:
    """OTX gives lists of strings or of {"id", "display_name"} objects."""
    items = value if isinstance(value, list) else [value]
    for v in items:
        if isinstance(v, dict):
            v = v.get(key) or v.get("name") or v.get("id")
        if isinstance(v, str) and v.strip():
            yield v.strip()


def mentions(source: str, ctx: dict[str, Any]) -> list[tuple[str, str, str]]:
    """(kind, name, field) triples named by one sighting's context."""
    out: list[tuple[str, str, str]] = []
    if source in ("threatfox", "feodo"):
        out += [("malware", n, "malware") for n in _names(ctx.get("malware"))]
    elif source == "otx":
        out += [("malware", n, "malware_families") for n in _names(ctx.get("malware_families"))]
        out += [("intrusion-set", n, "adversary") for n in _names(ctx.get("adversary"))]
        out += [("attack-pattern", n.upper(), "attack_ids") for n in _names(ctx.get("attack_ids"), "id")]
    return [
        (k, n, f)
        for k, n, f in out
        if alias_key(n) not in _UNKNOWN and (k != "attack-pattern" or _TECHNIQUE.match(n))
    ]


class Resolver:
    """Name → entity stix id, with a per-run cache."""

    def __init__(self, s: AsyncSession, source_id: int, now: datetime) -> None:
        self.s = s
        self.source_id = source_id
        self.now = now
        self.cache: dict[tuple[str, str], str | None] = {}

    async def __call__(self, kind: str, name: str) -> str | None:
        key = (kind, alias_key(name) if kind != "attack-pattern" else name)
        if key not in self.cache:
            self.cache[key] = await self._resolve(kind, name)
        return self.cache[key]

    async def _resolve(self, kind: str, name: str) -> str | None:
        if kind == "attack-pattern":
            return await self.s.scalar(
                select(Entity.stix_id).where(
                    Entity.type == "attack-pattern", Entity.external_id == name, Entity.revoked.is_(False)
                )
            )
        k = alias_key(name)
        if not k:
            return None
        types = KIND_TYPES[kind]
        rows = (
            await self.s.scalars(
                select(Entity)
                .join(EntityAlias, EntityAlias.entity_id == Entity.id)
                .where(EntityAlias.alias_key == k, Entity.type.in_(types), Entity.revoked.is_(False))
            )
        ).all()
        if rows:
            best = min(
                rows,
                key=lambda e: (
                    e.origin != "attack",
                    e.deprecated,
                    alias_key(e.name) != k,
                    types.index(e.type),
                    e.id,
                ),
            )
            return best.stix_id
        # Unknown to ATT&CK: a local entity attributed to the feed that named it.
        etype = types[0]
        sid = stix_id(etype, k)
        await self.s.execute(
            upsert_insert(self.s, Entity)
            .values(
                stix_id=sid,
                type=etype,
                name=clip(name, 100),
                description="",
                aliases=[],
                domains=[],
                platforms=[],
                tactics=[],
                is_subtechnique=False,
                revoked=False,
                deprecated=False,
                origin="feed",
                source_id=self.source_id,
                stix={},
                created_at=self.now,
                updated_at=self.now,
            )
            .on_conflict_do_nothing(index_elements=["stix_id"])
        )
        eid = await self.s.scalar(select(Entity.id).where(Entity.stix_id == sid))
        await self.s.execute(
            upsert_insert(self.s, EntityAlias)
            .values(alias_key=k, entity_id=eid)
            .on_conflict_do_nothing(index_elements=["alias_key", "entity_id"])
        )
        return sid


async def _edge(
    s: AsyncSession,
    src: str,
    rel: str,
    dst: str,
    *,
    origin: str,
    scope: str,
    source_id: int | None,
    confidence: int,
    provenance: dict[str, Any],
    now: datetime,
) -> None:
    sid = edge_stix_id(src, rel, dst, f"{origin}:{scope}")
    await s.execute(
        upsert_insert(s, Relationship)
        .values(
            stix_id=sid,
            src_ref=src,
            rel_type=rel,
            dst_ref=dst,
            origin=origin,
            scope=scope,
            description="",
            confidence=confidence,
            source_id=source_id,
            provenance=provenance,
            revoked=False,
            first_seen=now,
            last_seen=now,
        )
        .on_conflict_do_update(index_elements=["stix_id"], set_={"last_seen": now, "confidence": confidence})
    )


async def backfill_indicator_ids(sm: async_sessionmaker[AsyncSession]) -> int:
    """Give indicators created before Phase 2 their deterministic STIX id."""
    done = 0
    while True:
        async with sm() as s, s.begin():
            rows = (
                await s.execute(
                    select(Indicator.id, Observable.canonical_key)
                    .join(Observable, Observable.id == Indicator.observable_id)
                    .where(Indicator.stix_id.is_(None))
                    .limit(BATCH)
                )
            ).all()
            if not rows:
                return done
            await s.execute(update(Indicator), [{"id": i, "stix_id": indicator_stix_id(k)} for i, k in rows])
            done += len(rows)


async def link_source(sm: async_sessionmaker[AsyncSession], source: str, since: datetime) -> int:
    """Link the sightings ``source`` wrote since ``since``; returns edges written."""
    await backfill_indicator_ids(sm)
    written = 0
    last_id = 0
    while True:
        async with sm() as s, s.begin():
            src = await s.scalar(select(Source).where(Source.name == source))
            if src is None:
                return written
            stmt = (
                select(Sighting.id, Sighting.context, Sighting.confidence, Indicator.stix_id, Observable)
                .join(Indicator, Indicator.id == Sighting.indicator_id)
                .join(Observable, Observable.id == Indicator.observable_id)
                .where(Sighting.source_id == src.id, Sighting.updated_at >= since, Sighting.id > last_id)
            )
            if source not in LINKED_SOURCES:  # no entity fields: only CVE identity edges
                stmt = stmt.where(Observable.type == "vulnerability")
            rows = (await s.execute(stmt.order_by(Sighting.id).limit(BATCH))).all()
            if not rows:
                return written
            last_id = rows[-1][0]
            resolve = Resolver(s, src.id, since)
            cves = [obs.value for *_, obs in rows if obs.type == "vulnerability"]
            if cves:
                await ensure_stubs(s, cves)
            for sg_id, ctx, conf, ind_ref, obs in rows:
                if not ind_ref:
                    continue
                if obs.type == "vulnerability":
                    await _edge(
                        s, ind_ref, "related-to", vulnerability_stix_id(obs.value),
                        origin="identity", scope="cve", source_id=None, confidence=100,
                        provenance={"reason": "the indicator is this CVE"}, now=since,
                    )  # fmt: skip
                    written += 1
                if source not in LINKED_SOURCES:
                    continue
                named = mentions(source, ctx or {})
                resolved: dict[str, list[str]] = {}
                for kind, name, field in named:
                    ent = await resolve(kind, name)
                    if ent is None:
                        continue
                    resolved.setdefault(kind, []).append(ent)
                    await _edge(
                        s, ind_ref, "indicates", ent,
                        origin="feed", scope=source, source_id=src.id, confidence=conf,
                        provenance={"field": field, "value": clip(name, 100), "sighting": sg_id},
                        now=since,
                    )  # fmt: skip
                    written += 1
                if source == "otx":
                    pulse = {
                        "pulse": (ctx or {}).get("pulse_id"),
                        "title": clip((ctx or {}).get("pulse"), 200),
                    }
                    for actor in resolved.get("intrusion-set", []):
                        for mal in resolved.get("malware", []):
                            await _edge(
                                s, actor, "uses", mal, origin="feed", scope=source, source_id=src.id,
                                confidence=40, provenance={**pulse, "claim": "pulse names both"}, now=since,
                            )  # fmt: skip
                            written += 1
                    for mal in resolved.get("malware", []):
                        for tech in resolved.get("attack-pattern", []):
                            await _edge(
                                s, mal, "uses", tech, origin="feed", scope=source, source_id=src.id,
                                confidence=40, provenance={**pulse, "claim": "pulse names both"}, now=since,
                            )  # fmt: skip
                            written += 1


async def merge_feed_entities(s: AsyncSession) -> int:
    """Fold feed-created entities into ATT&CK entities that now match them.

    Feeds are often collected before ATT&CK is loaded (or before ATT&CK adds a
    family), so a feed may have created a local "Emotet". After every ATT&CK
    load, each local entity whose alias matches a live ATT&CK entity of a
    compatible type is merged: its edges are re-pointed (or dropped when the
    ATT&CK entity already has the same edge) and the local entity is deleted.
    Returns how many entities were merged.
    """
    merged = 0
    locals_ = (await s.scalars(select(Entity).where(Entity.origin == "feed"))).all()
    for local in locals_:
        types = next((t for t in KIND_TYPES.values() if local.type in t), (local.type,))
        target = await s.scalar(
            select(Entity)
            .join(EntityAlias, EntityAlias.entity_id == Entity.id)
            .where(
                EntityAlias.alias_key == alias_key(local.name),
                Entity.origin == "attack",
                Entity.type.in_(types),
                Entity.revoked.is_(False),
            )
            .order_by(Entity.deprecated, Entity.id)
            .limit(1)
        )
        if target is None:
            continue
        edges = (
            await s.scalars(
                select(Relationship).where(
                    (Relationship.src_ref == local.stix_id) | (Relationship.dst_ref == local.stix_id)
                )
            )
        ).all()
        for e in edges:
            src = target.stix_id if e.src_ref == local.stix_id else e.src_ref
            dst = target.stix_id if e.dst_ref == local.stix_id else e.dst_ref
            new_id = edge_stix_id(src, e.rel_type, dst, f"{e.origin}:{e.scope}")
            if await s.scalar(select(Relationship.id).where(Relationship.stix_id == new_id)):
                await s.delete(e)  # the ATT&CK entity already has this edge
                continue
            e.src_ref, e.dst_ref, e.stix_id = src, dst, new_id
            e.provenance = {**(e.provenance or {}), "merged_from": local.name}
        await s.flush()
        await s.execute(delete(EntityAlias).where(EntityAlias.entity_id == local.id))
        await s.delete(local)
        merged += 1
    return merged
