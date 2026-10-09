"""MITRE ATT&CK (Enterprise, Mobile, ICS) from the official STIX 2.1 data.

MITRE's ``attack-stix-data`` repository publishes an ``index.json`` listing
every release of every domain, each as an immutable, versioned bundle.
A run reads the index and loads any release newer than the one stored.

Loading a release:

* upserts every STIX object except bundle metadata into ``entities``
  (techniques, tactics, groups, software, campaigns, mitigations, detection
  objects), keeping the original object;
* upserts ATT&CK relationships into ``relationships`` and deletes the ones
  that disappeared from this domain;
* links CVEs named in ATT&CK text to vulnerability nodes, with the sentence
  as evidence (a mention, not a claim of exploitation);
* records the release and, compared with the previous release of the
  domain, every **meaningful** change. Most objects in a new release only get
  a new ``modified`` timestamp or spec version; those are counted as
  "touched", not listed.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from threatlens.connectors.base import SchemaDriftError, SourceInfo, clip, parse_time, require
from threatlens.db import upsert_insert
from threatlens.kb.base import KbContext, KbResult, KnowledgeSource, archive, register_kb
from threatlens.kb.ids import CVE_IN_TEXT, alias_key, edge_stix_id, vulnerability_stix_id
from threatlens.kb.link import merge_feed_entities
from threatlens.kb.vulns import ensure_stubs
from threatlens.models import AttackChange, AttackRelease, Entity, EntityAlias, Relationship

INDEX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"
COLLECTIONS = {
    "Enterprise ATT&CK": "enterprise-attack",
    "Mobile ATT&CK": "mobile-attack",
    "ICS ATT&CK": "ics-attack",
}
SKIP_TYPES = {"relationship", "marking-definition", "identity", "x-mitre-collection", "x-mitre-matrix"}
ATTACK_SOURCES = {"mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"}
# Fields whose change is worth telling an analyst about.
TRACKED = (
    "name",
    "description",
    "aliases",
    "x_mitre_aliases",
    "x_mitre_version",
    "revoked",
    "x_mitre_deprecated",
    "kill_chain_phases",
    "x_mitre_platforms",
    "x_mitre_domains",
)
_BOOL_FIELDS = {"revoked", "x_mitre_deprecated"}
CHUNK = 1000


class DowngradeError(ValueError):
    pass


def _utc(dt: datetime | None) -> datetime | None:
    """SQLite returns naive datetimes; compare everything as aware UTC."""
    return dt.replace(tzinfo=UTC) if dt is not None and dt.tzinfo is None else dt


def version_key(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v)) or (0,)


def external_id(o: dict[str, Any]) -> str | None:
    for r in o.get("external_references") or []:
        if r.get("source_name") in ATTACK_SOURCES and r.get("external_id"):
            return str(r["external_id"])[:32]
    return None


def _norm(field: str, value: Any) -> Any:
    return bool(value) if field in _BOOL_FIELDS else value


def changed_fields(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    return [f for f in TRACKED if _norm(f, old.get(f)) != _norm(f, new.get(f))]


def entity_values(o: dict[str, Any], domain: str, source_id: int) -> dict[str, Any]:
    aliases = [
        a for a in (*(o.get("aliases") or []), *(o.get("x_mitre_aliases") or [])) if isinstance(a, str)
    ]
    if o["type"] == "x-mitre-tactic" and o.get("x_mitre_shortname"):
        aliases.append(o["x_mitre_shortname"])
    return {
        "stix_id": o["id"],
        "type": o["type"][:40],
        "name": clip(o.get("name") or o["id"], 500),
        "external_id": external_id(o),
        "description": o.get("description") or "",
        "aliases": list(dict.fromkeys(a for a in aliases if a != o.get("name"))),
        "domains": [d for d in o.get("x_mitre_domains") or [domain] if isinstance(d, str)],
        "platforms": [p for p in o.get("x_mitre_platforms") or [] if isinstance(p, str)],
        "tactics": [
            p["phase_name"]
            for p in o.get("kill_chain_phases") or []
            if isinstance(p, dict) and str(p.get("kill_chain_name", "")).startswith("mitre")
        ],
        "is_subtechnique": bool(o.get("x_mitre_is_subtechnique")),
        "revoked": bool(o.get("revoked")),
        "deprecated": bool(o.get("x_mitre_deprecated")),
        "version": clip(o.get("x_mitre_version"), 16) or None,
        "stix_modified": parse_time(o.get("modified")),
        "origin": "attack",
        "source_id": source_id,
        "stix": o,
    }


def _classify(old: dict[str, Any], new: dict[str, Any], fields: list[str]) -> str:
    was_revoked, is_revoked = bool(old.get("revoked")), bool(new.get("revoked"))
    was_dep, is_dep = bool(old.get("x_mitre_deprecated")), bool(new.get("x_mitre_deprecated"))
    if is_revoked and not was_revoked:
        return "revoked"
    if is_dep and not was_dep:
        return "deprecated"
    if (was_revoked and not is_revoked) or (was_dep and not is_dep):
        return "restored"
    return "modified"


def _snippet(text: str, start: int, end: int, width: int = 160) -> str:
    a, b = max(0, start - width), min(len(text), end + width)
    return ("…" if a else "") + re.sub(r"\s+", " ", text[a:b]).strip() + ("…" if b < len(text) else "")


def parse_bundle(body: bytes) -> list[dict[str, Any]]:
    try:
        doc = json.loads(body)
    except ValueError as e:
        raise SchemaDriftError(f"ATT&CK: not JSON ({e})") from e
    if not isinstance(doc, dict) or doc.get("type") != "bundle":
        raise SchemaDriftError("ATT&CK: not a STIX bundle")
    require(doc, "objects", where="ATT&CK bundle")
    objs = [o for o in doc["objects"] if isinstance(o, dict) and isinstance(o.get("id"), str) and "type" in o]
    if not any(o["type"] == "attack-pattern" for o in objs):
        raise SchemaDriftError("ATT&CK: bundle contains no techniques")
    return objs


@register_kb
class MitreAttack(KnowledgeSource):
    info = SourceInfo(
        name="mitre_attack",
        title="MITRE ATT&CK (Enterprise, Mobile, ICS; STIX 2.1)",
        kind="knowledge",
        homepage="https://attack.mitre.org/",
        url=INDEX_URL,
        reliability="A",
        reliability_note="Curated, cited knowledge base of adversary behaviour maintained by MITRE.",
        license="ATT&CK Terms of Use: royalty-free incl. commercial; copies keep the copyright notice",
        license_url="https://attack.mitre.org/resources/legal-and-branding/terms-of-use/",
        commercial_use=True,
        redistribution=True,
        attribution=(
            "© The MITRE Corporation. This work is reproduced and distributed with the "
            "permission of The MITRE Corporation."
        ),
        upstream="mitre",
        interval=timedelta(hours=24),
        min_interval=timedelta(hours=1),
        default_confidence=90,
        max_bytes=128 * 1024 * 1024,  # Enterprise is ~54 MB
        verified="2026-10-09",
    )

    async def sync(self, ctx: KbContext) -> KbResult:
        r = await ctx.http.get(INDEX_URL, etag=ctx.checkpoint.get("etag"), max_bytes=4 * 1024 * 1024)
        cp = {**ctx.checkpoint, **({"etag": r.etag} if r.etag else {})}
        if r.not_modified:
            return KbResult(status="not_modified", http_status=304, checkpoint=cp)
        try:
            index = json.loads(r.body)
        except ValueError as e:
            raise SchemaDriftError(f"ATT&CK index: not JSON ({e})") from e
        require(index, "collections", where="ATT&CK index")
        res = KbResult(checkpoint=cp)
        loaded = []
        for coll in index["collections"]:
            require(coll, "name", "versions", where="ATT&CK index collection")
            domain = COLLECTIONS.get(coll["name"])
            if domain is None or domain not in ctx.settings.attack_domains or not coll["versions"]:
                continue
            latest = max(coll["versions"], key=lambda v: version_key(str(v.get("version", "0"))))
            require(latest, "version", "url", where="ATT&CK index version")
            async with ctx.sm() as s:
                have = await s.scalar(
                    select(AttackRelease.id).where(
                        AttackRelease.domain == domain, AttackRelease.version == latest["version"]
                    )
                )
            if have:
                continue
            one = await load_release(ctx, domain, latest["version"], latest["url"], self.info.max_bytes)
            res.items_total += one.items_total
            res.items_new += one.items_new
            res.items_updated += one.items_updated
            loaded.append(f"{domain} {latest['version']}")
        res.note = f"loaded {', '.join(loaded)}" if loaded else "up to date"
        return res


async def load_release(
    ctx: KbContext,
    domain: str,
    version: str,
    url: str,
    max_bytes: int = 128 * 1024 * 1024,
    *,
    force: bool = False,
) -> KbResult:
    """Fetch one versioned bundle and apply it (see the module docstring)."""
    async with ctx.sm() as s:
        prev = await s.scalar(
            select(AttackRelease)
            .where(AttackRelease.domain == domain)
            .order_by(AttackRelease.ingested_at.desc(), AttackRelease.id.desc())
            .limit(1)
        )
        same = await s.scalar(
            select(AttackRelease.id).where(AttackRelease.domain == domain, AttackRelease.version == version)
        )
    if prev is not None and version_key(version) < version_key(prev.version) and not force:
        raise DowngradeError(f"{domain} {version} is older than the loaded {prev.version}; use force")
    if same is not None and not force:
        raise DowngradeError(f"{domain} {version} is already loaded; use force to load it again")
    r = await ctx.http.get(url, max_bytes=max_bytes)
    objs = parse_bundle(r.body)
    raw_id = await archive(ctx, url, r.body, r.content_type, len(objs))
    collection = next((o for o in objs if o["type"] == "x-mitre-collection"), {})
    async with ctx.sm() as s, s.begin():
        if same is not None:  # a forced reload replaces the stored release and its change list
            await s.execute(delete(AttackChange).where(AttackChange.release_id == same))
            await s.execute(delete(AttackRelease).where(AttackRelease.id == same))
        summary, changes, counts = await _apply(s, ctx, domain, objs, baseline=prev is None)
        release = AttackRelease(
            domain=domain,
            version=version,
            released=parse_time(collection.get("modified")),
            url=url,
            sha256=r.sha256,
            baseline=prev is None,
            previous_version=prev.version if prev else None,
            counts=counts,
            summary=summary,
            ingested_at=ctx.now,
        )
        s.add(release)
        await s.flush()
        for i in range(0, len(changes), CHUNK):
            await s.execute(
                insert(AttackChange),
                [{**c, "release_id": release.id} for c in changes[i : i + CHUNK]],
            )
    return KbResult(
        items_total=len(objs),
        items_new=summary.get("added", 0) if prev else counts.get("entities", 0),
        items_updated=summary.get("modified", 0),
        http_status=r.status,
        raw_id=raw_id,
        note=f"{domain} {version}",
    )


async def _apply(
    s: AsyncSession, ctx: KbContext, domain: str, objs: list[dict[str, Any]], *, baseline: bool
) -> tuple[dict[str, int], list[dict[str, Any]], dict[str, int]]:
    entities = [o for o in objs if o["type"] not in SKIP_TYPES]
    rels = [o for o in objs if o["type"] == "relationship"]
    summary: Counter[str] = Counter()
    changes: list[dict[str, Any]] = []

    def change(o: dict[str, Any], kind: str, details: dict[str, Any]) -> None:
        summary[kind] += 1
        if not baseline:
            changes.append(
                {
                    "stix_id": o["id"],
                    "type": o["type"][:40],
                    "external_id": external_id(o),
                    "name": clip(o.get("name") or o["id"], 500),
                    "change": kind,
                    "details": details,
                }
            )

    # ── entities ────────────────────────────────────────────────────────────
    existing = {
        e.stix_id: e for e in (await s.scalars(select(Entity).where(Entity.origin == "attack"))).all()
    }
    inserts, updates = [], []
    for o in entities:
        vals = entity_values(o, domain, ctx.source_id)
        e = existing.get(o["id"])
        if e is None:
            inserts.append({**vals, "created_at": ctx.now, "updated_at": ctx.now})
            change(o, "added", {"version": o.get("x_mitre_version")})
            continue
        fields = changed_fields(e.stix or {}, o)
        if fields:
            change(
                o,
                _classify(e.stix or {}, o, fields),
                {"fields": fields, "version": [e.version, o.get("x_mitre_version")]},
            )
        elif domain in ((e.stix or {}).get("x_mitre_domains") or []) and domain not in (e.domains or []):
            # Back in a domain an earlier release dropped it from (e.g. after a forced older load).
            change(o, "restored", {"domain": domain})
        elif _utc(e.stix_modified) != vals["stix_modified"]:
            summary["touched"] += 1
        if fields or _utc(e.stix_modified) != vals["stix_modified"] or domain not in (e.domains or []):
            updates.append({"id": e.id, **vals, "updated_at": ctx.now})
    for i in range(0, len(inserts), CHUNK):
        await s.execute(insert(Entity), inserts[i : i + CHUNK])
    for i in range(0, len(updates), CHUNK):
        await s.execute(update(Entity), updates[i : i + CHUNK])

    seen = {o["id"] for o in entities}
    for e in existing.values():
        if e.stix_id in seen or domain not in (e.domains or []):
            continue
        change(e.stix or {"id": e.stix_id, "type": e.type, "name": e.name}, "removed", {"domain": domain})
        e.domains = [d for d in e.domains if d != domain]
        if not e.domains:
            e.deprecated = True

    # ── aliases (rebuilt for this bundle's objects) ─────────────────────────
    ids = {
        sid: eid
        for sid, eid in (
            await s.execute(select(Entity.stix_id, Entity.id).where(Entity.origin == "attack"))
        ).all()
        if sid in seen
    }
    eids = list(ids.values())
    for i in range(0, len(eids), CHUNK):
        await s.execute(delete(EntityAlias).where(EntityAlias.entity_id.in_(eids[i : i + CHUNK])))
    alias_rows: dict[tuple[str, int], dict[str, Any]] = {}
    for o in entities:
        if o["type"] not in (
            "malware",
            "tool",
            "intrusion-set",
            "campaign",
            "x-mitre-tactic",
            "attack-pattern",
        ):
            continue
        names = [o.get("name"), *(o.get("aliases") or []), *(o.get("x_mitre_aliases") or [])]
        for n in names:
            if isinstance(n, str) and (k := alias_key(n)):
                alias_rows[(k, ids[o["id"]])] = {"alias_key": k, "entity_id": ids[o["id"]]}
    rows = list(alias_rows.values())
    for i in range(0, len(rows), CHUNK):
        await s.execute(insert(EntityAlias), rows[i : i + CHUNK])

    # ── relationships ───────────────────────────────────────────────────────
    old_rels = {
        r.stix_id: r
        for r in (
            await s.scalars(
                select(Relationship).where(Relationship.origin == "attack", Relationship.scope == domain)
            )
        ).all()
    }
    all_attack_rels = set(
        (await s.scalars(select(Relationship.stix_id).where(Relationship.origin == "attack"))).all()
    )
    rel_inserts, rel_updates = [], []
    for o in rels:
        if not {"source_ref", "target_ref", "relationship_type"} <= set(o):
            continue
        vals = {
            "stix_id": o["id"],
            "src_ref": o["source_ref"],
            "rel_type": str(o["relationship_type"])[:40],
            "dst_ref": o["target_ref"],
            "origin": "attack",
            "scope": domain,
            "description": o.get("description") or "",
            "confidence": 90,
            "source_id": ctx.source_id,
            "provenance": {
                "attack_relationship": o["id"],
                "references": [
                    {k: r.get(k) for k in ("source_name", "url") if r.get(k)}
                    for r in (o.get("external_references") or [])[:10]
                ],
            },
            "revoked": bool(o.get("revoked")) or bool(o.get("x_mitre_deprecated")),
            "last_seen": ctx.now,
        }
        old = old_rels.get(o["id"])
        if old is not None:
            keys = ("src_ref", "rel_type", "dst_ref", "description", "revoked", "provenance")
            if any(
                getattr(old, k) != vals[k] for k in keys
            ):  # unchanged relationships only get last_seen, in one statement below
                rel_updates.append({"id": old.id, **vals})
        elif o["id"] in all_attack_rels:  # same relationship already loaded via another domain
            continue
        else:
            rel_inserts.append({**vals, "first_seen": ctx.now})
            if not baseline:
                summary["relationships_added"] += 1
    for i in range(0, len(rel_inserts), CHUNK):
        await s.execute(insert(Relationship), rel_inserts[i : i + CHUNK])
    for i in range(0, len(rel_updates), CHUNK):
        await s.execute(update(Relationship), rel_updates[i : i + CHUNK])
    await s.execute(
        update(Relationship)
        .where(Relationship.origin == "attack", Relationship.scope == domain)
        .values(last_seen=ctx.now)
        .execution_options(synchronize_session=False)
    )
    current = {o["id"] for o in rels}
    gone = [r.id for sid, r in old_rels.items() if sid not in current]
    for i in range(0, len(gone), CHUNK):
        await s.execute(delete(Relationship).where(Relationship.id.in_(gone[i : i + CHUNK])))
    if not baseline:
        summary["relationships_removed"] += len(gone)

    # ── CVEs named in ATT&CK text ───────────────────────────────────────────
    await s.execute(
        delete(Relationship).where(Relationship.origin == "attack-mention", Relationship.scope == domain)
    )
    mentions: dict[str, dict[str, Any]] = {}
    for o in [*entities, *rels]:
        text = o.get("description") or ""
        if "CVE-" not in text.upper():
            continue
        subject = o["source_ref"] if o["type"] == "relationship" else o["id"]
        for m in CVE_IN_TEXT.finditer(text):
            cve = m.group(0).upper()
            dst = vulnerability_stix_id(cve)
            sid = edge_stix_id(subject, "related-to", dst, "attack-mention")
            if sid in mentions:
                continue
            mentions[sid] = {
                "stix_id": sid,
                "src_ref": subject,
                "rel_type": "related-to",
                "dst_ref": dst,
                "origin": "attack-mention",
                "scope": domain,
                "description": "",
                "confidence": 60,
                "source_id": ctx.source_id,
                "provenance": {
                    "mentioned_in": o["id"],
                    "cve": cve,
                    "quote": _snippet(text, m.start(), m.end()),
                },
                "revoked": False,
                "first_seen": ctx.now,
                "last_seen": ctx.now,
            }
    if mentions:
        await ensure_stubs(s, {m["provenance"]["cve"] for m in mentions.values()})
        rows = list(mentions.values())
        for i in range(0, len(rows), CHUNK):
            # The same software can carry the same text in two domains.
            await s.execute(
                upsert_insert(s, Relationship)
                .values(rows[i : i + CHUNK])
                .on_conflict_do_nothing(index_elements=["stix_id"])
            )
    summary["cve_mentions"] = len(mentions)

    summary["feed_entities_merged"] = await merge_feed_entities(s)

    counts = dict(Counter(o["type"] for o in objs))
    counts["entities"] = len(entities)
    return dict(summary), changes, counts
