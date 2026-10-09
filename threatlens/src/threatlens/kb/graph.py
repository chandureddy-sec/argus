"""Graph queries over ``relationships``: node lookup, neighbours, and paths.

Nodes are named by STIX id. People type other things, so ``resolve`` also
accepts a CVE id, an ATT&CK id (T1059.001, S0367, G0102, TA0002, M1031, C0022),
an entity name or alias, an indicator value (``1.2.3.4``, ``evil.com``) or
``indicator:<id>``.

``paths`` runs a bidirectional breadth-first search. It expands the smaller
frontier one level at a time and stops at the first level where the two
searches meet, so every path returned is a shortest path. Each edge carries
its provenance: which source asserted it, how (ATT&CK relationship, feed
field, text mention, same identifier), and the evidence. Hub nodes (Ingress
Tool Transfer has 520 `uses` edges in Enterprise 19.2) are handled by a
visited-node budget; when it runs out, the result says so.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Literal

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from threatlens.connectors.base import clip
from threatlens.ioc.normalize import guess
from threatlens.ioc.types import Observable as Obs
from threatlens.kb.ids import alias_key, is_cve
from threatlens.models import Entity, EntityAlias, Indicator, Observable, Relationship, Source, Vulnerability

_ATTACK_ID = re.compile(r"^(T\d{4}(\.\d{3})?|TA\d{4}|[SGCM]\d{4}|DS\d{4}|DC\d{4}|AN\d{4}|DET\d{4})$", re.I)
EXCLUDED_RELS = frozenset({"revoked-by"})
Direction = Literal["out", "in", "both"]


@dataclass
class Node:
    ref: str
    kind: str  # entity | vulnerability | indicator
    type: str  # STIX type (attack-pattern, malware, …) or observable type
    label: str
    external_id: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class Edge:
    id: int
    stix_id: str
    src: str
    rel_type: str
    dst: str
    origin: str
    source: str | None
    confidence: int
    description: str
    provenance: dict[str, Any]
    first_seen: datetime
    last_seen: datetime

    def view(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("id")
        return d


async def _entity_nodes(s: AsyncSession, where: Any) -> list[Node]:
    rows = (await s.scalars(select(Entity).where(where))).all()
    return [
        Node(
            e.stix_id,
            "entity",
            e.type,
            e.name,
            e.external_id,
            {"origin": e.origin, "revoked": e.revoked, "deprecated": e.deprecated},
        )
        for e in rows
    ]


async def nodes(s: AsyncSession, refs: Iterable[str]) -> dict[str, Node]:
    refs = list(dict.fromkeys(refs))
    out: dict[str, Node] = {}
    ents = [r for r in refs if not r.startswith(("vulnerability--", "indicator--"))]
    vulns = [r for r in refs if r.startswith("vulnerability--")]
    inds = [r for r in refs if r.startswith("indicator--")]
    for i in range(0, len(ents), 500):
        for n in await _entity_nodes(s, Entity.stix_id.in_(ents[i : i + 500])):
            out[n.ref] = n
    for i in range(0, len(vulns), 500):
        for v in (
            await s.scalars(select(Vulnerability).where(Vulnerability.stix_id.in_(vulns[i : i + 500])))
        ).all():
            out[v.stix_id] = Node(
                v.stix_id,
                "vulnerability",
                "vulnerability",
                v.cve_id,
                v.cve_id,
                {"kev": v.kev, "epss": v.epss, "cvss": v.cvss_score},
            )
    for i in range(0, len(inds), 500):
        rows = await s.execute(
            select(Indicator, Observable)
            .join(Observable, Observable.id == Indicator.observable_id)
            .where(Indicator.stix_id.in_(inds[i : i + 500]))
        )
        for ind, obs in rows.all():
            if ind.stix_id is None:
                continue
            out[ind.stix_id] = Node(
                ind.stix_id,
                "indicator",
                obs.type,
                obs.defanged,
                None,
                {"id": ind.id, "status": ind.status, "confidence": ind.confidence, "tlp": ind.tlp},
            )
    return out


async def resolve(s: AsyncSession, ident: str) -> Node | None:
    """Find the node a person means; None if nothing matches."""
    ident = ident.strip()
    if not ident or len(ident) > 300:
        return None
    if "--" in ident:
        return (await nodes(s, [ident])).get(ident)
    if is_cve(ident):
        ref = await s.scalar(select(Vulnerability.stix_id).where(Vulnerability.cve_id == ident.upper()))
        return (await nodes(s, [ref])).get(ref) if ref else None
    if ident.lower().startswith("indicator:") and ident[10:].isdigit():
        ref = await s.scalar(select(Indicator.stix_id).where(Indicator.id == int(ident[10:])))
        return (await nodes(s, [ref])).get(ref) if ref else None
    if _ATTACK_ID.match(ident):
        found = await _entity_nodes(s, func.upper(Entity.external_id) == ident.upper())
        found.sort(key=lambda n: (bool(n.extra.get("revoked")), bool(n.extra.get("deprecated"))))
        if found:
            return found[0]
    key = alias_key(ident)
    if key:
        ents = (
            await s.scalars(
                select(Entity)
                .join(EntityAlias, EntityAlias.entity_id == Entity.id)
                .where(EntityAlias.alias_key == key)
            )
        ).all()
        if ents:
            best = min(
                ents,
                key=lambda e: (e.revoked, e.deprecated, e.origin != "attack", alias_key(e.name) != key, e.id),
            )
            return (await nodes(s, [best.stix_id]))[best.stix_id]
    obs = guess(ident)
    if isinstance(obs, Obs):
        ref = await s.scalar(
            select(Indicator.stix_id)
            .join(Observable, Observable.id == Indicator.observable_id)
            .where(Observable.canonical_key == obs.key)
        )
        return (await nodes(s, [ref])).get(ref) if ref else None
    return None


async def _source_names(s: AsyncSession) -> dict[int, str]:
    return {i: n for i, n in (await s.execute(select(Source.id, Source.name))).all()}  # noqa: C416


def _edge(r: Relationship, names: dict[int, str]) -> Edge:
    return Edge(
        r.id,
        r.stix_id,
        r.src_ref,
        r.rel_type,
        r.dst_ref,
        r.origin,
        names.get(r.source_id) if r.source_id else None,
        r.confidence,
        clip(r.description, 600),
        r.provenance or {},
        r.first_seen,
        r.last_seen,
    )


async def edges_of(
    s: AsyncSession,
    refs: Sequence[str],
    *,
    direction: Direction = "both",
    rel: str | None = None,
    include_revoked: bool = False,
) -> list[Relationship]:
    out: dict[int, Relationship] = {}
    for i in range(0, len(refs), 500):
        chunk = refs[i : i + 500]
        conds = []
        if direction in ("out", "both"):
            conds.append(Relationship.src_ref.in_(chunk))
        if direction in ("in", "both"):
            conds.append(Relationship.dst_ref.in_(chunk))
        stmt = select(Relationship).where(or_(*conds))
        if rel:
            stmt = stmt.where(Relationship.rel_type == rel)
        else:
            stmt = stmt.where(Relationship.rel_type.not_in(EXCLUDED_RELS))
        if not include_revoked:
            stmt = stmt.where(Relationship.revoked.is_(False))
        for r in (await s.scalars(stmt)).all():
            out[r.id] = r
    return list(out.values())


async def neighbors(
    s: AsyncSession,
    ref: str,
    *,
    direction: Direction = "both",
    rel: str | None = None,
    node_type: str | None = None,
    limit: int = 200,
) -> tuple[list[dict[str, Any]], int]:
    """Edges touching ``ref`` with the node at the other end; returns (items, total)."""
    rels = await edges_of(s, [ref], direction=direction, rel=rel)
    other = {r.id: (r.dst_ref if r.src_ref == ref else r.src_ref) for r in rels}
    nodemap = await nodes(s, other.values())
    names = await _source_names(s)
    items: list[dict[str, Any]] = []
    for r in rels:
        n = nodemap.get(other[r.id])
        if n is None or (node_type and n.type != node_type):
            continue
        items.append(
            {
                "node": asdict(n),
                "direction": "out" if r.src_ref == ref else "in",
                "edge": _edge(r, names).view(),
            }
        )
    items.sort(key=lambda x: (x["edge"]["rel_type"], x["node"]["external_id"] or "", x["node"]["label"]))
    return items[:limit], len(items)


@dataclass
class PathResult:
    paths: list[list[dict[str, Any]]]
    nodes: dict[str, dict[str, Any]]
    length: int | None
    truncated: bool


async def paths(
    s: AsyncSession, src: str, dst: str, *, max_depth: int = 4, limit: int = 5, max_nodes: int = 20_000
) -> PathResult:
    if src == dst:
        n = await nodes(s, [src])
        return PathResult([[]], {k: asdict(v) for k, v in n.items()}, 0, False)
    # parents[node] = [(previous node, edge)], dist[node] = hops from that side's start
    pf: dict[str, list[tuple[str, Relationship]]] = {src: []}
    pb: dict[str, list[tuple[str, Relationship]]] = {dst: []}
    df, db = {src: 0}, {dst: 0}
    ff, fb = {src}, {dst}
    truncated = False
    meet: set[str] = set()
    while ff and fb and df[next(iter(ff))] + db[next(iter(fb))] < max_depth:
        forward = len(ff) <= len(fb)
        frontier, parents, dist = (ff, pf, df) if forward else (fb, pb, db)
        level = dist[next(iter(frontier))] + 1
        nxt: set[str] = set()
        for r in await edges_of(s, sorted(frontier)):
            for a, b in ((r.src_ref, r.dst_ref), (r.dst_ref, r.src_ref)):
                if a not in frontier:
                    continue
                if b not in dist:
                    dist[b] = level
                    parents[b] = []
                    nxt.add(b)
                if dist[b] == level:
                    parents[b].append((a, r))
        if forward:
            ff = nxt
        else:
            fb = nxt
        meet = set(df) & set(db)
        if meet:
            break
        if len(df) + len(db) > max_nodes:
            truncated = True
            break
    if not meet:
        return PathResult([], {}, None, truncated)
    best = min(df[m] + db[m] for m in meet)
    meet = {m for m in meet if df[m] + db[m] == best}

    def chains(
        node: str, parents: dict[str, list[tuple[str, Relationship]]]
    ) -> list[list[tuple[str, Relationship]]]:
        if not parents[node]:
            return [[]]
        out: list[list[tuple[str, Relationship]]] = []
        for prev, r in parents[node]:
            for c in chains(prev, parents):
                out.append([*c, (node, r)])
                if len(out) >= limit:
                    return out
        return out

    found: list[list[Relationship]] = []
    for m in sorted(meet):
        for head in chains(m, pf):
            for tail in chains(m, pb):
                edges = [r for _, r in head] + [r for _, r in reversed(tail)]
                found.append(edges)
                if len(found) >= limit:
                    break
            if len(found) >= limit:
                break
        if len(found) >= limit:
            break
    names = await _source_names(s)
    refs = {x for p in found for r in p for x in (r.src_ref, r.dst_ref)} | {src, dst}
    nodemap = await nodes(s, refs)
    return PathResult(
        [[_edge(r, names).view() for r in p] for p in found],
        {k: asdict(v) for k, v in nodemap.items()},
        best,
        truncated,
    )
