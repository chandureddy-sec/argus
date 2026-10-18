"""ATT&CK views for detection engineering (ADR 0020): Navigator layers for
any actor, malware, tool or campaign, and coverage gaps of our rule
inventory against the techniques that matter to us."""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

import yaml
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from threatlens import tlp as tlp_rules
from threatlens.models import AttackRelease, AuditLog, DetectionRule, Entity, Indicator, Relationship
from threatlens.settings import Settings

NAVIGATOR_VERSION = "4.5"  # ATT&CK Navigator layer format
NAVIGATOR_APP = "5.1.0"
_TECH_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.I)
MAX_IMPORT = 5000


async def attack_version(s: AsyncSession) -> str:
    v = await s.scalar(
        select(AttackRelease.version)
        .where(AttackRelease.domain == "enterprise-attack")
        .order_by(AttackRelease.id.desc())
        .limit(1)
    )
    return str(v or "17").split(".")[0]


async def techniques_of(s: AsyncSession, ref: str) -> list[tuple[Entity, str]]:
    """(technique, how) used by an entity, from ATT&CK and feed relationships."""
    rows = (
        await s.execute(
            select(Entity, Relationship.description)
            .join(Relationship, Relationship.dst_ref == Entity.stix_id)
            .where(
                Relationship.src_ref == ref,
                Relationship.rel_type == "uses",
                Entity.type == "attack-pattern",
                Relationship.revoked.is_(False),
                Entity.revoked.is_(False),
            )
        )
    ).all()
    seen: dict[str, tuple[Entity, str]] = {}
    for e, desc in rows:
        seen.setdefault(e.stix_id, (e, desc or ""))
    return sorted(seen.values(), key=lambda x: x[0].external_id or "")


def layer(
    name: str,
    description: str,
    version: str,
    scores: dict[str, tuple[int, str]],
    *,
    gradient: tuple[str, str] = ("#ffffff", "#e45756"),
    maximum: int = 1,
) -> dict[str, Any]:
    """An ATT&CK Navigator layer (format 4.5) scoring ``scores``: technique id -> (score, comment)."""
    return {
        "name": name[:200],
        "versions": {"attack": version, "navigator": NAVIGATOR_APP, "layer": NAVIGATOR_VERSION},
        "domain": "enterprise-attack",
        "description": description[:2000],
        "sorting": 3,
        "layout": {"layout": "side", "showName": True, "showID": True, "aggregateFunction": "max"},
        "hideDisabled": False,
        "techniques": [
            {
                "techniqueID": tid,
                "score": sc,
                "comment": comment[:500],
                "enabled": True,
                "showSubtechniques": True,
            }
            for tid, (sc, comment) in sorted(scores.items())
        ],
        "gradient": {"colors": list(gradient), "minValue": 0, "maxValue": max(1, maximum)},
        "legendItems": [],
        "metadata": [
            {"name": "generated_by", "value": "Argus"},
            {"name": "generated_at", "value": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }


async def entity_layer(s: AsyncSession, ent: Entity) -> dict[str, Any]:
    techs = await techniques_of(s, ent.stix_id)
    scores = {t.external_id: (1, (how or f"used by {ent.name}")[:300]) for t, how in techs if t.external_id}
    return layer(
        f"{ent.name} ({ent.external_id or ent.type})",
        f"Techniques used by {ent.name} per MITRE ATT&CK and feed relationships in Argus ({len(scores)}).",
        await attack_version(s),
        scores,
    )


# ── relevance and coverage ──────────────────────────────────────────────────


async def relevant(s: AsyncSession, settings: Settings, clearance: str) -> dict[str, dict[str, Any]]:
    """Techniques that matter to us, with why: watched by a PIR (weight 5 each)
    or used by malware/actors that our current indicators point at (weight 1 per family)."""
    from threatlens.profile import ProfileError, load_pirs, load_profile

    out: dict[str, dict[str, Any]] = {}

    def add(tid: str, weight: int, why: str) -> None:
        d = out.setdefault(tid.upper(), {"weight": 0, "why": []})
        d["weight"] += weight
        if why not in d["why"]:
            d["why"].append(why)

    try:
        pirs = load_pirs(settings.pirs_path, load_profile(settings.profile_path))
        for p in pirs.pirs:
            for t in p.watch.techniques:
                add(str(t), 5, f"{p.id} watches it")
    except (ProfileError, OSError):
        pass
    vis = Indicator.tlp.in_(tlp_rules.readable(clearance))
    fams = (
        await s.execute(
            select(Relationship.dst_ref, func.count(func.distinct(Relationship.src_ref)))
            .join(Indicator, Indicator.stix_id == Relationship.src_ref)
            .where(Relationship.rel_type == "indicates", Indicator.status == "active", vis)
            .group_by(Relationship.dst_ref)
        )
    ).all()
    names = {
        e.stix_id: e.name
        for e in (await s.scalars(select(Entity).where(Entity.stix_id.in_([f for f, _ in fams])))).all()
    }
    for ref, _n in fams:
        for tech, _ in await techniques_of(s, ref):
            if tech.external_id:
                add(tech.external_id, 1, f"used by {names.get(ref, ref)}")
    return out


def rule_techniques(tags: Iterable[str]) -> list[str]:
    return sorted({m.group(1).upper() for t in tags if (m := _TECH_TAG.match(str(t).strip()))})


def parse_inventory(texts: Iterable[tuple[str, str]]) -> tuple[list[dict[str, Any]], list[str]]:
    """Sigma YAML files (name, text) → rule records; unreadable files are reported, not fatal."""
    rules: list[dict[str, Any]] = []
    errors: list[str] = []
    for name, text in texts:
        try:
            docs = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
        except yaml.YAMLError as e:
            errors.append(f"{name}: not YAML ({str(e)[:120]})")
            continue
        for d in docs:
            if "detection" not in d or "title" not in d:
                continue  # an action/collection document, not a rule
            rules.append(
                {
                    "uid": str(d.get("id") or hashlib.sha256(yaml.safe_dump(d).encode()).hexdigest()[:32])[
                        :100
                    ],
                    "title": str(d.get("title"))[:300],
                    "status": str(d.get("status") or "")[:20] or None,
                    "level": str(d.get("level") or "")[:20] or None,
                    "logsource": d.get("logsource") if isinstance(d.get("logsource"), dict) else {},
                    "techniques": rule_techniques(d.get("tags") or []),
                    "content": yaml.safe_dump(d, sort_keys=False)[:50_000],
                }
            )
            if len(rules) >= MAX_IMPORT:
                errors.append(f"stopped at {MAX_IMPORT} rules")
                return rules, errors
    return rules, errors


async def import_rules(s: AsyncSession, records: list[dict[str, Any]], *, actor: str) -> dict[str, int]:
    existing = {
        r.rule_uid: r
        for r in (await s.scalars(select(DetectionRule).where(DetectionRule.origin == "imported"))).all()
    }
    added = updated = 0
    for rec in records:
        row = existing.get(rec["uid"])
        if row is None:
            s.add(
                DetectionRule(
                    origin="imported",
                    rule_uid=rec["uid"],
                    title=rec["title"],
                    status=rec["status"],
                    level=rec["level"],
                    logsource=rec["logsource"],
                    techniques=rec["techniques"],
                    content=rec["content"],
                    created_by=actor[:100],
                )
            )
            existing[rec["uid"]] = row  # type: ignore[assignment]
            added += 1
        elif row is not None:
            row.title, row.status, row.level = rec["title"], rec["status"], rec["level"]
            row.logsource, row.techniques, row.content = rec["logsource"], rec["techniques"], rec["content"]
            updated += 1
    s.add(
        AuditLog(
            actor=actor[:100],
            action="detections.import",
            target="detection_rules",
            details={"added": added, "updated": updated},
        )
    )
    return {"added": added, "updated": updated}


async def coverage(s: AsyncSession, settings: Settings, clearance: str) -> dict[str, Any]:
    """Relevant techniques, which of them our inventory covers (a rule tagged with the
    technique or one of its sub-techniques), and the gaps, most relevant first."""
    rel = await relevant(s, settings, clearance)
    rows = (await s.scalars(select(DetectionRule))).all()
    covered: Counter[str] = Counter()
    for r in rows:
        for t in r.techniques or []:
            covered[t.upper()] += 1
            covered[t.upper().split(".")[0]] += 0  # parent key exists for lookups below

    def count_for(tid: str) -> int:
        if covered.get(tid):
            return covered[tid]
        return sum(n for k, n in covered.items() if k.startswith(tid + "."))  # a sub-technique rule counts

    ents = {
        e.external_id: e
        for e in (
            await s.scalars(
                select(Entity).where(Entity.type == "attack-pattern", Entity.external_id.in_(list(rel)))
            )
        ).all()
    }
    from threatlens.detect.hunts import library

    hunted = {h["technique"] for h in library()}
    items = []
    for tid, info in rel.items():
        n = count_for(tid)
        e = ents.get(tid)
        items.append(
            {
                "technique": tid,
                "name": e.name if e else "",
                "weight": info["weight"],
                "why": info["why"][:5],
                "rules": n,
                "covered": n > 0,
                "hunt": tid in hunted
                or any(h.startswith(tid + ".") or tid.startswith(h + ".") for h in hunted),
                "tactics": (e.tactics if e else []) or [],
            }
        )
    items.sort(key=lambda x: (x["covered"], -x["weight"], x["technique"]))
    gaps = [i for i in items if not i["covered"]]
    version = await attack_version(s)
    gap_layer = layer(
        "Argus coverage gaps",
        "Relevant techniques without a detection rule (score = relevance).",
        version,
        {i["technique"]: (i["weight"], "; ".join(i["why"])) for i in gaps},
        maximum=max([i["weight"] for i in gaps] or [1]),
    )
    cov_layer = layer(
        "Argus detection coverage",
        "Relevant techniques: green covered, red not (score = rules).",
        version,
        {i["technique"]: (i["rules"], f"{i['rules']} rule(s); " + "; ".join(i["why"])) for i in items},
        gradient=("#e45756", "#54a24b"),
        maximum=max([i["rules"] for i in items] or [1]),
    )
    return {
        "rules": len(rows),
        "relevant": len(items),
        "covered": len(items) - len(gaps),
        "gaps": gaps,
        "items": items,
        "gapLayer": gap_layer,
        "coverageLayer": cov_layer,
    }
