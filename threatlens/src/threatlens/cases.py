"""Cases, indicator notes and saved searches (Phase 5, ADR 0009).

* A **case** collects evidence (indicators, CVEs, entities, looked-up values,
  free notes), a summary and a documented conclusion. Each item stores a
  *snapshot* of what the platform said when it was added (verdict, score,
  formula, sources), so a case still reads the same after scores change.
* **TLP**: a case is at least as restricted as its strictest item. Adding an
  AMBER indicator to a GREEN case makes the case AMBER. Readers below the
  case's marking don't see it at all, and nobody can add an item they can't
  read themselves.
* Every change is audited (``case.create``, ``case.update``, ``case.item.add``,
  ``case.item.remove``, ``case.export``, ``note.create``).
* Exports: Markdown, with the TLP marking as its first line and every value
  defanged; and a print view the browser saves as PDF.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from threatlens import tlp as tlp_rules
from threatlens.models import (
    CASE_ITEM_KINDS,
    CASE_SEVERITIES,
    CASE_STATUSES,
    AuditLog,
    Case,
    CaseItem,
    Entity,
    Indicator,
    Note,
    SavedSearch,
    Sighting,
    Source,
    Vulnerability,
)
from threatlens.models import Observable as ObsRow

MAX_TITLE, MAX_TEXT, MAX_NOTE = 200, 20_000, 5_000


class CaseError(ValueError):
    """A request about a case that can't be honoured (shown to the user)."""


def _now() -> datetime:
    return datetime.now(UTC)


def visible(clearance: str) -> Any:
    return Case.tlp.in_(tlp_rules.readable(clearance))


def _check(title: str, severity: str, tlp: str) -> None:
    if not title.strip() or len(title) > MAX_TITLE:
        raise CaseError(f"a title is 1-{MAX_TITLE} characters")
    if severity not in CASE_SEVERITIES:
        raise CaseError(f"severity must be one of {', '.join(CASE_SEVERITIES)}")
    if tlp not in tlp_rules.LEVELS:
        raise CaseError(f"TLP must be one of {', '.join(tlp_rules.LEVELS)}")


async def create_case(
    s: AsyncSession,
    *,
    title: str,
    actor: str,
    clearance: str,
    severity: str = "medium",
    tlp: str = "TLP:AMBER",
    summary: str = "",
) -> Case:
    _check(title, severity, tlp)
    if not tlp_rules.may_read(clearance, tlp):
        raise CaseError(f"you can't create a {tlp} case: your clearance is {clearance}")
    c = Case(
        title=title.strip(), severity=severity, tlp=tlp, summary=summary[:MAX_TEXT], conclusion="",
        status="open", created_by=actor[:100], created_at=_now(), updated_at=_now(),
    )  # fmt: skip
    s.add(c)
    await s.flush()
    s.add(AuditLog(actor=actor[:100], action="case.create", target=f"case:{c.id}",
                   details={"title": c.title, "severity": severity, "tlp": tlp}))  # fmt: skip
    return c


async def get_case(s: AsyncSession, case_id: int, clearance: str) -> Case | None:
    return await s.scalar(
        select(Case).where(Case.id == case_id, visible(clearance)).options(selectinload(Case.items))
    )


async def list_cases(
    s: AsyncSession, clearance: str, *, status: str | None = None, q: str | None = None, limit: int = 200
) -> list[tuple[Case, int]]:
    stmt = (
        select(Case, func.count(CaseItem.id))
        .outerjoin(CaseItem, CaseItem.case_id == Case.id)
        .where(visible(clearance))
        .group_by(Case.id)
        .order_by(Case.status.desc(), Case.updated_at.desc())  # open before closed
        .limit(limit)
    )
    if status in CASE_STATUSES:
        stmt = stmt.where(Case.status == status)
    if q:
        like = "%" + q.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        stmt = stmt.where(func.lower(Case.title).like(like, escape="\\"))
    return [(c, int(n)) for c, n in (await s.execute(stmt)).all()]


async def update_case(
    s: AsyncSession,
    case: Case,
    *,
    actor: str,
    status: str | None = None,
    severity: str | None = None,
    summary: str | None = None,
    conclusion: str | None = None,
    title: str | None = None,
) -> Case:
    changes: dict[str, Any] = {}
    if status is not None:
        if status not in CASE_STATUSES:
            raise CaseError("status must be open or closed")
        if status != case.status:
            changes["status"] = [case.status, status]
            case.status = status
            case.closed_at = _now() if status == "closed" else None
    if severity is not None:
        if severity not in CASE_SEVERITIES:
            raise CaseError(f"severity must be one of {', '.join(CASE_SEVERITIES)}")
        if severity != case.severity:
            changes["severity"] = [case.severity, severity]
            case.severity = severity
    if title is not None:
        _check(title, case.severity, case.tlp)
        if title.strip() != case.title:
            changes["title"] = [case.title, title.strip()]
            case.title = title.strip()
    if summary is not None and summary != case.summary:
        case.summary = summary[:MAX_TEXT]
        changes["summary"] = "edited"
    if conclusion is not None and conclusion != case.conclusion:
        case.conclusion = conclusion[:MAX_TEXT]
        changes["conclusion"] = "edited"
    if changes:
        case.updated_at = _now()
        s.add(AuditLog(actor=actor[:100], action="case.update", target=f"case:{case.id}", details=changes))
    return case


async def add_item(
    s: AsyncSession,
    case: Case,
    *,
    kind: str,
    ref: str,
    label: str,
    snapshot: dict[str, Any],
    tlp: str,
    actor: str,
    note: str = "",
) -> CaseItem:
    """Add evidence. The same indicator/CVE/entity is added once (a second add
    only updates its note); the case's TLP rises to the item's."""
    if kind not in CASE_ITEM_KINDS:
        raise CaseError(f"kind must be one of {', '.join(CASE_ITEM_KINDS)}")
    if case.status != "open":
        raise CaseError("the case is closed: reopen it to add evidence")
    tlp = tlp_rules.normalize(tlp)
    item = None
    if kind != "note":
        item = await s.scalar(
            select(CaseItem).where(CaseItem.case_id == case.id, CaseItem.kind == kind, CaseItem.ref == ref)
        )
    if item is None:
        item = CaseItem(
            case_id=case.id, kind=kind, ref=ref[:200], label=label[:2000], snapshot=snapshot,
            note=note[:MAX_NOTE], tlp=tlp, added_by=actor[:100], added_at=_now(),
        )  # fmt: skip
        s.add(item)
    elif note:
        item.note = note[:MAX_NOTE]
    stricter = tlp_rules.stricter(case.tlp, tlp)
    details: dict[str, Any] = {"kind": kind, "ref": ref[:200]}
    if stricter != case.tlp:
        details["case_tlp"] = [case.tlp, stricter]
        case.tlp = stricter
    case.updated_at = _now()
    await s.flush()
    s.add(AuditLog(actor=actor[:100], action="case.item.add", target=f"case:{case.id}", details=details))
    return item


async def remove_item(s: AsyncSession, case: Case, item_id: int, *, actor: str) -> bool:
    item = await s.scalar(select(CaseItem).where(CaseItem.id == item_id, CaseItem.case_id == case.id))
    if item is None:
        return False
    await s.delete(item)
    case.updated_at = _now()
    s.add(AuditLog(actor=actor[:100], action="case.item.remove", target=f"case:{case.id}",
                   details={"kind": item.kind, "ref": item.ref}))  # fmt: skip
    return True


# ── evidence snapshots ───────────────────────────────────────────────────────


async def indicator_evidence(
    s: AsyncSession, indicator_id: int, clearance: str
) -> tuple[str, str, dict[str, Any], str] | None:
    """(ref, label, snapshot, tlp) for an indicator the reader may see."""
    row = (
        await s.execute(
            select(Indicator, ObsRow)
            .join(ObsRow, ObsRow.id == Indicator.observable_id)
            .where(Indicator.id == indicator_id)
        )
    ).first()
    if row is None or not tlp_rules.may_read(clearance, row[0].tlp):
        return None
    ind, obs = row
    sources = sorted(
        (await s.scalars(select(Source.name).join(Sighting).where(Sighting.indicator_id == ind.id))).all()
    )
    bd = ind.score_breakdown or {}
    snap = {
        "type": obs.type,
        "status": ind.status,
        "priority": ind.priority_score,
        "verdict": bd.get("verdict"),
        "formula": bd.get("formula"),
        "config": bd.get("config"),
        "sources": sources,
        "analyst_verdict": ind.analyst_verdict,
        "labels": (ind.labels or [])[:10],
    }
    return str(ind.id), obs.defanged, snap, ind.tlp


async def vulnerability_evidence(s: AsyncSession, cve: str) -> tuple[str, str, dict[str, Any], str] | None:
    v = await s.scalar(select(Vulnerability).where(Vulnerability.cve_id == cve.upper()))
    if v is None:
        return None
    snap = {
        "patch_priority": v.patch_priority,
        "patch_score": v.patch_score,
        "kev": v.kev,
        "epss_percentile": v.epss_percentile,
        "cvss": v.cvss_score,
        "name": v.kev_name or (v.description or "")[:200],
    }
    return v.cve_id, v.cve_id, snap, "TLP:CLEAR"


async def entity_evidence(s: AsyncSession, ref: str) -> tuple[str, str, dict[str, Any], str] | None:
    e = await s.scalar(select(Entity).where(Entity.stix_id == ref))
    if e is None:
        return None
    return e.stix_id, e.name, {"type": e.type, "external_id": e.external_id}, "TLP:CLEAR"


def lookup_evidence(result: dict[str, Any]) -> tuple[str, str, dict[str, Any], str]:
    """A looked-up value (not necessarily an indicator) as evidence."""
    q = result["query"]
    snap = {
        "type": q["type"],
        "verdict": result["verdict"],
        "priority": result.get("priority", result.get("score")),
        "action": result["recommended_action"],
        "formula": (result.get("score_breakdown") or {}).get("formula"),
        "sources": (result.get("known") or {}).get("sources", []),
        "evidence": [e["text"][:200] for e in result.get("evidence", [])[:5]],
    }
    return q["canonical_key"], q["defanged"], snap, result.get("tlp") or "TLP:CLEAR"


# ── exports ──────────────────────────────────────────────────────────────────


def _md(text: object) -> str:
    """One table cell or line: no newlines, no pipe breaking the table, no HTML."""
    return (
        str(text if text is not None else "")
        .replace("\r", " ")
        .replace("\n", " ")
        .replace("|", "\\|")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .strip()
    )


def _block(text: str) -> str:
    return (text or "").replace("<", "&lt;").replace(">", "&gt;").strip() or "_none_"


def item_summary(item: CaseItem) -> str:
    sn = item.snapshot or {}
    if item.kind in ("indicator", "observable"):
        bits = [str(sn.get("verdict") or "unknown")]
        if sn.get("priority") is not None:
            bits.append(f"priority {float(sn['priority']):.0f}")
        if sn.get("sources"):
            bits.append("sources: " + ", ".join(sn["sources"]))
        if sn.get("analyst_verdict"):
            bits.append(f"analyst: {sn['analyst_verdict'].upper()}")
        return "; ".join(bits)
    if item.kind == "vulnerability":
        bits = [f"patch {sn.get('patch_priority') or '?'}"]
        if sn.get("kev"):
            bits.append("CISA KEV")
        if sn.get("cvss") is not None:
            bits.append(f"CVSS {sn['cvss']}")
        return "; ".join(bits)
    if item.kind == "entity":
        return " ".join(str(x) for x in (sn.get("type"), sn.get("external_id")) if x)
    return ""


def to_markdown(case: Case, *, exported_by: str) -> str:
    lines = [
        f"**{case.tlp}**",
        "",
        f"# Case {case.id}: {_md(case.title)}",
        "",
        f"- Status: {case.status}"
        + (f" (closed {case.closed_at:%Y-%m-%d %H:%M} UTC)" if case.closed_at else ""),
        f"- Severity: {case.severity}",
        f"- Opened by {_md(case.created_by)} on {case.created_at:%Y-%m-%d %H:%M} UTC",
        f"- Exported by {_md(exported_by)} on {_now():%Y-%m-%d %H:%M} UTC from ThreatLens",
        "",
        "## Summary",
        "",
        _block(case.summary),
        "",
        "## Conclusion",
        "",
        _block(case.conclusion),
        "",
        "## Evidence",
        "",
    ]
    evidence = [i for i in case.items if i.kind != "note"]
    if evidence:
        lines += [
            "| # | Kind | Value (defanged) | What ThreatLens said | Analyst note | Added |",
            "|---|---|---|---|---|---|",
        ]
        for n, i in enumerate(evidence, 1):
            lines.append(
                f"| {n} | {i.kind} | `{_md(i.label)}` | {_md(item_summary(i))} | {_md(i.note)} | "
                f"{_md(i.added_by)}, {i.added_at:%Y-%m-%d %H:%M} |"
            )
    else:
        lines.append("_No evidence yet._")
    notes = [i for i in case.items if i.kind == "note"]
    if notes:
        lines += ["", "## Notes", ""]
        for i in notes:
            lines += [f"- **{_md(i.added_by)}**, {i.added_at:%Y-%m-%d %H:%M} UTC: {_md(i.note)}"]
    lines += [
        "",
        "---",
        f"Marking: {case.tlp}. Values are defanged; refang them deliberately, not by copy-paste.",
        "",
    ]
    return "\n".join(lines)


# ── indicator notes ──────────────────────────────────────────────────────────


async def add_note(s: AsyncSession, indicator_id: int, *, author: str, body: str) -> Note:
    body = body.strip()
    if not body or len(body) > MAX_NOTE:
        raise CaseError(f"a note is 1-{MAX_NOTE} characters")
    n = Note(indicator_id=indicator_id, author=author[:100], body=body, created_at=_now())
    s.add(n)
    s.add(AuditLog(actor=author[:100], action="note.create", target=f"indicator:{indicator_id}", details={}))
    await s.flush()
    return n


async def notes_for(s: AsyncSession, indicator_id: int, limit: int = 100) -> Sequence[Note]:
    return (
        await s.scalars(
            select(Note)
            .where(Note.indicator_id == indicator_id)
            .order_by(Note.created_at.desc())
            .limit(limit)
        )
    ).all()


# ── saved searches ───────────────────────────────────────────────────────────


def owner_key(kind: str, ident: int) -> str:
    return f"{kind}:{ident}"


def check_query(query: str) -> str:
    """Only paths inside the UI may be saved (no open redirect, no other host)."""
    q = query.strip()
    parts = urlsplit(q)
    if parts.scheme or parts.netloc or not q.startswith("/ui") or "//" in q or "\\" in q or len(q) > 2000:
        raise CaseError("only views inside the ThreatLens UI can be saved")
    return q


async def save_search(s: AsyncSession, owner: str, name: str, query: str) -> SavedSearch:
    name = name.strip()
    if not name or len(name) > 100:
        raise CaseError("a name is 1-100 characters")
    q = check_query(query)
    row = await s.scalar(select(SavedSearch).where(SavedSearch.owner == owner, SavedSearch.name == name))
    if row is None:
        row = SavedSearch(owner=owner, name=name, query=q, created_at=_now())
        s.add(row)
    else:
        row.query = q
    await s.flush()
    return row


async def saved_searches(s: AsyncSession, owner: str) -> Sequence[SavedSearch]:
    return (
        await s.scalars(select(SavedSearch).where(SavedSearch.owner == owner).order_by(SavedSearch.name))
    ).all()


async def delete_search(s: AsyncSession, owner: str, search_id: int) -> bool:
    row = await s.scalar(select(SavedSearch).where(SavedSearch.id == search_id, SavedSearch.owner == owner))
    if row is None:
        return False
    await s.delete(row)
    return True
