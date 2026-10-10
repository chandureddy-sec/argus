"""Vulnerability patch priority P1-P4 (PROMPT §7, ADR 0008). Pure: no I/O.

Points for each signal (``config/scoring.yaml: patch_priority.points``) are
summed and mapped to a tier, then floors apply: anything in CISA KEV is at
least P2, and a KEV entry affecting our stack is P1. KEV is a floor that never
decays: an exploited vulnerability doesn't become safe with time.

Every reason is returned, so the tier can be checked by hand.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from threatlens.scoring.config import ScoringConfig

TIERS = ("P1", "P2", "P3", "P4")


@dataclass(frozen=True)
class VulnFacts:
    cve_id: str
    kev: bool = False
    kev_ransomware: str | None = None
    exploitation: str | None = None  # CISA ADP SSVC: none | poc | active
    exploit_refs: int = 0
    epss_percentile: float | None = None
    cvss_score: float | None = None


def _stricter(a: str, b: str) -> str:
    return a if TIERS.index(a) <= TIERS.index(b) else b


def patch_priority(
    v: VulnFacts, *, in_stack: Sequence[str], exposed: Sequence[str], cfg: ScoringConfig
) -> dict[str, Any]:
    pp = cfg.patch_priority
    pts = pp.points
    reasons: list[dict[str, Any]] = []

    def add(points: float, reason: str) -> None:
        reasons.append({"points": points, "reason": reason})

    if v.kev:
        add(pts.kev, "in CISA KEV: exploited in the wild")
        if v.kev_ransomware == "Known":
            add(pts.kev_ransomware, "KEV: known ransomware campaign use")
    elif v.exploitation == "active":
        add(pts.exploitation_active, "CISA SSVC: exploitation active")
    if v.exploitation == "poc" or (v.exploit_refs and not v.kev):
        add(pts.public_exploit, "public exploit or proof of concept")
    p = v.epss_percentile
    if p is not None:
        if p >= 0.95:
            add(pts.epss_95, f"EPSS percentile {p:.2f} (top 5%)")
        elif p >= 0.80:
            add(pts.epss_80, f"EPSS percentile {p:.2f} (top 20%)")
        elif p >= 0.50:
            add(pts.epss_50, f"EPSS percentile {p:.2f}")
    c = v.cvss_score
    if c is not None:
        if c >= 9.0:
            add(pts.cvss_critical, f"CVSS {c:g} (critical)")
        elif c >= 7.0:
            add(pts.cvss_high, f"CVSS {c:g} (high)")
        elif c >= 4.0:
            add(pts.cvss_medium, f"CVSS {c:g} (medium)")
    if in_stack:
        add(pts.in_stack, "affects our stack: " + ", ".join(sorted(in_stack)[:5]))
    if exposed:
        add(pts.exposed, "seen on our internet-facing assets: " + ", ".join(sorted(exposed)[:5]))

    total = sum(r["points"] for r in reasons)
    tier = "P4"
    for t in ("P3", "P2", "P1"):
        if total >= pp.tiers[t]:
            tier = t
    floor = None
    if v.kev and in_stack and _stricter(pp.kev_in_stack_floor, tier) != tier:
        floor = f"KEV entry affecting our stack: at least {pp.kev_in_stack_floor}"
        tier = pp.kev_in_stack_floor
    elif v.kev and _stricter(pp.kev_floor, tier) != tier:
        floor = f"KEV entry: at least {pp.kev_floor}"
        tier = pp.kev_floor
    return {
        "priority": tier,
        "score": total,
        "reasons": reasons,
        "floor": floor,
        "tiers": dict(pp.tiers),
        "config": cfg.tag,
    }
