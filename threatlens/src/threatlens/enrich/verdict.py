"""Interim verdict for lookups (model ``v0``; ADR 0005).

Phase 4 brings the full scoring model (reliability weights, decay, PIR
relevance). Until then a lookup still has to say *something* a SOC analyst
can act on, so this combines the evidence in a small, explainable way:

* per source, only its strongest finding of each kind counts (one feed
  reporting an IP five times is still one source);
* malicious part = strongest malicious weight + 5 per further independent
  malicious source (max +15);
* suspicious part = strongest suspicious weight + 5 per further source
  (max +10), capped at 69: suspicion alone never reaches "malicious";
* score = the larger part, minus half the strongest benign weight;
* an allowlist suppression (our own assets, analyst allowlist, top domains)
  makes the verdict benign whatever else was found.

Every step is returned in ``breakdown`` so the number can be checked by hand.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Literal

from threatlens.enrich.base import Evidence

MODEL = "v0-interim"
Verdict = Literal["malicious", "suspicious", "benign", "unknown"]

ACTIONS: dict[Verdict, tuple[str, str]] = {
    "malicious": ("block", "Block it, then search logs for past connections to it."),
    "suspicious": (
        "investigate",
        "Check what touched it and why before deciding; don't block on this alone.",
    ),
    "benign": ("no_action", "Known-good or own infrastructure: close the alert as benign."),
    "unknown": ("monitor", "No reputation either way; judge it on the alert's own context."),
}


@dataclass
class Assessment:
    verdict: Verdict
    score: int
    action: str
    action_text: str
    breakdown: list[dict[str, Any]] = field(default_factory=list)
    model: str = MODEL


def _strongest(evidence: Iterable[Evidence], kind: str) -> list[tuple[int, str]]:
    best: dict[str, int] = {}
    for e in evidence:
        if e.kind == kind and e.weight > best.get(e.source, -1):
            best[e.source] = e.weight
    return sorted(((w, s) for s, w in best.items()), reverse=True)


def assess(evidence: Iterable[Evidence], *, suppressed_by: str | None = None) -> Assessment:
    ev = list(evidence)
    mal, sus, ben = _strongest(ev, "malicious"), _strongest(ev, "suspicious"), _strongest(ev, "benign")
    steps: list[dict[str, Any]] = []
    mal_part = sus_part = 0
    if mal:
        bonus = min(15, 5 * (len(mal) - 1))
        mal_part = mal[0][0] + bonus
        steps.append({"step": "strongest malicious finding", "source": mal[0][1], "value": mal[0][0]})
        if bonus:
            steps.append(
                {
                    "step": "further independent malicious sources",
                    "sources": [s for _, s in mal[1:]],
                    "value": bonus,
                }
            )
    if sus:
        bonus = min(10, 5 * (len(sus) - 1))
        sus_part = min(69, sus[0][0] + bonus)
        steps.append(
            {
                "step": "strongest suspicious finding (+5 per further source, max 69)",
                "source": sus[0][1],
                "value": sus_part,
            }
        )
    score = max(mal_part, sus_part)
    if ben:
        steps.append(
            {
                "step": "minus half the strongest benign finding",
                "source": ben[0][1],
                "value": -(ben[0][0] // 2),
            }
        )
        score -= ben[0][0] // 2
    score = max(0, min(100, score))
    verdict: Verdict
    if suppressed_by:
        verdict = "benign"
        steps.append({"step": "allowlisted", "reason": suppressed_by, "value": None})
    elif score >= 70:
        verdict = "malicious"
    elif score >= 30:
        verdict = "suspicious"
    elif ben and ben[0][0] >= 50:
        verdict = "benign"
    else:
        verdict = "unknown"
    steps.append({"step": "thresholds: malicious >= 70, suspicious >= 30", "value": score})
    action, text = ACTIONS[verdict]
    return Assessment(verdict, score, action, text, steps)
