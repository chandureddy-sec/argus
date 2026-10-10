"""Indicator scoring, model v1 (PROMPT §7, ADR 0008). Pure: no I/O.

    priority = clamp(0, 100, base + corroboration + relevance - penalty)

* **Signals** are reports about one observable: each feed sighting, each
  stored enrichment finding, and an analyst's "true positive". A signal's
  *contribution* is ``confidence x reliability weight x credibility x
  feedback factor x decay(age)``.
* **base** is the strongest malicious or suspicious contribution.
* **corroboration** adds ``per_source`` for each further independent
  *upstream* (abuse.ch's URLhaus and ThreatFox are one upstream) whose own
  contribution is still at least ``min_signal``; capped.
* **relevance** (PIR and own-asset matches) is added only while base is at
  least ``min_signal``: relevance makes a real report more urgent, it never
  turns "no report" into one.
* **penalty**: a fraction of the strongest benign finding (not decayed: it
  describes what the value is now) plus fixed context penalties (shared CDN,
  popular domain, dead domain).
* Suspicious-only evidence is capped below the malicious threshold.
* An allowlist suppression or analyst false positive gives 0 / ``benign``.

Only base and the corroboration count change with time, and both only go
down, so a score never rises without new evidence (property-tested).
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Literal

from threatlens.scoring.config import ScoringConfig

MODEL = "v1"
Verdict = Literal["malicious", "suspicious", "benign", "unknown"]
SignalKind = Literal["malicious", "suspicious", "benign"]

ACTIONS: dict[Verdict, tuple[str, str]] = {
    "malicious": ("block", "Block it, then search logs for past connections to it."),
    "suspicious": (
        "investigate",
        "Check what touched it and why before deciding; don't block on this alone.",
    ),
    "benign": ("no_action", "Known-good or own infrastructure: close the alert as benign."),
    "unknown": ("monitor", "No reputation either way; judge it on the alert's own context."),
}


@dataclass(frozen=True)
class Signal:
    source: str
    upstream: str
    grade: str  # Admiralty source reliability A-F
    kind: SignalKind
    confidence: int  # 0-100
    seen_at: datetime  # when the source last reported it
    credibility: int = 6  # Admiralty information credibility 1-6 (6: cannot be judged)
    factor: float = 1.0  # feedback-derived source weight factor
    text: str = ""


@dataclass(frozen=True)
class Hit:
    """A relevance bonus or a context penalty, with its reason."""

    kind: str
    points: float
    reason: str


@dataclass
class Score:
    priority: float
    verdict: Verdict
    breakdown: dict[str, Any]
    valid_until: datetime | None = None
    action: str = ""
    action_text: str = ""
    signals: list[dict[str, Any]] = field(default_factory=list)


def decay(age_days: float, half_life_days: float) -> float:
    return float(0.5 ** (max(0.0, age_days) / half_life_days))


def _age_days(now: datetime, then: datetime) -> float:
    return max(0.0, (now - then).total_seconds() / 86400)


def _r(x: float) -> float:
    return round(x, 2)


def score(
    signals: Iterable[Signal],
    *,
    obs_type: str,
    now: datetime,
    cfg: ScoringConfig,
    relevance: Sequence[Hit] = (),
    penalties: Sequence[Hit] = (),
    suppressed: str | None = None,
) -> Score:
    sigs = list(signals)
    half = cfg.half_life(obs_type)
    rows: list[dict[str, Any]] = []
    bad: list[tuple[float, Signal, dict[str, Any]]] = []
    start: dict[int, float] = {}  # contribution at age 0, per signal
    benign_best: tuple[float, Signal] | None = None
    for sg in sigs:
        w = cfg.weight(sg.grade, sg.credibility) * max(0.0, sg.factor)
        conf = max(0, min(100, sg.confidence))
        age = _age_days(now, sg.seen_at)
        d = 1.0 if sg.kind == "benign" else decay(age, half)  # benign evidence describes the present
        value = conf * w * d
        row = {
            "source": sg.source,
            "upstream": sg.upstream,
            "kind": sg.kind,
            "confidence": conf,
            "weight": _r(w),
            "decay": _r(d),
            "age_days": _r(age),
            "value": _r(value),
            "text": sg.text,
        }
        rows.append(row)
        if sg.kind == "benign":
            if benign_best is None or value > benign_best[0]:
                benign_best = (value, sg)
        else:
            bad.append((value, sg, row))
            start[id(sg)] = conf * w

    bad.sort(key=lambda t: t[0], reverse=True)
    base = bad[0][0] if bad else 0.0
    base_sig = bad[0][1] if bad else None
    min_sig = cfg.corroboration.min_signal
    counted = [(v, sg, row) for v, sg, row in bad if v >= min_sig]
    upstreams = list(dict.fromkeys(sg.upstream for _, sg, _ in counted))
    extra = [u for u in upstreams if base_sig is None or u != base_sig.upstream]
    corroboration = min(cfg.corroboration.cap, cfg.corroboration.per_source * len(extra))
    for _, _, row in counted:
        row["counted"] = True

    rel_applied = base >= min_sig
    rel_value = min(cfg.relevance.cap, sum(h.points for h in relevance)) if rel_applied else 0.0

    pen_items = [{"kind": h.kind, "points": _r(h.points), "reason": h.reason} for h in penalties]
    penalty = sum(h.points for h in penalties)
    if benign_best is not None:
        b = benign_best[0] * cfg.penalties.benign_fraction
        penalty += b
        pen_items.append(
            {"kind": "benign_evidence", "points": _r(b),
             "reason": f"{benign_best[1].source}: {benign_best[1].text}".strip(": ")}
        )  # fmt: skip

    raw = base + corroboration + rel_value - penalty
    has_malicious = any(sg.kind == "malicious" for _, sg, _ in counted)
    cap_note = None
    if not has_malicious and raw > cfg.suspicious_cap:
        raw = cfg.suspicious_cap
        cap_note = f"suspicious-only evidence: capped at {cfg.suspicious_cap:g}"
    priority = _r(max(0.0, min(100.0, raw)))

    verdict: Verdict
    if suppressed:
        priority = 0.0
        verdict = "benign"
    elif priority >= cfg.verdict.malicious:
        verdict = "malicious"
    elif priority >= cfg.verdict.suspicious:
        verdict = "suspicious"
    elif penalty >= cfg.verdict.benign_penalty:
        verdict = "benign"
    else:
        verdict = "unknown"

    valid_until = None
    below = cfg.expiry.below
    for _, sg, _row in bad:
        s0 = start[id(sg)]
        if s0 > below:
            t = sg.seen_at + timedelta(days=half * math.log2(s0 / below))
            valid_until = t if valid_until is None or t > valid_until else valid_until

    formula = f"{_r(base):g} + {_r(corroboration):g} + {_r(rel_value):g} - {_r(penalty):g}"
    breakdown: dict[str, Any] = {
        "model": MODEL,
        "config": cfg.tag,
        "computed_at": now.isoformat(),
        "obs_type": obs_type,
        "half_life_days": half,
        "base": {
            "value": _r(base),
            "source": base_sig.source if base_sig else None,
            "kind": base_sig.kind if base_sig else None,
        },
        "corroboration": {"value": _r(corroboration), "upstreams": extra},
        "relevance": {
            "value": _r(rel_value),
            "applied": rel_applied,
            "hits": [{"kind": h.kind, "points": _r(h.points), "reason": h.reason} for h in relevance],
        },
        "penalty": {"value": _r(penalty), "items": pen_items},
        "cap": cap_note,
        "suppressed": suppressed,
        "formula": f"{formula} = {priority:g}" if not suppressed else f"suppressed: {suppressed}",
        "priority": priority,
        "verdict": verdict,
        "thresholds": {"malicious": cfg.verdict.malicious, "suspicious": cfg.verdict.suspicious},
        "signals": sorted(rows, key=lambda r: -r["value"]),
    }
    action, text = ACTIONS[verdict]
    return Score(priority, verdict, breakdown, valid_until, action, text, breakdown["signals"])
