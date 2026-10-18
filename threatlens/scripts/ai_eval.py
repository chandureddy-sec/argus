"""Run the report-assistant evaluation on the SYNTHETIC set (ADR 0022).

    uv run python scripts/ai_eval.py            # deterministic extractor + the guard
    uv run python scripts/ai_eval.py --model    # also the configured Claude model

The model is measured only with --model and a configured key
(TL_AI_ENABLED=true plus TL_AI_API_KEY or the Anthropic SDK's own credentials).
"""

from __future__ import annotations

import argparse
import asyncio
import json

from threatlens import ai, ai_eval
from threatlens.settings import get_settings


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", action="store_true", help="also measure the configured Claude model")
    ap.add_argument("--json", action="store_true", help="print JSON instead of text")
    args = ap.parse_args()
    rows = ai_eval.load()
    out: dict[str, object] = {"dataset": str(ai_eval.DATASET.name), "reports": len(rows), "synthetic": True}
    out["deterministic"] = ai_eval.deterministic(rows).view()
    ora, att = ai_eval.guard(rows)
    out["guard_oracle"] = ora.view()
    out["guard_attacker"] = att.view()
    out["injection_flags"] = inj = ai_eval.injection(rows)
    settings = get_settings()
    if args.model and settings.ai_enabled:
        out["model"] = {"name": settings.ai_model} | (
            await ai_eval.model_score(rows, ai.ClaudeModel(settings))
        ).view()
    else:
        out["model"] = "not measured: no model configured (TL_AI_ENABLED and a key, then --model)"
    if args.json:
        print(json.dumps(out, indent=2))
        return
    d = out["deterministic"]
    print(f"SYNTHETIC evaluation set: {len(rows)} reports (fabricated, not real intelligence)\n")
    print(
        f"Deterministic extractor   precision {d['precision']:.3f}  recall {d['recall']:.3f}  "  # type: ignore[index]
        f"(tp {d['tp']}, fp {d['fp']}, fn {d['fn']})"  # type: ignore[index]
    )
    print(
        f"Guard, oracle model       kept {ora.true_kept}/{ora.true_items} true items "
        f"({ora.true_kept / max(ora.true_items, 1):.1%})"
    )
    print(
        f"Guard, attacker model     planted items kept {att.planted_kept}/{att.planted} "
        f"(of those, {att.planted_kept_in_text} were literally in the report text and "
        f"{att.planted_kept_flagged} came with an injection warning); "
        f"summaries with foreign values dropped {att.summaries_dropped}/{att.reports}"
    )
    print(
        f"Injection heuristic       flagged {inj['flagged']}/{inj['injected']} injected reports, "
        f"{inj['falseFlags']} clean report(s) flagged"
    )
    print(f"Model                     {out['model']}")


if __name__ == "__main__":
    asyncio.run(main())
