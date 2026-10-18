"""The hunt library (ADR 0020): Sigma hunts per ATT&CK technique
(``detect/hunts.yml``), each with its data-source requirements and false
positives, compiled once to Splunk, KQL and Lucene."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from threatlens.detect import rules as gen

LIBRARY = Path(__file__).with_name("hunts.yml")
AUTHOR = "Argus hunt library"
DATE = "2026-10-18"


@lru_cache(maxsize=1)
def library() -> tuple[dict[str, Any], ...]:
    """Every hunt with its Sigma text and compiled queries (cached: compiling takes a second)."""
    entries = yaml.safe_load(LIBRARY.read_text(encoding="utf-8"))
    out = []
    for e in entries:
        rule = {
            **e["rule"],
            "author": AUTHOR,
            "date": DATE,
            "references": [f"https://attack.mitre.org/techniques/{e['technique'].replace('.', '/')}/"],
        }
        body = yaml.safe_dump(rule, sort_keys=False, width=120)
        queries, problems = gen.compile_sigma(body)
        out.append(
            {
                "technique": e["technique"],
                "title": rule["title"],
                "description": rule["description"],
                "dataSources": e["data_sources"],
                "falsepositives": rule.get("falsepositives", []),
                "level": rule.get("level"),
                "tags": rule.get("tags", []),
                "sigma": body,
                "queries": queries,
                "problems": problems,
            }
        )
    return tuple(out)


def for_techniques(ids: set[str]) -> list[dict[str, Any]]:
    """Hunts for these techniques, or their parent (T1059.001 covers a T1059 request too)."""
    want = {i.upper() for i in ids}
    parents = {i.split(".")[0] for i in want}
    return [h for h in library() if h["technique"] in want or h["technique"].split(".")[0] in parents]
