"""Deterministic identifiers for graph nodes and derived edges.

ATT&CK objects keep MITRE's STIX ids. Everything ThreatLens creates itself
(indicators, CVEs, feed-named malware, derived edges) gets a uuid5 under one
fixed namespace, so the same fact always maps to the same id: re-ingesting
never duplicates a node, and a STIX export (Phase 6) is stable across runs.
"""

from __future__ import annotations

import re
import uuid

# Fixed forever: changing it would re-key every derived node and edge.
NAMESPACE = uuid.UUID("6f1c7e2a-3b4d-5e6f-8a9b-0c1d2e3f4a5b")

_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
CVE_IN_TEXT = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def stix_id(stix_type: str, key: str) -> str:
    return f"{stix_type}--{uuid.uuid5(NAMESPACE, f'{stix_type}:{key}')}"


def indicator_stix_id(canonical_key: str) -> str:
    return stix_id("indicator", canonical_key)


def vulnerability_stix_id(cve: str) -> str:
    return stix_id("vulnerability", cve.upper())


def edge_stix_id(src: str, rel: str, dst: str, origin: str) -> str:
    return stix_id("relationship", f"{src}|{rel}|{dst}|{origin}")


def is_cve(value: str) -> bool:
    return bool(_CVE.match(value.upper()))


def alias_key(name: str) -> str:
    """'Cobalt Strike', 'cobalt-strike' and 'CobaltStrike' all become 'cobaltstrike'."""
    return re.sub(r"[^a-z0-9]", "", name.lower())[:200]
