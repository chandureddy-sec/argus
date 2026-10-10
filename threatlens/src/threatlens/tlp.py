"""TLP 2.0: who may read what, and where a value may be sent (ADR 0008).

Levels, least to most restricted: CLEAR < GREEN < AMBER < AMBER+STRICT < RED.

* **Reading.** Every API key and user account has a *clearance*, the most
  restricted level it may read (by default from its role: viewer GREEN,
  analyst AMBER+STRICT, admin RED). Read paths filter with :func:`readable`
  or :func:`may_read`; an item above the reader's clearance is treated as if it
  did not exist (404, left out of lists, counts and graph paths).
* **Sending.** Anything that leaves the platform is a *sink* with a maximum
  level (:data:`SINKS`). :func:`sink_allows` is the only test.
* **Unknown values fail closed**: an item whose TLP isn't one of the five
  levels is treated as RED; a reader whose clearance isn't one of them may
  read only CLEAR.
"""

from __future__ import annotations

from dataclasses import dataclass

LEVELS: tuple[str, ...] = ("TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED")
_RANK = {lv: i for i, lv in enumerate(LEVELS)}
RED = "TLP:RED"

DEFAULT_CLEARANCE = {"viewer": "TLP:GREEN", "analyst": "TLP:AMBER+STRICT", "admin": "TLP:RED"}


def rank(level: str | None) -> int:
    """Position in LEVELS; unknown or missing markings rank as RED (fail closed)."""
    return _RANK.get(level or "", _RANK[RED])


def normalize(level: str | None) -> str:
    """A known level as written, else RED."""
    return level if level in _RANK else RED


def stricter(*levels: str | None) -> str:
    """The most restricted of the given levels (CLEAR when none is given)."""
    given = [lv for lv in levels if lv is not None]
    return max((normalize(lv) for lv in given), key=rank) if given else LEVELS[0]


def _clearance_rank(clearance: str | None) -> int:
    return _RANK.get(clearance or "", 0)  # an unknown clearance reads CLEAR only


def may_read(clearance: str, level: str | None) -> bool:
    return rank(level) <= _clearance_rank(clearance)


def readable(clearance: str) -> list[str]:
    """Levels a reader with this clearance may see (for SQL ``IN``)."""
    return list(LEVELS[: _clearance_rank(clearance) + 1])


def clearance_for(role: str, explicit: str | None) -> str:
    """Effective clearance: the account's own setting, else its role's default."""
    if explicit is not None:
        return explicit if explicit in _RANK else LEVELS[0]
    return DEFAULT_CLEARANCE.get(role, LEVELS[0])


@dataclass(frozen=True)
class Sink:
    name: str
    max_level: str
    description: str


SINKS: dict[str, Sink] = {
    s.name: s
    for s in (
        Sink(
            "enricher:third_party",
            "TLP:GREEN",
            "A provider that receives the value but keeps lookups private (AbuseIPDB, RDAP, crt.sh…).",
        ),
        Sink(
            "enricher:disclosing",
            "TLP:CLEAR",
            "A provider whose lookups others can see (VirusTotal adds looked-up items to its corpus).",
        ),
    )
}


def sink_allows(sink: str, level: str | None) -> bool:
    """May a value marked ``level`` go to this sink? Unknown sinks allow nothing."""
    s = SINKS.get(sink)
    return s is not None and level in _RANK and rank(level) <= rank(s.max_level)
