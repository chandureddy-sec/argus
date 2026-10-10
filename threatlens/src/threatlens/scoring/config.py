"""Scoring configuration (``config/scoring.yaml``), validated strictly.

``ScoringConfig.version`` combines the file's own ``version`` with a short
hash of its content, and is stored with every score.
"""

from __future__ import annotations

import hashlib
from functools import lru_cache
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Tier = Literal["P1", "P2", "P3", "P4"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Corroboration(_Strict):
    per_source: float = Field(ge=0, le=50)
    cap: float = Field(ge=0, le=100)
    min_signal: float = Field(ge=0, le=100)


class Relevance(_Strict):
    cap: float = Field(ge=0, le=100)
    own_asset: float = Field(ge=0, le=100)
    impersonation: float = Field(ge=0, le=100)
    technique: float = Field(ge=0, le=100)
    sector: float = Field(ge=0, le=100)
    geography: float = Field(ge=0, le=100)


class Penalties(_Strict):
    benign_fraction: float = Field(ge=0, le=1)
    shared_cdn: float = Field(ge=0, le=100)
    popular_domain: float = Field(ge=0, le=100)
    dead_domain: float = Field(ge=0, le=100)


class VerdictCfg(_Strict):
    malicious: float = Field(gt=0, le=100)
    suspicious: float = Field(gt=0, le=100)
    benign_penalty: float = Field(ge=0, le=100)

    @model_validator(mode="after")
    def _order(self) -> VerdictCfg:
        if self.suspicious >= self.malicious:
            raise ValueError("verdict.suspicious must be below verdict.malicious")
        return self


class Expiry(_Strict):
    below: float = Field(gt=0, le=100)


class Feedback(_Strict):
    prior_precision: float = Field(gt=0, le=1)
    pseudo_count: float = Field(gt=0)
    min_factor: float = Field(gt=0, le=1)
    max_factor: float = Field(ge=1, le=2)
    analyst_confidence: int = Field(ge=0, le=100)


class PatchPoints(_Strict):
    kev: float
    kev_ransomware: float
    exploitation_active: float
    public_exploit: float
    epss_95: float
    epss_80: float
    epss_50: float
    cvss_critical: float
    cvss_high: float
    cvss_medium: float
    in_stack: float
    exposed: float


class PatchPriority(_Strict):
    points: PatchPoints
    tiers: dict[Literal["P1", "P2", "P3"], float]
    kev_floor: Tier
    kev_in_stack_floor: Tier

    @field_validator("tiers")
    @classmethod
    def _tiers(cls, v: dict[str, float]) -> dict[str, float]:
        if set(v) != {"P1", "P2", "P3"} or not v["P1"] > v["P2"] > v["P3"]:
            raise ValueError("patch_priority.tiers needs P1 > P2 > P3")
        return v


class ScoringConfig(_Strict):
    version: str = Field(min_length=1, max_length=20)
    reliability_weights: dict[str, float]  # A-F, checked below
    credibility_modifiers: dict[int, float]
    half_life_days: dict[str, float]
    corroboration: Corroboration
    relevance: Relevance
    penalties: Penalties
    suspicious_cap: float = Field(ge=0, le=100)
    verdict: VerdictCfg
    expiry: Expiry
    feedback: Feedback
    patch_priority: PatchPriority
    content_hash: str = ""

    @field_validator("reliability_weights")
    @classmethod
    def _weights(cls, v: dict[str, float]) -> dict[str, float]:
        if set(v) != set("ABCDEF") or not all(0 <= w <= 1 for w in v.values()):
            raise ValueError("reliability_weights needs A-F, each between 0 and 1")
        return v

    @field_validator("credibility_modifiers")
    @classmethod
    def _cred(cls, v: dict[int, float]) -> dict[int, float]:
        if set(v) != {1, 2, 3, 4, 5, 6} or not all(0 <= m <= 1 for m in v.values()):
            raise ValueError("credibility_modifiers needs 1-6, each between 0 and 1")
        return v

    @field_validator("half_life_days")
    @classmethod
    def _half(cls, v: dict[str, float]) -> dict[str, float]:
        if "default" not in v or not all(h > 0 for h in v.values()):
            raise ValueError("half_life_days needs a positive 'default' and positive values")
        return v

    @property
    def tag(self) -> str:
        """Stored with every score: '<version>/<first 8 hex of the file's SHA-256>'."""
        return f"{self.version}/{self.content_hash[:8]}" if self.content_hash else self.version

    def half_life(self, obs_type: str) -> float:
        return self.half_life_days.get(obs_type, self.half_life_days["default"])

    def weight(self, grade: str, credibility: int) -> float:
        return self.reliability_weights.get(grade, 0.0) * self.credibility_modifiers.get(credibility, 1.0)


class ScoringConfigError(ValueError):
    pass


def load_config(path: Path) -> ScoringConfig:
    try:
        raw = path.read_bytes()
        data = yaml.safe_load(raw)
        cfg = ScoringConfig.model_validate(data)
    except OSError as e:
        raise ScoringConfigError(f"cannot read {path}: {e}") from e
    except (yaml.YAMLError, ValueError) as e:
        raise ScoringConfigError(f"{path}: {e}") from e
    return cfg.model_copy(update={"content_hash": hashlib.sha256(raw).hexdigest()})


@lru_cache(maxsize=8)
def _cached(path: str, mtime: float) -> ScoringConfig:
    return load_config(Path(path))


def get_config(path: Path) -> ScoringConfig:
    """Load once per file version (re-read when the file changes)."""
    try:
        mtime = path.stat().st_mtime
    except OSError as e:
        raise ScoringConfigError(f"cannot read {path}: {e}") from e
    return _cached(str(path), mtime)
