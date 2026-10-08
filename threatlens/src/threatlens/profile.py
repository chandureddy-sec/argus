"""Organization profile and Priority Intelligence Requirements (PIRs).

The profile describes what we defend (domains, IP ranges, brands, vendors, tech
stack, sectors, geography); the PIRs describe what we need to know about
threats to it. Both are plain YAML meant to be reviewed and committed, so they
are validated strictly: a typo should fail loudly at load time, not silently
make a PIR match nothing.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Annotated, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator

# ISO 3166-1 alpha-2 country codes are two upper-case letters; full list
# validation would pin us to a library release for no real benefit.
CountryCode = Annotated[str, StringConstraints(pattern=r"^[A-Z]{2}$")]
Slug = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9_]*$", max_length=64)]
TechniqueID = Annotated[str, StringConstraints(pattern=r"^T\d{4}(\.\d{3})?$")]

_HOSTNAME = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$")
# CPE 2.3 formatted string: "cpe:2.3:" + part (a|o|h) + vendor + product + optional fields.
_CPE23 = re.compile(r"^cpe:2\.3:[aoh\*]:[^:\s]+:[^:\s]+(:[^:\s]+)*$")

MatchTarget = Literal["domains", "brands", "ip_ranges", "vendors", "tech_stack", "sectors", "geography"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class TechItem(_Strict):
    product: str = Field(min_length=1, max_length=200)
    cpe: str

    @field_validator("cpe")
    @classmethod
    def _cpe(cls, v: str) -> str:
        v = v.lower()
        if not _CPE23.match(v):
            raise ValueError(f"not a CPE 2.3 string: {v!r} (expected cpe:2.3:<part>:<vendor>:<product>:...)")
        return v


class Org(_Strict):
    name: str = Field(min_length=1, max_length=200)
    sectors: list[Slug] = Field(default_factory=list)
    geography: list[CountryCode] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    brands: list[str] = Field(default_factory=list)
    ip_ranges: list[str] = Field(default_factory=list)
    vendors: list[Slug] = Field(default_factory=list)
    tech_stack: list[TechItem] = Field(default_factory=list)

    @field_validator("domains")
    @classmethod
    def _domains(cls, v: list[str]) -> list[str]:
        out = []
        for d in v:
            d = d.strip().lower().rstrip(".")
            if not _HOSTNAME.match(d):
                raise ValueError(f"not a valid domain name: {d!r}")
            out.append(d)
        return out

    @field_validator("ip_ranges")
    @classmethod
    def _ranges(cls, v: list[str]) -> list[str]:
        out = []
        for r in v:
            try:
                out.append(str(ipaddress.ip_network(r.strip(), strict=True)))
            except ValueError as e:
                raise ValueError(f"not a valid CIDR range: {r!r} ({e})") from e
        return out


class OrgProfile(_Strict):
    org: Org


class Watch(_Strict):
    sectors: list[Slug] = Field(default_factory=list)
    geography: list[CountryCode] = Field(default_factory=list)
    techniques: list[TechniqueID] = Field(default_factory=list)
    sources: list[Slug] = Field(default_factory=list)
    match: list[MatchTarget] = Field(default_factory=list)

    @field_validator("match", mode="before")
    @classmethod
    def _one_or_many(cls, v: object) -> object:
        # YAML authors write both `match: tech_stack` and `match: [domains, brands]`.
        return [v] if isinstance(v, str) else v

    @model_validator(mode="after")
    def _not_empty(self) -> Watch:
        if not (self.sectors or self.geography or self.techniques or self.sources or self.match):
            raise ValueError(
                "watch must name at least one of: sectors, geography, techniques, sources, match"
            )
        return self


class PIR(_Strict):
    id: Annotated[str, StringConstraints(pattern=r"^PIR-\d+$")]
    question: str = Field(min_length=10, max_length=1000)
    watch: Watch


class PIRSet(_Strict):
    pirs: list[PIR] = Field(min_length=1)

    @model_validator(mode="after")
    def _unique_ids(self) -> PIRSet:
        seen: set[str] = set()
        for p in self.pirs:
            if p.id in seen:
                raise ValueError(f"duplicate PIR id {p.id}")
            seen.add(p.id)
        return self


class ProfileError(ValueError):
    """Raised when a profile or PIR file can't be read or fails validation."""


def _load_yaml(path: Path) -> object:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        raise ProfileError(f"cannot read {path}: {e}") from e
    try:
        return yaml.safe_load(text)  # safe_load: never instantiate arbitrary objects
    except yaml.YAMLError as e:
        raise ProfileError(f"{path} is not valid YAML: {e}") from e


def load_profile(path: Path) -> OrgProfile:
    try:
        return OrgProfile.model_validate(_load_yaml(path))
    except ValueError as e:
        raise ProfileError(f"{path}: {e}") from e


def load_pirs(path: Path, profile: OrgProfile | None = None) -> PIRSet:
    """Load PIRs; with a profile, also check they only reference profile data."""
    try:
        pirs = PIRSet.model_validate(_load_yaml(path))
    except ValueError as e:
        raise ProfileError(f"{path}: {e}") from e
    if profile is not None:
        problems = cross_check(profile, pirs)
        if problems:
            raise ProfileError(f"{path}: " + "; ".join(problems))
    return pirs


def cross_check(profile: OrgProfile, pirs: PIRSet) -> list[str]:
    """PIRs that watch for profile data the profile doesn't have can never match."""
    org = profile.org
    problems = []
    for p in pirs.pirs:
        for s in p.watch.sectors:
            if s not in org.sectors:
                problems.append(f"{p.id} watches sector {s!r}, which is not in org.sectors")
        for g in p.watch.geography:
            if g not in org.geography:
                problems.append(f"{p.id} watches geography {g!r}, which is not in org.geography")
        for m in p.watch.match:
            if not getattr(org, m):
                problems.append(f"{p.id} matches on {m!r}, but org.{m} is empty")
    return problems
