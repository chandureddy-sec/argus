"""API v1 enrichment (Phase 3): single lookups, bulk SOC-alert enrichment,
and the enricher catalogue with quota use.

Lookups need the analyst role: they spend shared provider quotas and send
values to third parties (within TLP). Active enrichment additionally needs
``active=true`` per request, has its own per-key rate limit, and every active
call is written to the audit log (ADR 0005).
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Path, Query, Request
from pydantic import BaseModel, Field

from threatlens.api.v1 import Analyst, Viewer
from threatlens.auth import Principal
from threatlens.enrich.service import EnrichmentService
from threatlens.ioc.extract import extract
from threatlens.ioc.normalize import guess, normalize
from threatlens.ioc.types import IOCType, Observable, Rejected

router = APIRouter(prefix="/api/v1", tags=["enrichment"])
Tlp = Literal["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"]
NOT_LOOKUPS = frozenset({IOCType.CVE})  # CVEs have their own routes (/api/v1/vulnerabilities)


# ── schemas ──────────────────────────────────────────────────────────────────


class EvidenceOut(BaseModel):
    source: str
    kind: Literal["malicious", "suspicious", "benign", "info"]
    weight: int
    text: str
    ref: str | None = None


class EnrichmentOut(BaseModel):
    enricher: str
    title: str
    mode: Literal["passive", "active"]
    status: Literal["ok", "cached", "stale", "skipped", "error"] = Field(
        description="ok: fetched now; cached: fresh stored answer; stale: older answer shown because "
        "this one was skipped or failed; skipped: not asked (see skipped_reason); error: asked, failed"
    )
    skipped_reason: (
        Literal[
            "disabled", "active_not_requested", "tlp", "no_api_key", "budget_exhausted", "quota_exhausted"
        ]
        | None
    ) = None
    detail: str | None = None
    error: str | None = None
    resets_in_s: int | None = None
    found: bool | None = None
    fetched_at: datetime | None = None
    expires_at: datetime | None = None
    summary: dict[str, Any] = Field(default_factory=dict)
    evidence: list[EvidenceOut] = Field(default_factory=list)
    query: str | None = None
    cost: int | None = None


class QueryOut(BaseModel):
    type: str
    value: str
    defanged: str
    canonical_key: str


class KnownOut(BaseModel):
    indicator_id: int
    status: str
    confidence: int
    tlp: str
    labels: list[str]
    sources: list[str]
    first_seen: datetime
    last_seen: datetime
    allowlist_reason: str | None
    analyst_verdict: str | None = None
    priority_score: float | None = Field(default=None, description="the stored indicator's score")


class RelatedOut(BaseModel):
    kind: str
    type: str
    label: str
    external_id: str | None
    ref: str
    relationship: str
    via: str | None


class OwnAsset(BaseModel):
    kind: str
    target: str
    origin: str
    first_seen: datetime
    last_seen: datetime
    details: dict[str, Any]


class AllowlistHit(BaseModel):
    effect: Literal["suppress", "flag"] | None
    reasons: list[str]
    labels: list[str]


class LookupOut(BaseModel):
    query: QueryOut
    verdict: Literal["malicious", "suspicious", "benign", "unknown"]
    score: int = Field(ge=0, le=100, description="priority rounded to a whole number")
    priority: float = Field(ge=0, le=100, description="scoring model v1 (ADR 0008)")
    score_model: str
    score_breakdown: dict[str, Any] = Field(description="every term of the score, with its sources")
    recommended_action: Literal["block", "investigate", "no_action", "monitor"]
    recommended_action_text: str
    tlp: str
    known: KnownOut | None
    asset: OwnAsset | None = Field(default=None, description="set when the value is one of your own assets")
    allowlist: AllowlistHit
    evidence: list[EvidenceOut]
    related: list[RelatedOut]
    enrichments: list[EnrichmentOut]
    partial: bool = Field(description="true when any enricher was skipped (other than active mode) or failed")
    took_ms: float


class TypedValue(BaseModel):
    type: IOCType
    value: str = Field(min_length=1, max_length=2048)


class EnrichIn(BaseModel):
    indicators: list[str | TypedValue] = Field(
        default_factory=list,
        max_length=1000,
        description="values (type guessed; defanged input is fine) or {type, value} pairs",
    )
    text: str | None = Field(
        default=None, max_length=200_000, description="free text, e.g. an alert body: IOCs are extracted"
    )
    active: bool = False
    refresh: bool = False
    tlp: Tlp | None = Field(default=None, description="TLP of the values; a stricter stored TLP still wins")
    budget: int | None = Field(
        default=None, ge=0, le=10_000, description="max metered provider calls (default TL_ENRICH_BUDGET)"
    )


class RejectedOut(BaseModel):
    value: str
    reason: str


class EnrichOut(BaseModel):
    results: list[LookupOut]
    rejected: list[RejectedOut]
    counts: dict[str, int]
    budget_spent: int


class EnricherOut(BaseModel):
    name: str
    title: str
    applies_to: list[str]
    mode: str
    third_party: bool
    discloses: bool
    requires_key: bool
    key_configured: bool
    enabled: bool
    metered: bool
    quotas: list[str]
    used: dict[str, int]
    ttl_hours: float
    auto: bool
    reliability: str
    license: str
    commercial_use: bool
    redistribution: bool
    verified: str


# ── helpers ──────────────────────────────────────────────────────────────────


def _svc(request: Request) -> EnrichmentService:
    svc: EnrichmentService | None = getattr(request.app.state, "enrich", None)
    if svc is None:
        raise HTTPException(503, "enrichment is not configured")
    return svc


async def _allow_active(request: Request, who: Principal, n: int) -> None:
    """Active lookups have their own per-key budget per minute."""
    limit = _svc(request).settings.enrich_active_per_min
    for _ in range(n):
        wait = await request.app.state.limiter.hit(f"active:{who.key_id}", limit)
        if wait:
            raise HTTPException(
                429, f"active enrichment is limited to {limit} per minute", headers={"Retry-After": str(wait)}
            )


# ── routes ───────────────────────────────────────────────────────────────────


@router.get("/lookup/{type}/{value:path}", response_model=LookupOut)
async def lookup(
    who: Analyst,
    request: Request,
    type: Annotated[IOCType, Path(description="observable type, e.g. ipv4-addr, domain-name, url")],  # noqa: A002
    value: Annotated[str, Path(min_length=1, max_length=2048)],
    active: bool = False,
    refresh: bool = False,
    tlp: Tlp | None = None,
    enrichers: Annotated[str | None, Query(max_length=300, description="comma-separated subset")] = None,
) -> dict[str, Any]:
    """Everything known about one observable: what the platform's feeds say,
    each applicable enricher (cached, fetched now, or skipped with a reason),
    and a verdict with its evidence and recommended action."""
    if type in NOT_LOOKUPS:
        raise HTTPException(422, "look CVEs up at /api/v1/vulnerabilities/{cve}")
    r = normalize(type, value)
    if not isinstance(r, Observable):
        raise HTTPException(422, f"not a valid {type.value}: {r.reason}")
    svc = _svc(request)
    only = [e.strip() for e in enrichers.split(",") if e.strip()] if enrichers else None
    if only:
        unknown = sorted(set(only) - set(svc.registry))
        if unknown:
            raise HTTPException(422, f"unknown enricher(s): {', '.join(unknown)}")
    if active:
        await _allow_active(request, who, 1)
    return await svc.lookup(
        r, actor=who.name, active=active, refresh=refresh, tlp=tlp, only=only, clearance=who.clearance
    )


@router.post("/enrich", response_model=EnrichOut)
async def enrich(who: Analyst, request: Request, body: EnrichIn) -> dict[str, Any]:
    """Bulk enrichment for SOC alerts: pass values and/or the alert text; each
    observable comes back with a verdict, score, evidence, related entities and
    a recommended action. Metered provider calls share one ``budget``."""
    svc = _svc(request)
    obs: list[Observable] = []
    rejected: list[dict[str, str]] = []
    for item in body.indicators:
        if isinstance(item, TypedValue):
            raw, r = item.value, normalize(item.type, item.value)
        else:
            raw, r = item, guess(item[:2048])
        if isinstance(r, Observable) and r.type not in NOT_LOOKUPS:
            obs.append(r)
        else:
            rejected.append(
                {
                    "value": raw[:300],
                    "reason": r.reason if isinstance(r, Rejected) else "CVEs are not looked up here",
                }
            )
    if body.text:
        obs += [x for x in extract(body.text) if isinstance(x, Observable) and x.type not in NOT_LOOKUPS]
    unique = list({o.key: o for o in obs}.values())
    limit = svc.settings.enrich_bulk_max
    if len(unique) > limit:
        raise HTTPException(422, f"{len(unique)} observables; at most {limit} per request")
    if body.active:
        await _allow_active(request, who, len(unique))
    results, spent = await svc.lookup_many(
        unique,
        actor=who.name,
        active=body.active,
        refresh=body.refresh,
        tlp=body.tlp,
        budget=body.budget,
        clearance=who.clearance,
    )
    counts = dict.fromkeys(("malicious", "suspicious", "benign", "unknown"), 0)
    for res in results:
        counts[res["verdict"]] += 1
    order = {"malicious": 0, "suspicious": 1, "unknown": 2, "benign": 3}
    results.sort(key=lambda x: (order[x["verdict"]], -x["score"]))
    return {"results": results, "rejected": rejected, "counts": counts, "budget_spent": spent}


@router.get("/enrichers", response_model=list[EnricherOut])
async def enrichers_status(_: Viewer, request: Request) -> list[dict[str, Any]]:
    """Every enricher: what it handles, its policy (passive/active, third
    party, disclosure), whether its key is set, and its quota use right now."""
    return await _svc(request).status()
