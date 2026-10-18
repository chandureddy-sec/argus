"""Dissemination API (ADR 0019): integrations and alert rules (admin),
alerts (viewer), sightings from our SIEM (analyst) and an overview of what is
shared where. TAXII lives at /taxii2 and exports at /feeds/{token}/indicators.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Body, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import select

from threatlens.api.v1 import Admin, Analyst, Viewer, _app_settings, _sm
from threatlens.models import AlertRule, Integration
from threatlens.share import alerts, integrations, sightings, sinks
from threatlens.share import export as exports
from threatlens.share import select as sel
from threatlens.share.taxii import COLLECTIONS

router = APIRouter(prefix="/api/v1", tags=["sharing"])


class IntegrationIn(BaseModel):
    name: str = Field(min_length=2, max_length=63)
    kind: Literal[
        "splunk_hec", "elastic", "sentinel", "misp", "webhook", "slack", "teams", "telegram", "email"
    ]
    enabled: bool = True
    config: dict[str, Any] = Field(default_factory=dict)
    secret: dict[str, str] = Field(default_factory=dict, description="write-only; never returned")
    allow_internal: bool = False
    min_score: float = Field(default=60.0, ge=0, le=100)
    max_tlp: Literal["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT"] = "TLP:GREEN"
    types: list[str] = Field(default_factory=list, max_length=10)
    interval_minutes: int = Field(default=60, ge=5, le=10080)

    def form(self) -> integrations.Form:
        return integrations.Form(
            self.name,
            self.kind,
            self.config,
            dict(self.secret),
            self.enabled,
            self.allow_internal,
            self.min_score,
            self.max_tlp,
            tuple(self.types),
            self.interval_minutes,
        )


class RuleIn(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    kind: Literal["score", "pir", "kev_asset", "environment"]
    params: dict[str, Any] = Field(default_factory=dict)
    channels: list[int] = Field(min_length=1, max_length=10)
    max_tlp: Literal["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT"] = "TLP:GREEN"
    enabled: bool = True


class SightingsIn(BaseModel):
    system: str = Field(
        min_length=1, max_length=60, description="the reporting system, e.g. splunk, crowdstrike"
    )
    values: list[str] = Field(min_length=1, max_length=sightings.MAX_VALUES)
    seen_at: datetime | None = None
    context: dict[str, str] = Field(default_factory=dict, max_length=20)


def _bad(e: Exception) -> HTTPException:
    return HTTPException(422, str(e))


def _kinds() -> list[dict[str, Any]]:
    return [
        {
            "kind": k,
            "title": v.title,
            "role": v.role,
            "docs": v.docs,
            "config": [f.__dict__ for f in v.config],
            "secret": [f.__dict__ for f in v.secret],
        }
        for k, v in sinks.KINDS.items()
    ]


# ── integrations ─────────────────────────────────────────────────────────────


@router.get("/integrations")
async def list_integrations(who: Admin, request: Request) -> dict[str, Any]:
    async with _sm(request)() as s:
        rows = (await s.scalars(select(Integration).order_by(Integration.name))).all()
        items = [integrations.view(i) for i in rows]
    return {"items": items, "kinds": _kinds()}


@router.post("/integrations", status_code=201)
async def create_integration(who: Admin, request: Request, body: IntegrationIn) -> dict[str, Any]:
    async with _sm(request)() as s, s.begin():
        try:
            i = await integrations.create(s, body.form(), actor=who.name, settings=_app_settings(request))
        except sinks.IntegrationError as e:
            raise _bad(e) from e
        return integrations.view(i)


async def _get(s: Any, ident: int) -> Integration:
    i = await integrations.get(s, ident)
    if i is None:
        raise HTTPException(404, "no such integration")
    return i


@router.put("/integrations/{ident}")
async def update_integration(who: Admin, request: Request, ident: int, body: IntegrationIn) -> dict[str, Any]:
    async with _sm(request)() as s, s.begin():
        i = await _get(s, ident)
        try:
            await integrations.update(s, i, body.form(), actor=who.name, settings=_app_settings(request))
        except sinks.IntegrationError as e:
            raise _bad(e) from e
        return integrations.view(i)


@router.delete("/integrations/{ident}", status_code=204)
async def delete_integration(who: Admin, request: Request, ident: int) -> Response:
    async with _sm(request)() as s, s.begin():
        i = await _get(s, ident)
        await integrations.remove(s, i, actor=who.name)  # rules simply stop using it
    return Response(status_code=204)


@router.post("/integrations/{ident}/test")
async def test_integration(who: Admin, request: Request, ident: int) -> dict[str, Any]:
    try:
        msg = await integrations.test(_sm(request), _app_settings(request), ident, actor=who.name)
    except sinks.IntegrationError as e:
        raise HTTPException(502, str(e)) from e
    return {"ok": True, "result": msg}


@router.post("/integrations/{ident}/push")
async def push_integration(who: Admin, request: Request, ident: int) -> dict[str, Any]:
    try:
        return await integrations.push(
            _sm(request), _app_settings(request), ident, trigger="manual", actor=who.name
        )
    except sinks.IntegrationError as e:
        raise _bad(e) from e


@router.get("/integrations/{ident}/runs")
async def integration_runs(who: Admin, request: Request, ident: int) -> list[dict[str, Any]]:
    async with _sm(request)() as s:
        i = await _get(s, ident)
        return await integrations.runs(s, i.id)


@router.get("/sharing")
async def sharing(
    who: Viewer,
    request: Request,
    max_tlp: Annotated[str, Query(max_length=20)] = "TLP:GREEN",
    min_score: Annotated[float, Query(ge=0, le=100)] = 60.0,
) -> dict[str, Any]:
    """What would leave for a given TLP cap and score, and where intelligence is published."""
    settings = _app_settings(request)
    base = settings.public_url.rstrip("/")
    async with _sm(request)() as s:
        counts = await sel.held_back(s, sel.Rules(max_tlp, min_score, (), revocations=False))
    return {
        "preview": counts,
        "taxii": {
            "discovery": f"{base}/taxii2/",
            "apiRoot": f"{base}/taxii2/api/",
            "collections": [
                {
                    "id": c.id,
                    "title": c.title,
                    "description": c.description,
                    "maxTlp": c.rules.max_tlp,
                    "minScore": c.rules.min_score,
                    "url": f"{base}/taxii2/api/collections/{c.id}/",
                }
                for c in COLLECTIONS
            ],
        },
        "exports": [{"format": f, "media": m, "types": list(t)} for f, (m, t) in exports.FORMATS.items()],
        "exportPath": "/feeds/{token}/indicators/{format}?min_score=60",
    }


# ── alerts ───────────────────────────────────────────────────────────────────


@router.get("/alerts/rules")
async def list_rules(who: Admin, request: Request) -> list[dict[str, Any]]:
    async with _sm(request)() as s:
        rows = (await s.scalars(select(AlertRule).order_by(AlertRule.name))).all()
        return [alerts.rule_view(r) for r in rows]


@router.post("/alerts/rules", status_code=201)
async def create_rule(who: Admin, request: Request, body: RuleIn) -> dict[str, Any]:
    async with _sm(request)() as s, s.begin():
        try:
            r = await alerts.create_rule(
                s,
                name=body.name,
                kind=body.kind,
                params=body.params,
                channels=body.channels,
                max_tlp=body.max_tlp,
                actor=who.name,
            )
        except alerts.AlertError as e:
            raise _bad(e) from e
        r.enabled = body.enabled
        return alerts.rule_view(r)


@router.put("/alerts/rules/{rule_id}")
async def update_rule(who: Admin, request: Request, rule_id: int, body: RuleIn) -> dict[str, Any]:
    async with _sm(request)() as s, s.begin():
        r = await s.get(AlertRule, rule_id)
        if r is None:
            raise HTTPException(404, "no such rule")
        try:
            await alerts.update_rule(
                s,
                r,
                params=body.params,
                channels=body.channels,
                max_tlp=body.max_tlp,
                enabled=body.enabled,
                actor=who.name,
            )
        except alerts.AlertError as e:
            raise _bad(e) from e
        return alerts.rule_view(r)


@router.delete("/alerts/rules/{rule_id}", status_code=204)
async def delete_rule(who: Admin, request: Request, rule_id: int) -> Response:
    from threatlens.models import AuditLog

    async with _sm(request)() as s, s.begin():
        r = await s.get(AlertRule, rule_id)
        if r is None:
            raise HTTPException(404, "no such rule")
        s.add(
            AuditLog(
                actor=who.name[:100],
                action="alert_rule.delete",
                target=f"alert_rule:{r.id}",
                details={"name": r.name},
            )
        )
        await s.delete(r)
    return Response(status_code=204)


@router.post("/alerts/evaluate")
async def evaluate_now(who: Admin, request: Request) -> dict[str, int]:
    return await alerts.evaluate(_sm(request), _app_settings(request))


@router.get("/alerts")
async def recent_alerts(
    who: Viewer, request: Request, limit: Annotated[int, Query(ge=1, le=500)] = 100
) -> list[dict[str, Any]]:
    async with _sm(request)() as s:
        return await alerts.recent(s, who.clearance, limit)


# ── sightings from our environment ───────────────────────────────────────────


def _matches(found: list[sightings.Match], checked: int) -> dict[str, Any]:
    return {"checked": checked, "known": len(found), "matches": [m.__dict__ for m in found]}


@router.post("/sightings")
async def post_sightings(who: Analyst, request: Request, body: SightingsIn) -> dict[str, Any]:
    """A SIEM, EDR or proxy reports values it saw; known indicators get an
    environment sighting and the answer says what each one is."""
    async with _sm(request)() as s, s.begin():
        found, checked = await sightings.record(
            s,
            body.system,
            body.values,
            clearance=who.clearance,
            actor=who.name,
            seen_at=body.seen_at,
            context=body.context,
        )
    return _matches(found, checked)


@router.post("/integrations/wazuh/alert")
async def wazuh_alert(
    who: Analyst, request: Request, alert: Annotated[dict[str, Any] | list[dict[str, Any]], Body()]
) -> dict[str, Any]:
    """Wazuh's integratord posts each alert here (integrations/wazuh/custom-argus).
    Indicators in the alert are matched; the answer enriches the alert."""
    batch = alert if isinstance(alert, list) else [alert]
    values: list[str] = []
    ctx: dict[str, str] = {}
    for a in batch[:50]:
        values += sightings.wazuh_values(a)
        r_, g_ = a.get("rule"), a.get("agent")
        rule: dict[str, Any] = r_ if isinstance(r_, dict) else {}
        agent: dict[str, Any] = g_ if isinstance(g_, dict) else {}
        ctx = {
            "rule": str(rule.get("description", ""))[:200],
            "rule_id": str(rule.get("id", ""))[:20],
            "agent": str(agent.get("name", ""))[:100],
        }
    async with _sm(request)() as s, s.begin():
        found, checked = await sightings.record(
            s, "wazuh", values, clearance=who.clearance, actor=who.name, context=ctx
        )
    return _matches(found, checked)
