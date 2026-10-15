"""Analyst feedback, source weights, stored scores, expiry and patch priority
against the database (ADR 0008)."""

from __future__ import annotations

import io
from collections.abc import AsyncIterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.test_collect import Clock, collector, feed_handler
from tests.test_enrich import KEYS, http, seeded, upstream  # noqa: F401  # fixtures
from tests.test_jobs import cli_db  # noqa: F401  # fixture
from threatlens import cli
from threatlens.api.app import create_app
from threatlens.auth import MemoryRateLimiter, create_key
from threatlens.collect import reapply_allowlist
from threatlens.enrich.quota import MemoryQuotaStore
from threatlens.enrich.service import EnrichmentService
from threatlens.jobs import daily_scoring
from threatlens.models import (
    ApiKey,
    AuditLog,
    Indicator,
    Sighting,
    Source,
    Vulnerability,
    VulnerabilityProduct,
)
from threatlens.models import Observable as ObsRow
from threatlens.net.http import SafeHttp
from threatlens.scoring.config import load_config
from threatlens.scoring.feedback import factor
from threatlens.scoring.store import rescore, rescore_vulns
from threatlens.settings import Settings
from threatlens.users import create_user

SM = async_sessionmaker[AsyncSession]
MakeHttp = Any
CFG = load_config(Path(__file__).parent.parent / "config" / "scoring.yaml")
LIVE_C2 = "50.16.16.211"  # the fixture's one "online" Feodo C2
OLD_C2 = "162.243.103.246"  # offline since 2026-03-07
SETTINGS = Settings()


def test_weight_factor_formula() -> None:
    assert factor(0, 0, CFG) == 1.0
    assert factor(0, 1, CFG) == pytest.approx((18 / 21) / 0.9, abs=1e-4)
    assert factor(0, 50, CFG) == 0.5  # floor
    assert factor(10, 0, CFG) == pytest.approx((28 / 30) / 0.9, abs=1e-4)
    assert factor(1000, 0, CFG) == 1.1  # ceiling
    assert factor(9, 1, CFG) == pytest.approx(1.0, abs=1e-4)  # 90% precision: the prior


async def ind_of(sm: SM, value: str) -> Indicator:
    async with sm() as s:
        ind = await s.scalar(select(Indicator).join(ObsRow).where(ObsRow.value == value))
    assert ind is not None
    return ind


async def test_collection_scores_what_it_touched(seeded: SM) -> None:  # noqa: F811
    live, old = await ind_of(seeded, LIVE_C2), await ind_of(seeded, OLD_C2)
    assert live.status == "active"
    async with seeded() as s:
        conf = await s.scalar(select(Sighting.confidence).where(Sighting.indicator_id == live.id))
    assert conf is not None
    assert live.priority_score == pytest.approx(conf * 0.85, abs=0.01)  # Feodo: B, credibility 2
    assert live.score_breakdown is not None
    assert live.score_breakdown["verdict"] == "malicious"
    assert live.score_breakdown["config"] == CFG.tag
    assert live.valid_until is not None
    assert old.status == "expired"  # offline for seven months
    assert old.priority_score is not None
    assert old.priority_score < CFG.expiry.below


async def test_expiry_and_reactivation(sm: SM, mock_http: MakeHttp, tmp_path: Path) -> None:
    clock = Clock()
    c = collector(sm, mock_http(feed_handler()), tmp_path, clock)
    await c.run("feodo")
    live = await ind_of(sm, LIVE_C2)
    assert live.valid_until is not None
    # Nobody reports it for 40 days: the daily job expires it at its valid_until.
    res = await rescore(sm, SETTINGS, now=clock() + timedelta(days=40))
    assert res.expired == 1
    assert (await ind_of(sm, LIVE_C2)).status == "expired"
    assert clock() + timedelta(days=40) > live.valid_until.replace(tzinfo=clock().tzinfo)
    # Feodo lists it again: the run re-scores it and it comes back.
    clock.advance(days=40)
    await c.run("feodo", force=True)
    back = await ind_of(sm, LIVE_C2)
    assert back.status == "active"
    assert back.priority_score is not None
    assert back.priority_score > 60


async def test_cve_indicators_use_patch_priority_and_never_expire(
    sm: SM, mock_http: MakeHttp, tmp_path: Path
) -> None:
    clock = Clock()
    c = collector(sm, mock_http(feed_handler()), tmp_path, clock)
    await c.run("cisa_kev")
    async with sm() as s:
        v = (await s.scalars(select(Vulnerability).where(Vulnerability.kev.is_(True)))).first()
        assert v is not None
        cve = v.cve_id
        assert v.patch_priority in ("P1", "P2")  # KEV floor, computed after the KEV run
    await rescore(sm, SETTINGS, now=clock() + timedelta(days=3650))
    ind = await ind_of(sm, cve)
    assert ind.status == "active"
    assert ind.score_breakdown is not None
    assert ind.score_breakdown["model"] == "patch-priority"


async def test_patch_priority_uses_the_stack(sm: SM) -> None:
    async with sm() as s, s.begin():
        for cve, kev in (("CVE-2099-0001", True), ("CVE-2099-0002", False)):
            v = Vulnerability(cve_id=cve, stix_id=f"vulnerability--{cve}", kev=kev, cvss_score=9.8)
            s.add(v)
            await s.flush()
            s.add(VulnerabilityProduct(vulnerability_id=v.id, part="o", vendor="fortinet", product="fortios"))
    assert await rescore_vulns(sm, SETTINGS) == 2
    async with sm() as s:
        rows = {v.cve_id: v for v in (await s.scalars(select(Vulnerability))).all()}
    kev = rows["CVE-2099-0001"]
    assert kev.patch_priority == "P1"  # KEV + fortinet:fortios in the example profile
    assert kev.patch_breakdown is not None
    assert any("affects our stack" in r["reason"] for r in kev.patch_breakdown["reasons"])
    assert rows["CVE-2099-0002"].patch_priority == "P3"  # CVSS 9.8 + in stack = 45 points


# ── the API ──────────────────────────────────────────────────────────────────


class Api:
    def __init__(self, client: httpx.AsyncClient, keys: dict[str, str], sm: SM) -> None:
        self.client = client
        self.keys = keys
        self.sm = sm

    def h(self, who: str) -> dict[str, str]:
        return {"X-API-Key": self.keys[who]}

    async def feedback(
        self, value: str, verdict: str, who: str = "analyst", note: str = ""
    ) -> httpx.Response:
        ind = await ind_of(self.sm, value)
        return await self.client.post(
            f"/api/v1/indicators/{ind.id}/feedback",
            json={"verdict": verdict, "note": note},
            headers=self.h(who),
        )


@pytest.fixture
async def api(seeded: SM, http: SafeHttp) -> AsyncIterator[Api]:  # noqa: F811
    keys = {}
    async with seeded() as s, s.begin():
        for name, role, clearance in (
            ("viewer", "viewer", None),
            ("analyst", "analyst", None),
            ("green", "analyst", "TLP:GREEN"),
        ):
            _, keys[name] = await create_key(s, name, role, clearance=clearance)
        await create_user(s, "anna", "anna-password", "analyst")
        await create_user(s, "vera", "vera-password", "viewer")
    settings = Settings(rate_limit_analyst=1000, **KEYS)  # type: ignore[arg-type]
    svc = EnrichmentService(seeded, http, MemoryQuotaStore(), settings)
    app = create_app(settings, checks={}, sessionmaker=seeded, limiter=MemoryRateLimiter(), enrich=svc)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c,
    ):
        yield Api(c, keys, seeded)


async def test_false_positive_feedback(api: Api) -> None:
    assert (await api.feedback(LIVE_C2, "fp", who="viewer")).status_code == 403
    r = await api.feedback(LIVE_C2, "fp", note="our pentest box")
    assert r.status_code == 200
    body = r.json()
    ind = body["indicator"]
    assert (ind["status"], ind["analyst_verdict"], ind["priority_score"], ind["verdict"]) == (
        "false_positive", "fp", 0, "benign"
    )  # fmt: skip
    assert ind["score_breakdown"]["suppressed"].startswith("marked false positive by analyst")
    assert ind["feedback"][0] == {
        **ind["feedback"][0],
        "verdict": "fp",
        "actor": "analyst",
        "note": "our pentest box",
    }
    (change,) = body["source_weights"]
    assert (change["source"], change["tp"], change["fp"]) == ("feodo", 0, 1)
    assert change["after"] == pytest.approx(factor(0, 1, CFG))
    # Neither the allowlist nor the next collection run brings it back.
    await reapply_allowlist(api.sm, SETTINGS)
    assert (await ind_of(api.sm, LIVE_C2)).status == "false_positive"
    look = await api.client.get(
        f"/api/v1/lookup/ipv4-addr/{LIVE_C2}?enrichers=ripestat", headers=api.h("analyst")
    )
    assert look.json()["verdict"] == "benign"
    async with api.sm() as s:
        actions = (await s.scalars(select(AuditLog.action).order_by(AuditLog.id))).all()
        feodo = await s.scalar(select(Source).where(Source.name == "feodo"))
    assert "indicator.feedback" in actions
    assert "source.weight" in actions
    assert feodo is not None
    assert (feodo.feedback_fp, feodo.weight_factor) == (1, pytest.approx(factor(0, 1, CFG)))


async def test_weight_changes_reach_the_sources_other_indicators(api: Api) -> None:
    other = await ind_of(api.sm, "34.204.119.63")
    before = other.score_breakdown
    assert before is not None
    await api.feedback(LIVE_C2, "fp")  # the background task re-scores the rest of Feodo
    after = (await ind_of(api.sm, "34.204.119.63")).score_breakdown
    assert after is not None
    assert after["signals"][0]["weight"] < before["signals"][0]["weight"]


async def test_true_positive_and_reset(api: Api) -> None:
    r = await api.feedback(OLD_C2, "tp", note="seen in our proxy logs")
    ind = r.json()["indicator"]
    assert ind["status"] == "active"  # the analyst's report is fresh: back from expired
    assert ind["verdict"] == "malicious"
    assert ind["score_breakdown"]["base"]["source"] == "analyst"
    assert r.json()["source_weights"][0]["tp"] == 1
    r = await api.feedback(OLD_C2, "reset")
    ind = r.json()["indicator"]
    assert ind["analyst_verdict"] is None
    assert ind["status"] == "expired"  # back to what the feeds alone say
    assert [f["verdict"] for f in ind["feedback"]] == ["reset", "tp"]
    async with api.sm() as s:
        feodo = await s.scalar(select(Source).where(Source.name == "feodo"))
    assert feodo is not None
    assert (feodo.feedback_tp, feodo.weight_factor) == (0, 1.0)


async def test_feedback_respects_clearance_and_existence(api: Api) -> None:
    async with api.sm() as s, s.begin():
        ind = await s.scalar(select(Indicator).join(ObsRow).where(ObsRow.value == LIVE_C2))
        assert ind is not None
        ind.tlp = "TLP:AMBER"
    assert (await api.feedback(LIVE_C2, "fp", who="green")).status_code == 404
    r = await api.client.post(
        "/api/v1/indicators/999999/feedback", json={"verdict": "fp"}, headers=api.h("analyst")
    )
    assert r.status_code == 404
    bad = await api.client.post(
        "/api/v1/indicators/1/feedback", json={"verdict": "maybe"}, headers=api.h("analyst")
    )
    assert bad.status_code == 422


async def test_api_shows_scores_and_sorts_by_priority(api: Api) -> None:
    page = (await api.client.get("/api/v1/indicators?sort=priority", headers=api.h("viewer"))).json()
    scores = [i["priority_score"] for i in page["items"]]
    assert scores == sorted(scores, reverse=True)
    assert page["items"][0]["value"] == LIVE_C2
    assert page["items"][0]["verdict"] == "malicious"
    hot = (await api.client.get("/api/v1/indicators?min_score=60", headers=api.h("viewer"))).json()
    assert [i["value"] for i in hot["items"]] == [LIVE_C2]
    detail = (
        await api.client.get(f"/api/v1/indicators/{page['items'][0]['id']}", headers=api.h("viewer"))
    ).json()
    assert detail["score_breakdown"]["model"] == "v1"
    sources = {
        s["name"]: s for s in (await api.client.get("/api/v1/sources", headers=api.h("viewer"))).json()
    }
    assert sources["feodo"]["credibility"] == 2
    assert sources["feodo"]["weight_factor"] == 1.0


async def test_feedback_through_the_argus_session(api: Api) -> None:
    ind = await ind_of(api.sm, LIVE_C2)
    same = {"Sec-Fetch-Site": "same-origin"}
    await api.client.post(
        "/app/api/session", json={"username": "vera", "password": "vera-password"}, headers=same
    )
    detail = (await api.client.get(f"/api/v1/indicators/{ind.id}")).json()
    assert ind.score_breakdown is not None
    assert detail["score_breakdown"]["formula"] == ind.score_breakdown["formula"]
    r = await api.client.post(f"/api/v1/indicators/{ind.id}/feedback", json={"verdict": "fp"}, headers=same)
    assert r.status_code == 403  # viewers read only
    await api.client.delete("/app/api/session", headers=same)
    await api.client.post(
        "/app/api/session", json={"username": "anna", "password": "anna-password"}, headers=same
    )
    cross = await api.client.post(
        f"/api/v1/indicators/{ind.id}/feedback",
        json={"verdict": "fp"},
        headers={"Sec-Fetch-Site": "cross-site"},
    )
    assert cross.status_code == 403
    r = await api.client.post(
        f"/api/v1/indicators/{ind.id}/feedback", json={"verdict": "fp", "note": "lab host"}, headers=same
    )
    assert r.status_code == 200
    detail = (await api.client.get(f"/api/v1/indicators/{ind.id}")).json()
    assert detail["status"] == "false_positive"
    assert detail["feedback"][0]["note"] == "lab host"


# ── jobs and CLI ─────────────────────────────────────────────────────────────


async def test_daily_scoring_job(seeded: SM) -> None:  # noqa: F811
    out = await daily_scoring(seeded, SETTINGS)
    assert out["indicators"] == 3
    assert out["config"] == CFG.tag
    assert out["expired"] == 0  # already expired at collection time


def test_cli_rescore_and_clearances(
    cli_db: Settings,  # noqa: F811
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert cli.main(["rescore"]) == 0
    assert "indicators" in capsys.readouterr().out
    assert cli.main(["keys", "create", "reconx", "--role", "analyst", "--clearance", "TLP:GREEN"]) == 0
    capsys.readouterr()
    monkeypatch.setattr("sys.stdin", io.StringIO("long-enough-pw\n"))
    assert cli.main(["users", "create", "ana", "--role", "analyst", "--password-stdin"]) == 0
    assert "reads up to TLP:AMBER+STRICT" in capsys.readouterr().out
    assert cli.main(["users", "clearance", "ana"]) == 2
    assert cli.main(["users", "clearance", "ana", "--clearance", "TLP:RED"]) == 0
    assert "reads up to TLP:RED" in capsys.readouterr().out
    assert cli.main(["users", "clearance", "ana", "--role-default"]) == 0
    assert "reads up to TLP:AMBER+STRICT" in capsys.readouterr().out
    assert cli.main(["users", "list"]) == 0
    assert "TLP:AMBER+STRICT" in capsys.readouterr().out


async def test_key_clearance_is_stored(sm: SM) -> None:
    async with sm() as s, s.begin():
        _, _key = await create_key(s, "k", "admin", clearance="TLP:GREEN")
        with pytest.raises(ValueError, match="clearance"):
            await create_key(s, "k2", "admin", clearance="TLP:PINK")
    async with sm() as s:
        row = await s.scalar(select(ApiKey).where(ApiKey.name == "k"))
    assert row is not None
    assert row.tlp_clearance == "TLP:GREEN"
