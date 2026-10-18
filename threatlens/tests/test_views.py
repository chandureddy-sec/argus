"""Interactive views (ADR 0018): the threat map, the activity calendar, the
threat journey and the chart drill-downs."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from itertools import pairwise

from sqlalchemy import select, update

from tests.test_cases import LIVE, SAME, App
from tests.test_cases import app as app  # fixture (an explicit re-export)
from tests.test_enrich import FEODO_IP, Upstream, http, seeded, upstream  # noqa: F401  # fixtures
from threatlens.argus_views import project
from threatlens.models import Indicator


async def _located(app: App) -> int:
    """FEODO_IP with a stored RIPEstat location (Secaucus, US in the fixture), made active."""
    await app.login("anna")
    await app.c.get("/app/api/verify/stream", params={"q": FEODO_IP, "tlp": "TLP:CLEAR"})
    ind = await app.ind(FEODO_IP)
    async with app.sm() as s, s.begin():
        await s.execute(update(Indicator).where(Indicator.id == ind.id).values(status="active"))
    return ind.id


def test_projection_matches_the_land_outline() -> None:
    assert project(0, 0) == (500.0, 250.0)
    assert project(90, -180) == (0.0, 0.0)
    assert project(-90, 180) == (1000.0, 500.0)


async def test_threat_map_groups_located_ips_by_place(app: App) -> None:
    ind_id = await _located(app)
    d = (await app.c.get("/app/api/threatmap")).json()
    assert d["mode"] == "landscape"
    place = next(p for p in d["points"] if any(i["id"] == ind_id for i in p["ips"]))
    assert place["place"] == "Secaucus, US"
    assert (place["x"], place["y"]) == project(40.7908, -74.056)
    ip = next(i for i in place["ips"] if i["id"] == ind_id)
    assert ip["value"] == "162[.]243[.]103[.]246"  # defanged like every other value
    assert ip["blocked"] is None
    assert ip["flagged"] is False
    assert FEODO_IP not in (await app.c.get("/app/api/threatmap")).text
    # "acted": only what we blocked or confirmed
    assert (await app.c.get("/app/api/threatmap", params={"mode": "acted"})).json()["points"] == []
    await app.c.post(f"/api/v1/indicators/{ind_id}/feedback", json={"verdict": "tp"}, headers=SAME)
    acted = (await app.c.get("/app/api/threatmap", params={"mode": "acted"})).json()
    assert [i["flagged"] for p in acted["points"] for i in p["ips"]] == [True]
    assert acted["points"][0]["acted"] == 1


async def test_threat_map_respects_clearance(app: App) -> None:
    ind_id = await _located(app)
    async with app.sm() as s, s.begin():
        await s.execute(update(Indicator).where(Indicator.id == ind_id).values(tlp="TLP:RED"))
    await app.login("vera")
    ids = [i["id"] for p in (await app.c.get("/app/api/threatmap")).json()["points"] for i in p["ips"]]
    assert ind_id not in ids


async def test_calendar_counts_new_indicators_cases_and_blocks(app: App) -> None:
    await app.login("anna")
    today = datetime.now(UTC).date()
    await app.c.post("/api/v1/cases", json={"title": "Calendar case"}, headers=SAME)
    await app.c.post("/api/v1/blocks", json={"value": LIVE}, headers=SAME)
    d = (await app.c.get("/app/api/calendar")).json()
    assert d["month"] == today.strftime("%Y-%m")
    assert d["today"] == today.isoformat()
    assert d["next"] is None  # no future months
    day = d["days"][today.day - 1]
    assert day["date"] == today.isoformat()
    assert (day["cases"], day["blocks"]) == (1, 1)
    assert 0 <= d["firstWeekday"] <= 6
    prev = (await app.c.get("/app/api/calendar", params={"month": d["prev"]})).json()
    assert prev["next"] == d["month"]
    assert (await app.c.get("/app/api/calendar", params={"month": "2026-13"})).status_code == 422
    assert (await app.c.get("/app/api/calendar", params={"month": "x"})).status_code == 422


async def test_journey_follows_the_indicator_from_feed_to_action(app: App) -> None:
    await app.login("anna")
    ind = await app.ind(LIVE)
    stages = (await app.c.get(f"/app/api/indicators/{ind.id}/related")).json()["journey"]
    assert [s["key"] for s in stages] == [
        "reported",
        "ingested",
        "scored",
        "enriched",
        "seen",
        "decided",
        "acted",
    ]
    by = {s["key"]: s for s in stages}
    assert by["reported"]["state"] == "done"
    assert "Feodo" in by["reported"]["lines"][0]
    assert by["decided"]["state"] == "none"
    assert by["acted"]["state"] == "none"
    await app.c.post(f"/api/v1/indicators/{ind.id}/feedback", json={"verdict": "tp"}, headers=SAME)
    await app.c.post("/api/v1/blocks", json={"value": LIVE}, headers=SAME)
    case = (await app.c.post("/api/v1/cases", json={"title": "Journey"}, headers=SAME)).json()
    await app.c.post(
        f"/api/v1/cases/{case['id']}/items", json={"kind": "indicator", "ref": str(ind.id)}, headers=SAME
    )
    by = {s["key"]: s for s in (await app.c.get(f"/app/api/indicators/{ind.id}/related")).json()["journey"]}
    assert by["decided"]["state"] == "done"
    assert "confirmed malicious" in by["decided"]["lines"][0]
    assert by["acted"]["block"]["mode"] == "monitor"
    assert by["acted"]["cases"][0]["id"] == case["id"]


async def test_indicators_filter_by_when_they_were_added(app: App) -> None:
    await app.login("vera")
    all_ = (await app.c.get("/api/v1/indicators")).json()["total"]
    assert all_ > 0
    async with app.sm() as s:
        added = [i.created_at for i in (await s.scalars(select(Indicator))).all()]
    lo = min(added).replace(tzinfo=UTC)
    hi = max(added).replace(tzinfo=UTC)
    window = {
        "added_from": (lo - timedelta(seconds=1)).isoformat(),
        "added_until": (hi + timedelta(seconds=1)).isoformat(),
    }
    assert (await app.c.get("/api/v1/indicators", params=window)).json()["total"] == all_
    after = {"added_from": (hi + timedelta(days=1)).date().isoformat()}
    assert (await app.c.get("/api/v1/indicators", params=after)).json()["total"] == 0
    before = {"added_until": lo.isoformat()}
    assert (await app.c.get("/api/v1/indicators", params=before)).json()["total"] == 0


async def test_chart_points_carry_their_drill_down_range(app: App) -> None:
    await app.login("vera")
    pts = (await app.c.get("/app/api/activity", params={"range": "Week"})).json()["points"]
    assert len(pts) == 7
    assert all(p["from"] < p["to"] for p in pts)
    assert all(a["to"] == b["from"] for a, b in pairwise(pts))
    days = (await app.c.get("/app/api/collection")).json()["days"]
    assert [d["day"] for d in days] == ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    assert all(len(d["date"]) == 10 for d in days)
