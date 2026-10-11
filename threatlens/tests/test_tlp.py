"""TLP 2.0 enforcement (ADR 0008), the Phase 4 acceptance test: an AMBER
indicator is never returned to a reader without clearance, on any read path
(API, lookups, graph, assets, every UI page), and never sent to a sink its
marking doesn't allow."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from hypothesis import given
from hypothesis import strategies as st
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.test_assets import do_import, scan
from tests.test_enrich import KEYS, Upstream, http, seeded, upstream  # noqa: F401  # fixtures
from threatlens import tlp
from threatlens.api.app import create_app
from threatlens.auth import MemoryRateLimiter, create_key
from threatlens.enrich import REGISTRY as ENRICHERS
from threatlens.enrich.quota import MemoryQuotaStore
from threatlens.enrich.service import EnrichmentService, sink_for
from threatlens.ioc.types import IOCType, Observable
from threatlens.models import Indicator
from threatlens.models import Observable as ObsRow
from threatlens.net.http import SafeHttp
from threatlens.settings import Settings
from threatlens.users import create_user

SM = async_sessionmaker[AsyncSession]
AMBER_IP = "162.243.103.246"  # Feodo C2 in the fixture, re-marked TLP:AMBER here
RED_IP = "34.204.119.63"
CLEAR_IP = "50.16.16.211"
PW = "tlp-test-password"  # test accounts


# ── rules ────────────────────────────────────────────────────────────────────


def test_levels_ranks_and_fail_closed() -> None:
    assert tlp.LEVELS == ("TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED")
    assert tlp.stricter("TLP:GREEN", "TLP:AMBER", None) == "TLP:AMBER"
    assert tlp.stricter() == "TLP:CLEAR"
    assert tlp.stricter("TLP:WHITE") == "TLP:RED"  # TLP 1.0 name / typo: treated as RED
    assert tlp.readable("TLP:GREEN") == ["TLP:CLEAR", "TLP:GREEN"]
    assert tlp.readable("nonsense") == ["TLP:CLEAR"]  # an unknown clearance reads CLEAR only
    assert tlp.may_read("TLP:RED", "TLP:WHITE")  # an unknown marking counts as RED...
    assert not tlp.may_read("TLP:AMBER+STRICT", "TLP:WHITE")  # ...so only RED readers see it
    assert tlp.clearance_for("admin", "bogus") == "TLP:CLEAR"
    assert tlp.clearance_for("viewer", None) == "TLP:GREEN"
    assert tlp.clearance_for("analyst", None) == "TLP:AMBER+STRICT"
    assert tlp.clearance_for("admin", None) == "TLP:RED"
    assert tlp.clearance_for("admin", "TLP:CLEAR") == "TLP:CLEAR"


@given(st.sampled_from([*tlp.LEVELS, "TLP:WHITE", "", "x"]), st.sampled_from([*tlp.SINKS, "nowhere"]))
def test_sinks_never_receive_more_than_their_maximum(level: str, sink: str) -> None:
    if tlp.sink_allows(sink, level):
        assert level in tlp.LEVELS
        assert tlp.rank(level) <= tlp.rank(tlp.SINKS[sink].max_level)
    if tlp.rank(level) >= tlp.rank("TLP:AMBER"):
        assert not tlp.sink_allows(sink, level)  # no enrichment provider ever sees AMBER or RED


@given(st.sampled_from([*tlp.LEVELS, "bogus"]), st.sampled_from([*tlp.LEVELS, "bogus"]))
def test_may_read_matches_readable(clearance: str, level: str) -> None:
    unknown_item_for_red_reader = level not in tlp.LEVELS and clearance == tlp.RED
    assert tlp.may_read(clearance, level) == (level in tlp.readable(clearance) or unknown_item_for_red_reader)


# ── fixtures ─────────────────────────────────────────────────────────────────


class App:
    def __init__(self, client: httpx.AsyncClient, keys: dict[str, str], sm: SM, calls: list[str]) -> None:
        self.client = client
        self.keys = keys
        self.sm = sm
        self.calls = calls  # upstream hosts contacted

    def h(self, who: str) -> dict[str, str]:
        return {"X-API-Key": self.keys[who]}

    async def ids(self) -> dict[str, int]:
        async with self.sm() as s:
            rows = (await s.execute(select(ObsRow.value, Indicator.id).join(Indicator))).all()
        return dict(rows)  # type: ignore[arg-type]

    async def login(self, user: str) -> None:
        r = await self.client.post(
            "/ui/login", data={"username": user, "password": PW}, headers={"Sec-Fetch-Site": "same-origin"}
        )
        assert r.status_code == 303


@pytest.fixture
async def app(
    seeded: SM,  # noqa: F811
    http: SafeHttp,  # noqa: F811
    upstream: Upstream,  # noqa: F811
) -> AsyncIterator[App]:
    async with seeded() as s, s.begin():
        for value, level in ((AMBER_IP, "TLP:AMBER"), (RED_IP, "TLP:RED")):
            obs_id = select(ObsRow.id).where(ObsRow.value == value).scalar_subquery()
            await s.execute(update(Indicator).where(Indicator.observable_id == obs_id).values(tlp=level))
        keys = {}
        for name, role, clearance in (
            ("viewer", "viewer", None),
            ("analyst", "analyst", None),
            ("admin", "admin", None),
            ("green-analyst", "analyst", "TLP:GREEN"),
            ("amber-viewer", "viewer", "TLP:AMBER"),
        ):
            _, keys[name] = await create_key(s, name, role, clearance=clearance)
        await create_user(s, "vera", PW, "viewer")
        await create_user(s, "anna", PW, "analyst")
    settings = Settings(rate_limit_analyst=1000, rate_limit_viewer=1000, **KEYS)  # type: ignore[arg-type]
    svc = EnrichmentService(seeded, http, MemoryQuotaStore(), settings)
    a = create_app(settings, checks={}, sessionmaker=seeded, limiter=MemoryRateLimiter(), enrich=svc)
    async with (
        a.router.lifespan_context(a),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=a), base_url="http://test") as c,
    ):
        yield App(c, keys, seeded, upstream.calls)


def values(page: dict[str, Any]) -> set[str]:
    return {i["value"] for i in page["items"]}


# ── API ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("who", "sees"),
    [
        ("viewer", {CLEAR_IP}),
        ("green-analyst", {CLEAR_IP}),
        ("amber-viewer", {CLEAR_IP, AMBER_IP}),
        ("analyst", {CLEAR_IP, AMBER_IP}),
        ("admin", {CLEAR_IP, AMBER_IP, RED_IP}),
    ],
)
async def test_indicator_list_and_detail_respect_clearance(app: App, who: str, sees: set[str]) -> None:
    ids = await app.ids()
    for params in ("", "?sort=priority", "?q=16", "?type=ipv4-addr", "?status=expired", "?source=feodo"):
        page = (await app.client.get(f"/api/v1/indicators{params}", headers=app.h(who))).json()
        assert values(page) <= sees, params
        assert page["total"] == len(values(page)) or params == "?status=expired"
    page = (await app.client.get("/api/v1/indicators", headers=app.h(who))).json()
    assert values(page) == sees
    for value, ind_id in ids.items():
        r = await app.client.get(f"/api/v1/indicators/{ind_id}", headers=app.h(who))
        assert r.status_code == (200 if value in sees else 404)  # hidden = doesn't exist


async def test_lookups_never_show_what_the_caller_cannot_read(app: App) -> None:
    hidden = await app.client.get(
        f"/api/v1/lookup/ipv4-addr/{AMBER_IP}?enrichers=ripestat", headers=app.h("green-analyst")
    )
    body = hidden.json()
    assert body["known"] is None
    assert body["related"] == []
    assert "feodo" not in hidden.text
    assert "Emotet" not in hidden.text
    assert body["tlp"] == "TLP:CLEAR"  # the caller's marking, not the hidden one
    seen = await app.client.get(
        f"/api/v1/lookup/ipv4-addr/{AMBER_IP}?enrichers=ripestat", headers=app.h("analyst")
    )
    assert seen.json()["known"]["sources"] == ["feodo"]
    assert seen.json()["tlp"] == "TLP:AMBER"
    bulk = await app.client.post(
        "/api/v1/enrich", json={"indicators": [AMBER_IP, RED_IP]}, headers=app.h("green-analyst")
    )
    assert all(r["known"] is None for r in bulk.json()["results"])
    assert "feodo" not in bulk.text


async def test_hidden_markings_still_keep_values_away_from_third_parties(app: App) -> None:
    # The caller can't see the AMBER indicator and says TLP:CLEAR, but the
    # platform knows better: nothing may leave.
    r = await app.client.get(
        f"/api/v1/lookup/ipv4-addr/{AMBER_IP}?tlp=TLP:CLEAR", headers=app.h("green-analyst")
    )
    assert r.status_code == 200
    third_party = {e["enricher"]: e for e in r.json()["enrichments"]}
    assert third_party
    assert all(e["status"] == "skipped" and e["skipped_reason"] == "tlp" for e in third_party.values())
    assert app.calls == []


async def test_graph_respects_clearance(app: App) -> None:
    ids = await app.ids()
    for ident in (AMBER_IP, f"indicator:{ids[AMBER_IP]}"):
        assert (
            await app.client.get(f"/api/v1/graph/node?node={ident}", headers=app.h("viewer"))
        ).status_code == 404
        assert (
            await app.client.get(f"/api/v1/graph/node?node={ident}", headers=app.h("analyst"))
        ).status_code == 200
    r = await app.client.get(f"/api/v1/graph/paths?from={AMBER_IP}&to=Emotet", headers=app.h("viewer"))
    assert r.status_code == 404
    for who, expect in (("viewer", False), ("analyst", True)):
        n = await app.client.get("/api/v1/graph/neighbors?node=Emotet&limit=500", headers=app.h(who))
        labels = {i["node"]["label"] for i in n.json()["items"]}
        assert ("162[.]243[.]103[.]246" in labels) is expect
        p = await app.client.get(f"/api/v1/graph/paths?from={CLEAR_IP}&to=Emotet", headers=app.h(who))
        nodes = p.json()["nodes"]
        assert not any(n["label"] == "162[.]243[.]103[.]246" for n in nodes.values()) or expect


async def test_asset_flags_respect_clearance(app: App) -> None:
    await do_import(app.sm, scan())  # the scan claims AMBER_IP as our own address
    for who, expect in (("viewer", None), ("analyst", "expired")):
        page = (await app.client.get("/api/v1/assets", headers=app.h(who))).json()
        own = next(a for a in page["items"] if a["value"] == AMBER_IP)
        assert (own["indicator"]["status"] if own["indicator"] else None) == expect


# ── UI ───────────────────────────────────────────────────────────────────────


async def test_ui_pages_respect_clearance(app: App) -> None:
    ids = await app.ids()
    await app.login("vera")  # viewer: GREEN
    listing = await app.client.get("/ui/indicators?sort=priority")
    assert "162[.]243[.]103[.]246" not in listing.text
    assert (await app.client.get(f"/ui/indicators/{ids[AMBER_IP]}")).status_code == 404
    search = await app.client.get(f"/ui/search?q={AMBER_IP}")
    assert search.status_code == 200  # not a direct hit: a results page...
    assert f"/ui/indicators/{ids[AMBER_IP]}" not in search.text  # ...that doesn't list it either
    assert "No indicator matches" in search.text
    for page in ("/ui", "/ui/assets", "/ui/entities/Emotet", "/ui/attack"):
        r = await app.client.get(page)
        assert r.status_code == 200, page
        assert "162[.]243[.]103[.]246" not in r.text, page
        assert AMBER_IP not in r.text, page
    await app.client.post("/ui/logout", headers={"Sec-Fetch-Site": "same-origin"})
    await app.login("anna")  # analyst: AMBER+STRICT
    assert (await app.client.get(f"/ui/indicators/{ids[AMBER_IP]}")).status_code == 200
    assert (await app.client.get(f"/ui/indicators/{ids[RED_IP]}")).status_code == 404


# ── sinks ────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("level", tlp.LEVELS)
@pytest.mark.parametrize("name", sorted(n for n, c in ENRICHERS.items() if IOCType.IPV4 in c.info.applies_to))
async def test_each_enricher_only_receives_what_its_sink_allows(
    sm: SM,
    http: SafeHttp,  # noqa: F811
    upstream: Upstream,  # noqa: F811
    level: str,
    name: str,
) -> None:
    svc = EnrichmentService(sm, http, MemoryQuotaStore(), Settings(**KEYS))  # type: ignore[arg-type]
    res = await svc.lookup(
        Observable(IOCType.IPV4, AMBER_IP), actor="t", tlp=level, only=[name], clearance=tlp.RED, active=True
    )
    info = ENRICHERS[name].info
    sink = sink_for(info.third_party, info.discloses)
    allowed = sink is None or tlp.sink_allows(sink, level)
    (r,) = res["enrichments"]
    assert (r.get("skipped_reason") == "tlp") is (not allowed), (name, level, r)
    if not allowed:
        assert upstream.calls == []


async def test_background_enrichment_respects_stored_markings(
    seeded: SM,  # noqa: F811
    http: SafeHttp,  # noqa: F811
    upstream: Upstream,  # noqa: F811
) -> None:
    async with seeded() as s, s.begin():
        await s.execute(update(Indicator).values(tlp="TLP:AMBER", status="active"))
    svc = EnrichmentService(seeded, http, MemoryQuotaStore(), Settings())
    out = await svc.enrich_backlog(50)
    assert out == {"candidates": 3, "enriched": 0}
    assert upstream.calls == []
