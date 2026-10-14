"""Phase 5 analyst experience: cases (TLP, evidence snapshots, exports),
notes, saved searches, and the Argus landscape, bulk check and search."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, date, datetime

import httpx
import pytest
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.test_collect import Clock
from tests.test_enrich import KEYS, Upstream, http, seeded, upstream  # noqa: F401  # fixtures
from threatlens import cases as case_store
from threatlens import dashboard
from threatlens.api.app import create_app
from threatlens.auth import MemoryRateLimiter, create_key
from threatlens.enrich.quota import MemoryQuotaStore
from threatlens.enrich.service import EnrichmentService
from threatlens.models import AuditLog, Case, Indicator
from threatlens.models import Observable as ObsRow
from threatlens.net.http import SafeHttp
from threatlens.settings import Settings
from threatlens.users import create_user

SM = async_sessionmaker[AsyncSession]
LIVE = "50.16.16.211"
SAME = {"Sec-Fetch-Site": "same-origin"}


class App:
    def __init__(self, client: httpx.AsyncClient, sm: SM, keys: dict[str, str], calls: list[str]) -> None:
        self.c = client
        self.sm = sm
        self.keys = keys
        self.calls = calls

    def h(self, who: str) -> dict[str, str]:
        return {"X-API-Key": self.keys[who]}

    async def login(self, user: str) -> None:
        await self.c.delete("/app/api/session", headers=SAME)
        r = await self.c.post(
            "/app/api/session", json={"username": user, "password": user + "-password"}, headers=SAME
        )
        assert r.status_code == 200

    async def ind(self, value: str) -> Indicator:
        async with self.sm() as s:
            ind = await s.scalar(select(Indicator).join(ObsRow).where(ObsRow.value == value))
        assert ind is not None
        return ind


@pytest.fixture
async def app(
    seeded: SM,  # noqa: F811
    http: SafeHttp,  # noqa: F811
    upstream: Upstream,  # noqa: F811
) -> AsyncIterator[App]:
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
    settings = Settings(rate_limit_analyst=1000, rate_limit_viewer=1000, **KEYS)  # type: ignore[arg-type]
    svc = EnrichmentService(seeded, http, MemoryQuotaStore(), settings, now=Clock())  # the fixture's day
    a = create_app(settings, checks={}, sessionmaker=seeded, limiter=MemoryRateLimiter(), enrich=svc)
    async with (
        a.router.lifespan_context(a),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=a), base_url="http://test") as c,
    ):
        yield App(c, seeded, keys, upstream.calls)


# ── the case store ───────────────────────────────────────────────────────────


async def test_case_lifecycle_and_tlp(sm: SM) -> None:
    async with sm() as s, s.begin():
        with pytest.raises(case_store.CaseError, match="clearance"):
            await case_store.create_case(s, title="x", actor="v", clearance="TLP:GREEN", tlp="TLP:AMBER")
        with pytest.raises(case_store.CaseError, match="severity"):
            await case_store.create_case(s, title="x", actor="a", clearance="TLP:RED", severity="urgent")
        c = await case_store.create_case(
            s,
            title="Beacon | <b>host-17</b>",
            actor="a",
            clearance="TLP:RED",
            tlp="TLP:GREEN",
            summary="EDR alert",
        )
        await case_store.add_item(
            s,
            c,
            kind="observable",
            ref="ipv4-addr|1.2.3.4",
            label="1[.]2[.]3[.]4",
            snapshot={"verdict": "malicious", "priority": 72.3, "sources": ["feodo"]},
            tlp="TLP:AMBER",
            actor="a",
            note="seen | twice",
        )
        again = await case_store.add_item(
            s,
            c,
            kind="observable",
            ref="ipv4-addr|1.2.3.4",
            label="1[.]2[.]3[.]4",
            snapshot={},
            tlp="TLP:CLEAR",
            actor="a",
            note="updated",
        )
        await case_store.add_item(
            s,
            c,
            kind="note",
            ref="",
            label="note",
            snapshot={},
            tlp="TLP:CLEAR",
            actor="a",
            note="called the host owner",
        )
        assert c.tlp == "TLP:AMBER"  # raised to its strictest item
        assert again.note == "updated"  # the same evidence is added once
        await case_store.update_case(s, c, actor="a", conclusion="True positive.", status="closed")
        with pytest.raises(case_store.CaseError, match="closed"):
            await case_store.add_item(
                s, c, kind="note", ref="", label="", snapshot={}, tlp="TLP:CLEAR", actor="a", note="late"
            )
        case_id = c.id
    async with sm() as s:
        assert await case_store.get_case(s, case_id, "TLP:GREEN") is None  # AMBER now
        c2 = await case_store.get_case(s, case_id, "TLP:AMBER+STRICT")
        assert c2 is not None
        assert [i.kind for i in c2.items] == ["observable", "note"]
        md = case_store.to_markdown(c2, exported_by="anna")
        actions = (await s.scalars(select(AuditLog.action).order_by(AuditLog.id))).all()
    assert md.splitlines()[0] == "**TLP:AMBER**"
    assert "Beacon \\| &lt;b&gt;host-17&lt;/b&gt;" in md  # no table break, no HTML
    assert "`1[.]2[.]3[.]4`" in md
    assert "malicious; priority 72; sources: feodo" in md
    assert "updated" in md
    assert "called the host owner" in md
    assert "True positive." in md
    assert actions == ["case.create", "case.item.add", "case.item.add", "case.item.add", "case.update"]


@pytest.mark.parametrize(
    ("query", "ok"),
    [
        ("/ui/indicators?sort=priority", True),
        ("/ui/search?q=tag:qakbot&show=all", True),
        ("https://evil.example/ui", False),
        ("//evil.example/ui", False),
        ("/ui//evil.example", False),
        ("/api/v1/indicators", False),
        ("/ui\\..\\x", False),
    ],
)
def test_saved_searches_stay_inside_the_ui(query: str, ok: bool) -> None:
    if ok:
        assert case_store.check_query(query) == query
    else:
        with pytest.raises(case_store.CaseError):
            case_store.check_query(query)


# ── Argus ────────────────────────────────────────────────────────────────────


async def test_landscape_has_the_queue_pirs_and_patch_panels(app: App) -> None:
    await app.login("vera")
    d = (await app.c.get("/app/api/landscape")).json()
    assert d["queue"][0]["value"] == "50[.]16[.]16[.]211"  # the live C2 tops the queue
    assert d["queue"][0]["action"] == "block"
    assert [p["priority"] for p in d["patch"]] == ["P1", "P2", "P3", "P4"]
    assert any(p["id"] == "PIR-1" for p in d["pirs"])
    assert all(f["href"].startswith("/") and not f["href"].startswith("/ui") for f in d["families"])


async def test_activity_feed_respects_clearance(app: App) -> None:
    async with app.sm() as s, s.begin():
        await case_store.create_case(
            s, title="Green triage", actor="anna", tlp="TLP:GREEN", clearance="TLP:RED"
        )
        await case_store.create_case(
            s, title="Red operation", actor="anna", tlp="TLP:RED", clearance="TLP:RED"
        )
    await app.login("vera")  # viewer: TLP:GREEN
    titles = [e["title"] for e in (await app.c.get("/app/api/landscape")).json()["activity"]]
    assert "Green triage" in titles
    assert "Red operation" not in titles
    await app.login("anna")  # analyst: TLP:AMBER+STRICT
    titles = [e["title"] for e in (await app.c.get("/app/api/landscape")).json()["activity"]]
    assert "Red operation" not in titles


async def test_month_calendar_grid(app: App) -> None:
    now = datetime(2026, 10, 11, 12, tzinfo=UTC)
    async with app.sm() as s:
        c = await dashboard.month_calendar(s, now, "TLP:RED")
    assert c["label"] == "October 2026"
    assert all(len(w) == 7 for w in c["weeks"])
    first = c["weeks"][0]
    assert first[:4] == [None] * 4  # 1 Oct 2026 is a Thursday
    assert first[4]["day"] == 1
    days = [x for w in c["weeks"] for x in w if x]
    assert len(days) == 31
    assert [x["day"] for x in days if x["today"]] == [11]
    assert all(x["future"] for x in days[11:])
    assert not any(x["future"] for x in days[:11])
    assert c["prev"] == "2026-09"
    assert c["next"] is None
    assert dashboard.parse_month("2026-02") == date(2026, 2, 1)
    assert dashboard.parse_month("2026-2-1") is None


async def test_bulk_check_rules(app: App) -> None:
    alert = (
        "EDR: host-17 beaconed to 50.16.16[.]211 and 162.243.103.246; "
        "also hxxp://evil-example[.]com/x and 10.0.0.5"
    )
    await app.login("vera")
    assert (await app.c.post("/app/api/bulk/stream", data={"text": alert}, headers=SAME)).status_code == 403
    await app.login("anna")
    r = await app.c.post("/app/api/bulk/stream", data={"text": alert}, headers=SAME)
    assert r.status_code == 200
    assert app.calls == []  # providers are off unless asked
    assert "50[.]16[.]16[.]211" in r.text
    assert "10[.]0[.]0[.]5" not in r.text  # private: never looked up
    assert (
        await app.c.post("/app/api/bulk/stream", data={"text": "nothing here"}, headers=SAME)
    ).status_code == 422
    many = "\n".join(f"8.8.{i // 250}.{i % 250 + 1}" for i in range(501))
    too_many = await app.c.post("/app/api/bulk/stream", data={"text": many}, headers=SAME)
    assert too_many.status_code == 422
    assert "at most 500" in too_many.json()["detail"]
    cross = await app.c.post(
        "/app/api/bulk/stream", data={"text": alert}, headers={"Sec-Fetch-Site": "cross-site"}
    )
    assert cross.status_code == 403


async def test_search_lists_by_tag_and_entity(app: App) -> None:
    await app.login("vera")
    async with app.sm() as s, s.begin():
        await s.execute(update(Indicator).values(labels=["botnet-c2", "qakbot"]))
    r = (await app.c.get("/app/api/search", params={"q": "tag:qakbot"})).json()
    assert "50[.]16[.]16[.]211" in [i["value"] for i in r["indicators"]]
    listing = (await app.c.get("/app/api/search", params={"q": "qak", "all": "true"})).json()
    assert "QakBot" in [e["name"] for e in listing["entities"]]


# ── API ──────────────────────────────────────────────────────────────────────


async def test_cases_api(app: App) -> None:
    ind = await app.ind(LIVE)
    assert (
        await app.c.post("/api/v1/cases", json={"title": "x"}, headers=app.h("viewer"))
    ).status_code == 403
    r = await app.c.post(
        "/api/v1/cases", json={"title": "API case", "tlp": "TLP:GREEN"}, headers=app.h("analyst")
    )
    assert r.status_code == 201
    cid = r.json()["id"]
    r = await app.c.post(
        f"/api/v1/cases/{cid}/items",
        json={"kind": "indicator", "ref": str(ind.id), "note": "c2"},
        headers=app.h("analyst"),
    )
    body = r.json()
    assert body["evidence"][0]["snapshot"]["verdict"] == "malicious"
    r = await app.c.post(
        f"/api/v1/cases/{cid}/items",
        json={"values": ["hxxp://x-new-login[.]com"]},
        headers=app.h("analyst"),
    )
    assert [e["kind"] for e in r.json()["evidence"]] == ["indicator", "observable"]
    assert (
        await app.c.post(f"/api/v1/cases/{cid}/items", json={}, headers=app.h("analyst"))
    ).status_code == 422
    r = await app.c.patch(
        f"/api/v1/cases/{cid}", json={"status": "closed", "conclusion": "done"}, headers=app.h("analyst")
    )
    assert (r.json()["status"], r.json()["conclusion"]) == ("closed", "done")
    assert len((await app.c.get("/api/v1/cases?status=closed", headers=app.h("viewer"))).json()) == 1
    md = await app.c.get(f"/api/v1/cases/{cid}/export.md", headers=app.h("viewer"))
    assert md.text.startswith("**TLP:GREEN**")
    item_id = r.json()["evidence"][1]["id"]
    await app.c.patch(f"/api/v1/cases/{cid}", json={"status": "open"}, headers=app.h("analyst"))
    assert (
        await app.c.delete(f"/api/v1/cases/{cid}/items/{item_id}", headers=app.h("analyst"))
    ).status_code == 204
    assert (
        await app.c.delete(f"/api/v1/cases/{cid}/items/{item_id}", headers=app.h("analyst"))
    ).status_code == 404
    # an AMBER item makes the case AMBER: GREEN-cleared keys lose sight of it
    async with app.sm() as s, s.begin():
        await s.execute(update(Indicator).where(Indicator.id == ind.id).values(tlp="TLP:AMBER"))
    r = await app.c.post(
        f"/api/v1/cases/{cid}/items",
        json={"kind": "indicator", "ref": str(ind.id), "note": "again"},
        headers=app.h("green"),
    )
    assert r.status_code == 404  # the green key can't add what it can't read
    await app.c.post(
        f"/api/v1/cases/{cid}/items",
        json={"kind": "indicator", "ref": str(ind.id), "note": "again"},
        headers=app.h("analyst"),
    )
    async with app.sm() as s:
        case = await s.get(Case, cid)
    assert case is not None
    assert case.tlp == "TLP:AMBER"
    assert (await app.c.get(f"/api/v1/cases/{cid}", headers=app.h("green"))).status_code == 404


async def test_notes_api(app: App) -> None:
    ind = await app.ind(LIVE)
    r = await app.c.post(
        f"/api/v1/indicators/{ind.id}/notes", json={"body": "hello"}, headers=app.h("analyst")
    )
    assert r.status_code == 201
    notes = (await app.c.get(f"/api/v1/indicators/{ind.id}/notes", headers=app.h("viewer"))).json()
    assert [n["body"] for n in notes] == ["hello"]
    assert (
        await app.c.post(f"/api/v1/indicators/{ind.id}/notes", json={"body": "x"}, headers=app.h("viewer"))
    ).status_code == 403
    assert (await app.c.get("/api/v1/indicators/999999/notes", headers=app.h("viewer"))).status_code == 404
