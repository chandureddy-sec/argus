"""Phase 5 analyst experience: cases (TLP, evidence snapshots, exports),
notes, saved searches, bulk lookup with CSV, search, the new dashboard, and the
strict-CSP rule that no page uses inline styles."""

from __future__ import annotations

import csv
import io
import re
from collections.abc import AsyncIterator
from datetime import UTC, date, datetime

import httpx
import pytest
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.test_collect import Clock
from tests.test_enrich import KEYS, Upstream, http, seeded, upstream  # noqa: F401  # fixtures
from tests.uihelp import only_our_script
from threatlens import cases as case_store
from threatlens.api.app import create_app
from threatlens.auth import MemoryRateLimiter, create_key
from threatlens.enrich.quota import MemoryQuotaStore
from threatlens.enrich.service import EnrichmentService
from threatlens.models import AuditLog, Case, Indicator
from threatlens.models import Observable as ObsRow
from threatlens.net.http import SafeHttp
from threatlens.settings import Settings
from threatlens.ui import data as ui_data
from threatlens.ui.work import _csv_cell
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
        await self.c.post("/ui/logout", headers=SAME)
        r = await self.c.post(
            "/ui/login", data={"username": user, "password": user + "-password"}, headers=SAME
        )
        assert r.status_code == 303

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


@pytest.mark.parametrize(
    ("cell", "safe"),
    [
        ("=HYPERLINK(1)", "'=HYPERLINK(1)"),
        ("+1", "'+1"),
        ("-2", "'-2"),
        ("@x", "'@x"),
        ("1.2.3.4", "1.2.3.4"),
        (None, ""),
        (72.5, "72.5"),
    ],
)
def test_csv_cells_cannot_become_formulas(cell: object, safe: str) -> None:
    assert _csv_cell(cell) == safe


# ── UI ───────────────────────────────────────────────────────────────────────


async def test_dashboard_shows_the_new_panels(app: App) -> None:
    await app.login("vera")
    r = await app.c.get("/ui")
    assert r.status_code == 200
    for text in (
        "Malicious · block",
        "New high-priority",
        "Patch now · P1",
        "Feeds healthy",
        "Verdict mix",
        "Priority queue",
        "Intelligence requirements",
        "Feed reliability",
        "PIR-1",
    ):
        assert text in r.text, text
    assert r.text.count('class="gauge"') == 3
    assert "50[.]16[.]16[.]211" in r.text  # the live C2 tops the queue


async def test_activity_feed_respects_clearance(app: App) -> None:
    async with app.sm() as s, s.begin():
        await case_store.create_case(
            s, title="Green triage", actor="anna", tlp="TLP:GREEN", clearance="TLP:RED"
        )
        await case_store.create_case(
            s, title="Red operation", actor="anna", tlp="TLP:RED", clearance="TLP:RED"
        )
    await app.login("vera")  # viewer: TLP:GREEN
    r = await app.c.get("/ui")
    assert "Activity" in r.text
    assert "Green triage" in r.text
    assert "Red operation" not in r.text
    await app.login("anna")  # analyst: TLP:AMBER+STRICT
    assert "Red operation" not in (await app.c.get("/ui")).text


async def test_calendar_month_navigation(app: App) -> None:
    now = datetime.now(UTC)
    async with app.sm() as s, s.begin():
        await s.execute(update(Indicator).values(created_at=now))
    await app.login("vera")
    r = await app.c.get("/ui")
    assert now.strftime("%B %Y") in r.text
    assert re.search(r'<td class="l[1-4] today"', r.text)
    assert 'aria-label="Next month"' not in r.text  # nothing after the current month
    old = await app.c.get("/ui?month=2001-02")
    assert "February 2001" in old.text
    assert 'href="/ui?month=2001-03#calendar"' in old.text
    assert 'href="/ui?month=2001-01#calendar"' in old.text
    for bad in ("2099-12", "nonsense", "2026-13", "1999-01"):
        assert now.strftime("%B %Y") in (await app.c.get(f"/ui?month={bad}")).text, bad


async def test_month_calendar_grid(app: App) -> None:
    now = datetime(2026, 10, 11, 12, tzinfo=UTC)
    async with app.sm() as s:
        c = await ui_data.month_calendar(s, now, "TLP:RED")
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
    assert ui_data.parse_month("2026-02") == date(2026, 2, 1)
    assert ui_data.parse_month("2026-2-1") is None


async def test_no_page_uses_inline_styles(app: App) -> None:
    """The UI's CSP forbids inline styles: every page must style through app.css."""
    ind = await app.ind(LIVE)
    await app.login("anna")
    async with app.sm() as s, s.begin():
        c = await case_store.create_case(s, title="t", actor="anna", clearance="TLP:RED")
    pages = [
        "/ui",
        "/ui/indicators",
        f"/ui/indicators/{ind.id}",
        "/ui/lookup",
        "/ui/cases",
        f"/ui/cases/{c.id}",
        f"/ui/cases/{c.id}/print",
        "/ui/search",
        "/ui/search?q=50.16&show=all",
        "/ui/vulnerabilities",
        "/ui/sources",
        "/ui/assets",
        "/ui/attack",
        "/ui/blocklist",
        "/ui/blocklist?view=all",
        "/ui/settings",
    ]
    for path in pages:
        r = await app.c.get(path)
        assert r.status_code == 200, path
        assert not re.search(r'\sstyle="', r.text), path
        assert only_our_script(r.text), path
    font = await app.c.get("/ui/static/fonts/inter-latin.woff2")
    assert font.status_code == 200
    assert font.content[:4] == b"wOF2"


async def test_bulk_lookup_page_and_csv(app: App) -> None:
    alert = (
        "EDR: host-17 beaconed to 50.16.16[.]211 and 162.243.103.246; "
        "also hxxp://evil-example[.]com/x and 10.0.0.5"
    )
    await app.login("vera")
    assert (
        await app.c.post("/ui/lookup", data={"text": alert}, headers=SAME)
    ).status_code == 403  # viewers read
    await app.login("anna")
    r = await app.c.post("/ui/lookup", data={"text": alert}, headers=SAME)
    assert r.status_code == 200
    assert "no provider asked" in r.text
    assert app.calls == []  # no provider asked
    assert "50[.]16[.]16[.]211" in r.text
    assert "10[.]0[.]0[.]5" not in r.text  # private: never looked up
    out = await app.c.post("/ui/lookup", data={"text": alert, "format": "csv"}, headers=SAME)
    assert out.headers["content-type"].startswith("text/csv")
    assert "attachment" in out.headers["content-disposition"]
    rows = list(csv.reader(io.StringIO(out.text)))
    assert rows[0][:3] == ["value_defanged", "type", "verdict"]
    first = rows[1]
    assert (first[0], first[2], first[4]) == ("50[.]16[.]16[.]211", "malicious", "block")  # worst first
    assert (await app.c.post("/ui/lookup", data={"text": "nothing here"}, headers=SAME)).status_code == 422
    many = "\n".join(f"8.8.{i // 250}.{i % 250 + 1}" for i in range(501))
    too_many = await app.c.post("/ui/lookup", data={"text": many}, headers=SAME)
    assert too_many.status_code == 422
    assert "at most 500" in too_many.text
    cross = await app.c.post("/ui/lookup", data={"text": alert}, headers={"Sec-Fetch-Site": "cross-site"})
    assert cross.status_code == 403


async def test_case_flow_from_alert_to_documented_verdict(app: App) -> None:
    ind = await app.ind(LIVE)
    await app.login("anna")
    r = await app.c.post(
        "/ui/cases",
        data={"title": "Beacon from host-17", "severity": "high", "indicator_id": str(ind.id)},
        headers=SAME,
    )
    assert r.status_code == 303
    case_url = r.headers["location"]
    case_id = int(case_url.rsplit("/", 1)[1])
    added = await app.c.post(
        "/ui/cases/add",
        data={
            "case": str(case_id),
            "values": ["162.243.103.246", "hxxp://new-thing-login[.]com/a"],
            "note": "from the alert",
        },
        headers=SAME,
    )
    assert added.status_code == 303
    await app.c.post(
        f"/ui/cases/{case_id}/items",
        data={"kind": "note", "note": "Host owner confirmed."},
        headers=SAME,
    )
    await app.c.post(
        f"/ui/cases/{case_id}",
        data={"conclusion": "True positive: blocked, host reimaged."},
        headers=SAME,
    )
    page = await app.c.get(case_url)
    assert "50[.]16[.]16[.]211" in page.text
    assert "new-thing-login[.]com" in page.text  # not an indicator: added as an observable
    assert "Host owner confirmed." in page.text
    md = await app.c.get(f"/ui/cases/{case_id}/export.md")
    assert md.headers["content-disposition"] == f'attachment; filename="case-{case_id}.md"'
    assert md.text.startswith("**TLP:AMBER**")
    assert "True positive: blocked, host reimaged." in md.text
    assert re.search(r"malicious; priority \d+; sources: feodo", md.text)
    prt = await app.c.get(f"/ui/cases/{case_id}/print")
    assert "Save as PDF" in prt.text
    closed = await app.c.post(f"/ui/cases/{case_id}", data={"status": "closed"}, headers=SAME)
    assert closed.status_code == 303
    late = await app.c.post(f"/ui/cases/{case_id}/items", data={"kind": "note", "note": "x"}, headers=SAME)
    assert late.status_code == 422
    cross = await app.c.post(
        f"/ui/cases/{case_id}", data={"status": "open"}, headers={"Sec-Fetch-Site": "cross-site"}
    )
    assert cross.status_code == 403
    await app.login("vera")
    assert (
        await app.c.post(f"/ui/cases/{case_id}", data={"status": "open"}, headers=SAME)
    ).status_code == 403
    assert (await app.c.get(case_url)).status_code == 404  # an AMBER case; viewers read GREEN


async def test_notes_and_saved_searches(app: App) -> None:
    ind = await app.ind(LIVE)
    await app.login("anna")
    r = await app.c.post(
        f"/ui/indicators/{ind.id}/notes", data={"body": "Seen in proxy logs at 09:12."}, headers=SAME
    )
    assert r.status_code == 303
    assert "Seen in proxy logs at 09:12." in (await app.c.get(f"/ui/indicators/{ind.id}")).text
    saved = await app.c.post(
        "/ui/searches",
        data={"name": "Live C2", "query": "/ui/indicators?source=feodo&status=active"},
        headers=SAME,
    )
    assert saved.status_code == 303
    page = await app.c.get("/ui/search")
    assert "Live C2" in page.text
    bad = await app.c.post("/ui/searches", data={"name": "x", "query": "https://evil.example/"}, headers=SAME)
    assert bad.status_code == 422
    await app.login("vera")  # saved searches are per account
    assert "Live C2" not in (await app.c.get("/ui/search")).text


async def test_search_lists_by_tag_and_entity(app: App) -> None:
    await app.login("vera")
    async with app.sm() as s, s.begin():
        await s.execute(update(Indicator).values(labels=["botnet-c2", "qakbot"]))
    r = await app.c.get("/ui/search", params={"q": "tag:qakbot"})
    assert r.status_code == 200
    assert "50[.]16[.]16[.]211" in r.text
    assert "QakBot" in (await app.c.get("/ui/search", params={"q": "qak", "show": "all"})).text


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
