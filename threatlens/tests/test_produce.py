"""Phase 8 production (ADR 0021): intelligence products (deterministic,
cited, TLP-capped, HTML and PDF) and lookalike-domain monitoring."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import httpx
from sqlalchemy import select

from tests.test_ai import state
from tests.test_cases import App
from tests.test_cases import app as app  # fixture (an explicit re-export)
from tests.test_enrich import Upstream, http, seeded, upstream  # noqa: F401  # fixtures
from tests.test_share import _add
from threatlens import cases, lookalike
from threatlens.ioc.types import IOCType
from threatlens.models import AlertRule, Block, Lookalike, Product
from threatlens.products import build, render, store
from threatlens.settings import Settings
from threatlens.share import alerts
from threatlens.worker import build_products

NOW = datetime.now(UTC)
TOMORROW = NOW + timedelta(days=1)  # a daily product "as of" tomorrow covers today
XSS = "<script>alert(1)</script> phishing wave"


async def _seed(app: App) -> dict[str, int]:
    ids = {
        "green": await _add(app, "185.62.188.23", IOCType.IPV4, score=85, tlp="TLP:GREEN"),
        "amber": await _add(app, "secret-c2.example.org", IOCType.DOMAIN, score=95, tlp="TLP:AMBER"),
        "low": await _add(app, "low-score.example.org", IOCType.DOMAIN, score=20),
    }
    async with app.sm() as s, s.begin():
        c = await cases.create_case(s, title=XSS, actor="anna", clearance="TLP:RED", tlp="TLP:GREEN")
        ids["case"] = c.id
        s.add(
            Lookalike(
                domain="example.com",
                candidate="examp1e.com",
                fuzzer="homoglyph",
                first_seen=NOW,
                last_seen=NOW,
                evidence=[{"source": "ct"}],
                status="new",
            )
        )
    return ids


def _settings(app: App) -> Settings:
    s: Settings = state(app).settings
    return s


# ── products ─────────────────────────────────────────────────────────────────


def test_windows() -> None:
    wed = datetime(2026, 10, 21, 10, 30, tzinfo=UTC)
    d = build.window("daily", wed)
    assert (d.start, d.end) == (datetime(2026, 10, 20, tzinfo=UTC), datetime(2026, 10, 21, tzinfo=UTC))
    w = build.window("weekly", wed)
    assert (w.start, w.end) == (datetime(2026, 10, 12, tzinfo=UTC), datetime(2026, 10, 19, tzinfo=UTC))
    assert build.window("exec", wed) == w
    assert w.days == 7


async def test_product_is_deterministic_cited_and_tlp_capped(app: App) -> None:
    ids = await _seed(app)
    settings = _settings(app)
    async with app.sm() as s:
        a = await build.build(s, "daily", TOMORROW, settings)
    async with app.sm() as s:
        b = await build.build(s, "daily", TOMORROW, settings)
    assert a == b
    assert a["sha256"] == b["sha256"] == build.digest({k: v for k, v in a.items() if k != "sha256"})
    top = a["body"]["indicators"]["top"]
    refs = {t["ref"] for t in top}
    assert f"indicator #{ids['green']}" in refs
    assert f"indicator #{ids['amber']}" not in refs
    green = next(t for t in top if t["ref"] == f"indicator #{ids['green']}")
    assert green["value"] == "185[.]62[.]188[.]23"
    assert green["sources"] == ["licensed"]
    assert green["link"] == f"/indicators/{ids['green']}"
    assert f"indicator #{ids['low']}" not in refs  # below the high-priority line
    assert a["tlp"] == "TLP:GREEN"
    assert a["maxTlp"] == "TLP:GREEN"
    assert a["body"]["cases"]["items"][0]["ref"] == f"case #{ids['case']}"
    assert a["body"]["lookalikes"]["items"][0]["candidate"] == "examp1e[.]com"
    async with app.sm() as s:
        amber = await build.build(s, "daily", TOMORROW, settings, "TLP:AMBER")
    assert amber["tlp"] == "TLP:AMBER"
    assert amber["sha256"] != a["sha256"]
    assert f"indicator #{ids['amber']}" in {t["ref"] for t in amber["body"]["indicators"]["top"]}
    page = render.html(a, "https://argus.example")
    assert page.count("TLP:GREEN</p>") == 2  # marking at the top and the bottom
    assert "<script>" not in page
    assert "&lt;script&gt;" in page
    assert f'href="https://argus.example/app/indicators/{ids["green"]}"' in page
    assert "examp1e[.]com" in page
    assert render.to_pdf(a).startswith(b"%PDF")


async def test_every_kind_builds_and_renders_on_an_empty_period(app: App) -> None:
    settings = _settings(app)
    for kind in build.KINDS:
        async with app.sm() as s:
            p = await build.build(s, kind, datetime(2020, 1, 8, 12, tzinfo=UTC), settings)
        assert p["kind"] == kind
        assert p["title"] == build.KINDS[kind]
        assert "<html" in render.html(p, "http://x")
        assert render.to_pdf(p).startswith(b"%PDF")
    assert p["body"]["risks"] == [{"risk": "No new high-priority threats in the period.",
                                   "action": "No action needed.", "refs": []}]  # fmt: skip


async def test_store_api_verify_and_clearance(app: App) -> None:
    ids = await _seed(app)
    settings = _settings(app)
    row = await store.generate(app.sm, settings, "daily", TOMORROW, actor="test")
    again = await store.generate(app.sm, settings, "daily", TOMORROW, actor="test")
    assert again.id == row.id  # one product per kind and period
    r = await app.c.get("/api/v1/products", headers=app.h("viewer"))
    assert [p["id"] for p in r.json()] == [row.id]
    assert r.json()[0]["tlp"] == "TLP:GREEN"
    r = await app.c.get(f"/api/v1/products/{row.id}", headers=app.h("viewer"))
    assert r.json()["content"]["sha256"] == row.sha256
    r = await app.c.get(f"/api/v1/products/{row.id}/html", headers=app.h("viewer"))
    assert r.status_code == 200
    assert "script-src" not in r.headers["content-security-policy"]
    assert r.headers["content-security-policy"].startswith("default-src 'none'")
    r = await app.c.get(f"/api/v1/products/{row.id}/pdf", headers=app.h("viewer"))
    assert r.headers["content-type"] == "application/pdf"
    assert r.content.startswith(b"%PDF")
    r = await app.c.post(f"/api/v1/products/{row.id}/verify", headers=app.h("viewer"))
    assert r.json() == {"stored": row.sha256, "rebuilt": row.sha256, "match": True}
    await _add(app, "45.83.12.9", IOCType.IPV4, score=90, tlp="TLP:CLEAR")  # the data changed
    r = await app.c.post(f"/api/v1/products/{row.id}/verify", headers=app.h("viewer"))
    assert r.json()["match"] is False

    settings.products_max_tlp = "TLP:AMBER"
    try:
        monday = NOW.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=NOW.weekday())
        weekly = await store.generate(app.sm, settings, "weekly", monday + timedelta(days=7, hours=1))
    finally:
        settings.products_max_tlp = "TLP:GREEN"
    assert weekly.tlp == "TLP:AMBER"
    assert f"indicator #{ids['amber']}" in json.dumps(weekly.content)
    r = await app.c.get(f"/api/v1/products/{weekly.id}", headers=app.h("viewer"))
    assert r.status_code == 404  # above a viewer's TLP:GREEN clearance
    r = await app.c.get("/api/v1/products", params={"kind": "weekly"}, headers=app.h("analyst"))
    assert [p["id"] for p in r.json()] == [weekly.id]


async def test_generate_endpoint(app: App) -> None:
    r = await app.c.post("/api/v1/products/generate", json={"kind": "vulns"}, headers=app.h("viewer"))
    assert r.status_code == 403
    r = await app.c.post("/api/v1/products/generate", json={"kind": "vulns"}, headers=app.h("analyst"))
    assert r.status_code == 201
    assert r.json()["kind"] == "vulns"
    assert r.json()["generatedBy"] == "analyst"
    future = (NOW + timedelta(days=2)).isoformat()
    r = await app.c.post(
        "/api/v1/products/generate", json={"kind": "daily", "as_of": future}, headers=app.h("analyst")
    )
    assert r.status_code == 422


async def test_worker_builds_what_is_due_once(app: App) -> None:
    ctx: dict[str, Any] = {"collector": SimpleNamespace(sm=app.sm, settings=_settings(app))}
    assert sorted(await store.due(app.sm, NOW)) == sorted(build.KINDS)
    first = await build_products(ctx)
    assert sorted(first) == sorted(build.KINDS)
    assert await build_products(ctx) == {}
    async with app.sm() as s:
        assert len((await s.scalars(select(Product))).all()) == 4


# ── lookalikes ───────────────────────────────────────────────────────────────

CRT = [
    {"name_value": "examp1e.com\n*.examp1e.com", "not_before": "2026-10-10T08:00:00"},
    {"name_value": "examp1e.com", "not_before": "2026-09-01T08:00:00"},  # the earliest wins
    {"name_value": "login.example.com", "not_before": "2026-10-11T08:00:00"},  # ours
    {"name_value": "example-secure-login.net", "not_before": "2026-10-12T08:00:00"},  # combosquat
    {"name_value": "shop.example.in", "not_before": "2026-10-12T08:00:00"},  # ours
]


def test_permutations_and_matching() -> None:
    perms = lookalike.permutations("example.com")
    assert perms["examp1e.com"] == "homoglyph"
    assert perms["exampel.com"] == "transposition"
    assert perms["example.net"] == "tld-swap"
    assert "example.com" not in perms
    names = [r["name_value"] for r in CRT] + ["unrelated.org", "EXAMPEL.COM."]
    got = lookalike.match(names, "example.com", perms, {"example.com", "example.in"})
    assert got == {"examp1e.com": "homoglyph", "example-secure-login.net": "keyword",
                   "exampel.com": "transposition"}  # fmt: skip


def _crt(calls: list[str], status: int = 200) -> httpx.MockTransport:
    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(str(req.url))
        assert req.url.host == "crt.sh"
        assert req.url.params["output"] == "json"
        return httpx.Response(status, json=CRT if status == 200 else {"error": "busy"})

    return httpx.MockTransport(handler)


async def test_scan_review_block_and_alert(app: App) -> None:
    feed = await _add(app, "exarnple.com", IOCType.DOMAIN, score=70)  # already in a feed
    calls: list[str] = []
    state(app).http_transport = _crt(calls)
    r = await app.c.post("/api/v1/lookalikes/scan", headers=app.h("viewer"))
    assert r.status_code == 403
    r = await app.c.post("/api/v1/lookalikes/scan", headers=app.h("analyst"))
    assert r.status_code == 200, r.text
    res = r.json()
    assert res["domains"] == ["example.com", "example.in"]
    assert res["new"] == 3
    assert res["errors"] == []
    assert len(calls) == 1
    assert "q=%25example%25" in calls[0]
    r = await app.c.get("/api/v1/lookalikes", headers=app.h("viewer"))
    items = {i["candidate"]: i for i in r.json()["items"]}
    assert set(items) == {"examp1e[.]com", "example-secure-login[.]net", "exarnple[.]com"}
    assert items["examp1e[.]com"]["evidence"] == [
        {"source": "ct", "first_certificate": "2026-09-01T08:00:00"}
    ]
    assert items["exarnple[.]com"]["evidence"] == [{"source": "feed", "indicator": feed}]
    assert items["exarnple[.]com"]["fuzzer"] == "homoglyph"
    r = await app.c.post("/api/v1/lookalikes/scan", headers=app.h("analyst"))
    assert r.json()["new"] == 0  # already known

    rule = AlertRule(name="look", kind="lookalike", enabled=True, params={}, channels=[], max_tlp="TLP:GREEN")
    assert alerts.check_rule("look", "lookalike", {}, [1], "TLP:GREEN") == {}
    async with app.sm() as s:
        got = await alerts.candidates(s, rule, NOW - timedelta(hours=1), _settings(app))
    assert {c.key for c in got} == {f"lookalike:{x}" for x in ("examp1e.com", "example-secure-login.net",
                                                                 "exarnple.com")}  # fmt: skip
    assert all(c.tlp == "TLP:CLEAR" and "[.]" in c.title for c in got)

    target = items["examp1e[.]com"]["id"]
    r = await app.c.post(
        f"/api/v1/lookalikes/{target}/review",
        json={"status": "confirmed", "block": True},
        headers=app.h("viewer"),
    )
    assert r.status_code == 403
    r = await app.c.post(
        f"/api/v1/lookalikes/{target}/review",
        json={"status": "confirmed", "block": True},
        headers=app.h("analyst"),
    )
    assert r.status_code == 200
    assert r.json()["status"] == "confirmed"
    assert r.json()["block"]
    async with app.sm() as s:
        b = await s.get(Block, r.json()["block"])
        assert b is not None
        assert b.value == "examp1e.com"
        assert b.mode == "monitor"
        assert "Lookalike of example.com" in b.note
        got = await alerts.candidates(s, rule, NOW - timedelta(hours=1), _settings(app))
    assert "lookalike:examp1e.com" not in {c.key for c in got}  # reviewed: no longer alerts
    r = await app.c.post(
        f"/api/v1/lookalikes/{items['exarnple[.]com']['id']}/review",
        json={"status": "benign"},
        headers=app.h("analyst"),
    )
    assert r.json()["status"] == "benign"
    assert r.json()["reviewedBy"] == "analyst"
    r = await app.c.get("/api/v1/lookalikes", params={"status": "confirmed"}, headers=app.h("viewer"))
    assert [i["candidate"] for i in r.json()["items"]] == ["examp1e[.]com"]


async def test_scan_survives_a_failing_ct_log(app: App) -> None:
    await _add(app, "examp1e.com", IOCType.DOMAIN, score=70)
    state(app).http_transport = _crt([], status=503)
    r = await app.c.post("/api/v1/lookalikes/scan", headers=app.h("analyst"))
    res = r.json()
    assert res["errors"]
    assert "crt.sh" in res["errors"][0]
    assert res["new"] == 1  # the feed still found one
    async with app.sm() as s:
        row = await s.scalar(select(Lookalike))
    assert row is not None
    assert row.candidate == "examp1e.com"
    assert row.evidence[0]["source"] == "feed"
