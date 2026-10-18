"""Phase 5 analyst experience: the indicator page's context (stored
enrichment, graph pivots, techniques, timeline), saved views, case export to
PDF, and CSV cells that a spreadsheet won't run."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from tests.test_cases import LIVE, SAME, App
from tests.test_cases import app as app  # fixture (an explicit re-export)
from tests.test_enrich import FEODO_IP, Upstream, http, seeded, upstream  # noqa: F401  # fixtures
from threatlens import cases as case_store
from threatlens import pdf
from threatlens.argus_api import sheet_safe
from threatlens.models import AuditLog, Indicator


async def test_indicator_context_uses_stored_answers_only(app: App, upstream: Upstream) -> None:  # noqa: F811
    await app.login("anna")
    ind = await app.ind(FEODO_IP)
    before = (await app.c.get(f"/app/api/indicators/{ind.id}/related")).json()
    assert before["enrichments"] == []  # nothing asked yet, and the page asks nobody
    assert {t["kind"] for t in before["timeline"]} <= {"first", "last"}
    assert upstream.calls == []

    await app.c.get("/app/api/verify/stream", params={"q": FEODO_IP, "tlp": "TLP:CLEAR"})
    r = await app.c.get(f"/app/api/indicators/{ind.id}/related")
    assert r.status_code == 200
    d = r.json()
    by = {c["enricher"]: c for c in d["enrichments"]}
    assert {"rdap", "ripestat"} <= set(by)
    assert by["ripestat"]["status"] == "cached"
    assert isinstance(by["ripestat"]["fresh"], bool)  # the test clock is pinned, so not asserted fresh
    assert by["ripestat"]["headline"]
    assert any(t["kind"] == "enriched" and t["source"] == "ripestat" for t in d["timeline"])
    assert [t["at"] for t in d["timeline"]] == sorted(t["at"] for t in d["timeline"])
    assert FEODO_IP not in r.text  # values leave the server defanged
    asked = len(upstream.calls)
    await app.c.get(f"/app/api/indicators/{ind.id}/related")
    assert len(upstream.calls) == asked  # reading the page never calls a provider


async def test_indicator_context_pivots_to_malware(app: App) -> None:
    await app.login("vera")
    ind = await app.ind(LIVE)
    d = (await app.c.get(f"/app/api/indicators/{ind.id}/related")).json()
    names = {g["name"] for g in d["groups"]}
    assert "Malware" in names
    malware = next(g for g in d["groups"] if g["name"] == "Malware")["items"]
    assert all(m["href"].startswith("/entities/") for m in malware)
    assert all(m["source"] for m in malware)  # every link says who asserted it


async def test_indicator_context_respects_clearance(app: App) -> None:
    await app.login("vera")
    assert (await app.c.get("/app/api/indicators/999999/related")).status_code == 404
    ind = await app.ind(LIVE)
    async with app.sm() as s, s.begin():
        row = await s.get(Indicator, ind.id)
        assert row is not None
        row.tlp = "TLP:RED"
    assert (await app.c.get(f"/app/api/indicators/{ind.id}/related")).status_code == 404  # above clearance


async def test_saved_views_are_per_account_and_stay_inside_argus(app: App) -> None:
    await app.login("anna")
    r = await app.c.post(
        "/app/api/searches", json={"name": "Qakbot", "query": "/search?q=tag:qakbot"}, headers=SAME
    )
    assert r.status_code == 201
    sid = r.json()["id"]
    # the same name again updates the view instead of duplicating it
    await app.c.post(
        "/app/api/searches", json={"name": "Qakbot", "query": "/app/indicators?q=qakbot"}, headers=SAME
    )
    rows = (await app.c.get("/app/api/searches")).json()
    assert [(x["name"], x["query"]) for x in rows] == [("Qakbot", "/indicators?q=qakbot")]
    for bad in ("https://evil.example/", "//evil.example/x", "/api/v1/indicators", "/x\\..\\y"):
        r = await app.c.post("/app/api/searches", json={"name": "bad", "query": bad}, headers=SAME)
        assert r.status_code == 422, bad
    await app.login("vera")
    assert (await app.c.get("/app/api/searches")).json() == []  # anna's views are hers
    assert (await app.c.delete(f"/app/api/searches/{sid}", headers=SAME)).status_code == 404
    await app.login("anna")
    assert (await app.c.delete(f"/app/api/searches/{sid}", headers=SAME)).status_code == 204
    assert (await app.c.get("/app/api/searches")).json() == []


@pytest.mark.parametrize(
    ("stored", "path"),
    [
        ("/ui/indicators?sort=priority", "/indicators?sort=priority"),
        ("/ui", "/"),
        ("/search?q=x", "/search?q=x"),
    ],
)
def test_views_saved_by_the_old_ui_still_open(stored: str, path: str) -> None:
    assert case_store.app_path(stored) == path


async def test_case_exports_as_pdf_with_its_marking(app: App) -> None:
    ind = await app.ind(LIVE)
    r = await app.c.post(
        "/api/v1/cases",
        json={"title": "PDF case \u202eevil", "tlp": "TLP:AMBER"},
        headers=app.h("analyst"),
    )
    assert r.status_code == 201
    cid = r.json()["id"]
    await app.c.post(
        f"/api/v1/cases/{cid}/items",
        json={"kind": "indicator", "ref": str(ind.id), "note": "x" * 3000},
        headers=app.h("analyst"),
    )
    # a GREEN-cleared reader can't see an AMBER case at all
    assert (await app.c.get(f"/api/v1/cases/{cid}/export.pdf", headers=app.h("green"))).status_code == 404
    out = await app.c.get(f"/api/v1/cases/{cid}/export.pdf", headers=app.h("analyst"))
    assert out.status_code == 200
    assert out.headers["content-type"] == "application/pdf"
    assert out.content.startswith(b"%PDF-")
    assert f'filename="case-{cid}.pdf"' in out.headers["content-disposition"]
    async with app.sm() as s:
        fmts = (await s.scalars(select(AuditLog.details).where(AuditLog.action == "case.export"))).all()
    assert {"format": "pdf"} in fmts


def test_pdf_text_is_plain_and_bounded() -> None:
    assert pdf.clean("a\x00b\u202ec") == "abc"  # control and bidi-override characters dropped
    assert max(len(w) for w in pdf.clean("A" * 500).split()) <= 60  # no unbreakable token
    body = pdf.render(
        "T",
        [pdf.h1("Title"), pdf.table(["a", "b"], [["1", "**not markdown**"]]), pdf.p("")],
        marking="TLP:RED",
    )
    assert body.startswith(b"%PDF-")


@pytest.mark.parametrize(
    ("value", "cell"),
    [("=HYPERLINK(1)", "'=HYPERLINK(1)"), ("+1", "'+1"), ("-1", "'-1"), ("@SUM", "'@SUM"),
     ("\tx", "'\tx"), ("plain", "plain"), (None, ""), (7, "7")],
)  # fmt: skip
def test_csv_cells_never_become_formulas(value: object, cell: str) -> None:
    assert sheet_safe(value) == cell


async def test_reports_defang_free_text_too(app: App) -> None:
    r = await app.c.post(
        "/api/v1/cases",
        json={"title": "Investigate http://evil-c2.example/x", "summary": "beacons to 203.0.113.9"},
        headers=app.h("analyst"),
    )
    md = (await app.c.get(f"/api/v1/cases/{r.json()['id']}/export.md", headers=app.h("analyst"))).text
    assert "hxxp[://]evil-c2[.]example/x" in md
    assert "203[.]0[.]113[.]9" in md
    assert "http://evil-c2.example" not in md
