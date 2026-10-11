"""Verify an indicator and Bulk check, live (step 2): the streaming lookup,
the verify page with and without JavaScript, the NDJSON streams, Flag
malicious / Not malicious, file upload, auto-block, and the in-page JSON
answers."""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import select

from tests.test_cases import SAME, App
from tests.test_cases import app as app  # fixture (an explicit re-export)
from tests.test_enrich import FEODO_IP, IP, Upstream, http, seeded, upstream  # noqa: F401  # fixtures
from tests.uihelp import only_our_script
from threatlens import verify
from threatlens.models import AuditLog, Block, Indicator
from threatlens.models import Observable as ObsRow

LIVE = "50.16.16.211"  # the live Feodo C2: malicious
NEW = "185.220.101.77"  # nobody has reported it
JSON = {**SAME, "Accept": "application/json"}


def lines(body: str) -> list[dict[str, Any]]:
    return [json.loads(x) for x in body.splitlines() if x.strip()]


# ── the streaming lookup ─────────────────────────────────────────────────────


async def test_lookup_stream_reports_each_provider_then_the_verdict(app: App) -> None:
    svc = app.c._transport.app.state.enrich  # type: ignore[attr-defined]
    events = [(k, d) async for k, d in svc.lookup_stream(IP, actor="t", clearance="TLP:RED", tlp="TLP:CLEAR")]
    kinds = [k for k, _ in events]
    assert kinds[0] == "start"
    assert kinds[-1] == "done"
    start, done = events[0][1], events[-1][1]
    assert {p["enricher"] for p in start["pending"]} == {d["enricher"] for k, d in events if k == "enricher"}
    assert start["known"]["sources"] == ["feodo"]
    assert done["query"]["defanged"] == "162[.]243[.]103[.]246"
    assert {e["enricher"] for e in done["enrichments"]} == {p["enricher"] for p in start["pending"]}
    whole = await svc.lookup(IP, actor="t", clearance="TLP:RED", tlp="TLP:CLEAR")
    assert (whole["verdict"], whole["score"]) == (done["verdict"], done["score"])


async def test_closing_the_stream_early_is_clean(app: App) -> None:
    svc = app.c._transport.app.state.enrich  # type: ignore[attr-defined]
    gen = svc.lookup_stream(IP, actor="t", clearance="TLP:RED", tlp="TLP:CLEAR")
    assert (await gen.__anext__())[0] == "start"
    await gen.aclose()  # the reader went away: running providers are cancelled, nothing raises


# ── presentation helpers ─────────────────────────────────────────────────────


def test_headlines_and_fields() -> None:
    vt = {
        "enricher": "virustotal",
        "status": "ok",
        "summary": {"malicious": 5, "suspicious": 1, "engines": 92},
    }
    assert verify.headline(vt) == ("5/92 engines flag it, 1 suspicious", "mal")
    ab = {"enricher": "abuseipdb", "status": "cached", "summary": {"abuse_confidence": 0, "total_reports": 0}}
    assert verify.headline(ab) == ("Abuse confidence 0/100 · 0 reports", "ok")
    skip = {"enricher": "virustotal", "status": "skipped", "skipped_reason": "no_api_key"}
    assert verify.headline(skip)[1] == "off"
    rows = dict(
        verify.fields(
            "abuseipdb", {"abuse_confidence": 87, "is_tor": True, "hostnames": ["a", "b"], "x": None}
        )
    )
    assert rows == {"Abuse confidence": "87", "Tor exit": "yes", "Hostnames": "a, b"}


def test_second_opinion_links_follow_tlp() -> None:
    clear = {link.title for link in verify.second_opinion("ipv4-addr", "1.2.3.4", "TLP:CLEAR")}
    green = {link.title for link in verify.second_opinion("ipv4-addr", "1.2.3.4", "TLP:GREEN")}
    amber = verify.second_opinion("ipv4-addr", "1.2.3.4", "TLP:AMBER")
    assert "VirusTotal" in clear
    assert "VirusTotal" not in green  # its searches are public
    assert "AbuseIPDB" in green
    assert amber == []


# ── the verify page ──────────────────────────────────────────────────────────


async def test_verify_page_without_javascript_renders_everything(app: App) -> None:
    await app.login("vera")
    r = await app.c.get("/ui/verify", params={"q": "162.243.103[.]246", "tlp": "TLP:CLEAR"})
    assert r.status_code == 200
    for text in ("Our intel", "WHOIS (RDAP)", "Network &amp; geo", "DIGITALOCEAN-162-243-0-0", "Secaucus",
                 "Second opinion", "Actions", "Listed by <b>feodo</b>"):  # fmt: skip
        assert text in r.text, text
    assert "https://www.abuseipdb.com/check/162.243.103.246" in r.text
    assert 'rel="noopener noreferrer"' in r.text
    assert "Blocking and flagging need the analyst role" in r.text  # vera is a viewer
    assert only_our_script(r.text)
    bad = await app.c.get("/ui/verify", params={"q": "not an ioc!"})
    assert bad.status_code == 422


async def test_verify_live_page_and_stream(app: App) -> None:
    await app.login("anna")
    page = await app.c.get("/ui/verify", params={"q": FEODO_IP, "tlp": "TLP:CLEAR", "live": "true"})
    q = "162%5B.%5D243%5B.%5D103%5B.%5D246"
    stream_url = f"/ui/verify/stream?q={q}&amp;tlp=TLP%3ACLEAR&amp;providers=true"
    assert f'data-stream="{stream_url}"' in page.text  # the defanged value; the server refangs it
    assert "<noscript>" in page.text
    r = await app.c.get("/ui/verify/stream", params={"q": FEODO_IP, "tlp": "TLP:CLEAR"})
    assert r.headers["content-type"].startswith("application/x-ndjson")
    assert r.headers["cache-control"] == "no-store"
    msgs = lines(r.text)
    first = msgs[0]["ops"][0]
    assert (first["op"], first["id"]) == ("replace", "verify-body")
    assert "checking" in first["html"]
    assert 'id="vc-rdap"' in first["html"]  # a pending card per provider
    cards = [op["id"] for m in msgs[1:-1] for op in m["ops"]]
    assert "vc-rdap" in cards
    assert "vc-ripestat" in cards
    last = msgs[-1]
    assert last["done"] is True
    ids = [op["id"] for op in last["ops"]]
    assert ids == ["v-head", "vc-local", "vc-links", "vc-actions"]
    assert "Flag malicious" in last["ops"][3]["html"]  # anna is an analyst
    assert "162.243.103.246" not in "".join(
        op["html"] for m in msgs for op in m["ops"] if op["id"] != "vc-links"
    )


# ── flag malicious / not malicious ───────────────────────────────────────────


async def test_flag_a_new_value_creates_an_analyst_indicator(app: App) -> None:
    await app.login("anna")
    r = await app.c.post(
        "/ui/verify/flag", data={"values": NEW.replace(".", "[.]"), "verdict": "tp"}, headers=JSON
    )
    assert r.status_code == 200
    body = r.json()
    assert body["done"][0]["created"] is True
    assert body["done"][0]["input"] == "185[.]220[.]101[.]77"
    async with app.sm() as s:
        ind = await s.scalar(select(Indicator).join(ObsRow).where(ObsRow.value == NEW))
        audit = await s.scalar(select(AuditLog.action).where(AuditLog.action == "indicator.submit"))
    assert ind is not None
    assert verify.ANALYST_LABEL in ind.labels
    assert ind.analyst_verdict == "tp"
    assert (ind.priority_score or 0) > 0  # scored from the analyst signal
    assert audit == "indicator.submit"
    looked = await app.c.get("/ui/verify", params={"q": NEW, "providers": "false"})
    assert "Flagged by an analyst" in looked.text
    again = await app.c.post("/ui/verify/flag", data={"values": NEW, "verdict": "fp"}, headers=JSON)
    assert again.json()["done"][0]["created"] is False
    async with app.sm() as s:
        assert (await s.scalar(select(Indicator.status).where(Indicator.id == ind.id))) == "false_positive"


async def test_flag_rules(app: App) -> None:
    await app.login("anna")
    r = await app.c.post("/ui/verify/flag", data={"values": ["185.220.101.78", "nonsense!"], "verdict": "fp"},
                         headers=JSON)  # fmt: skip
    assert r.status_code == 200
    why = [x["why"] for x in r.json()["refused"]]
    assert "nothing to mark not malicious" in why[0]
    assert "not an IP, domain" in why[1]
    html = await app.c.post("/ui/verify/flag", data={"values": LIVE, "verdict": "tp"}, headers=SAME)
    assert "1 recorded" in html.text
    assert (await app.c.post("/ui/verify/flag", data={"values": LIVE, "verdict": "tp"},
                             headers={"Sec-Fetch-Site": "cross-site"})).status_code == 403  # fmt: skip
    await app.login("vera")
    assert (
        await app.c.post("/ui/verify/flag", data={"values": LIVE, "verdict": "tp"}, headers=SAME)
    ).status_code == 403


async def test_block_buttons_get_json(app: App) -> None:
    await app.login("anna")
    r = await app.c.post(
        "/ui/blocklist", data={"values": [NEW, "10.0.0.1"], "origin": "lookup"}, headers=JSON
    )
    assert r.status_code == 200
    body = r.json()
    assert [c["input"] for c in body["created"]] == [NEW]
    assert body["created"][0]["state"] == "monitor"
    assert "private or reserved" in body["refused"][0]["why"]


# ── bulk check ───────────────────────────────────────────────────────────────


async def test_bulk_stream_with_upload_and_autoblock(app: App) -> None:
    await app.login("anna")
    files = [("files", ("alert.log", f"conn to {LIVE}:443 and 162.243.103[.]246\n".encode(), "text/plain")),
             ("files", ("bin.exe", b"MZ\x00\x00 1.2.3.4", "application/octet-stream"))]  # fmt: skip
    r = await app.c.post(
        "/ui/lookup/stream", data={"text": "evil-c2.top", "autoblock": "true"}, files=files, headers=SAME
    )
    assert r.status_code == 200
    msgs = lines(r.text)
    assert msgs[0]["ops"][0]["id"] == "bulk-results"
    assert "bin.exe: skipped, not a text file" in msgs[0]["ops"][0]["html"]
    assert msgs[0]["progress"] == [0, 3]
    rows = [op["html"] for m in msgs for op in m["ops"] if op["op"] == "append"]
    assert len(rows) == 3
    assert msgs[-1]["done"] is True
    assert msgs[-1]["progress"] == [3, 3]
    live_row = next(h for h in rows if "50[.]16[.]16[.]211" in h)
    assert 'data-verdict="malicious"' in live_row
    assert ">blocked<" in live_row
    assert "1 auto-blocked" in msgs[-1]["ops"][0]["html"]
    async with app.sm() as s:
        b = await s.scalar(select(Block).where(Block.value == LIVE))
    assert b is not None
    assert (b.mode, b.reason, b.note) == ("monitor", "known_bad", "auto-blocked from a bulk check")
    assert all(LIVE not in h for h in rows)  # rows show values defanged


async def test_bulk_without_javascript(app: App) -> None:
    await app.login("anna")
    files = [("files", ("iocs.txt", f"{LIVE}\nevil-c2.top\n".encode(), "text/plain"))]
    r = await app.c.post("/ui/lookup", data={"format": "html"}, files=files, headers=SAME)
    assert r.status_code == 200
    assert r.text.count('class="brow"') == 2
    assert "<b>Done.</b>" in r.text
    assert 'formaction="/ui/verify/flag"' in r.text
    assert only_our_script(r.text)
    empty = await app.c.post("/ui/lookup", data={"text": "nothing here"}, headers=SAME)
    assert empty.status_code == 422
    stream = await app.c.post("/ui/lookup/stream", data={"text": "nothing here"}, headers=SAME)
    assert stream.status_code == 422
    await app.login("vera")
    assert (await app.c.post("/ui/lookup/stream", data={"text": LIVE}, headers=SAME)).status_code == 403


async def test_overview_has_the_verify_bar_and_the_script_is_served(app: App) -> None:
    await app.login("vera")
    r = await app.c.get("/ui")
    assert 'action="/ui/verify"' in r.text
    assert "data-verify" in r.text
    assert "script-src 'self'" in r.headers["content-security-policy"]
    js = await app.c.get("/ui/static/app.js")
    assert js.status_code == 200
    assert "eval(" not in js.text
    assert "innerHTML = '<p" in js.text  # only fixed strings or server-rendered HTML go into the page
