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
from threatlens import verify
from threatlens.models import AuditLog, Block, Indicator
from threatlens.models import Observable as ObsRow

LIVE = "50.16.16.211"  # the live Feodo C2: malicious
NEW = "185.220.101.77"  # nobody has reported it


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
    assert verify.headline(vt) == ("5 of 92 security engines flag it (1 more suspicious)", "mal")
    ab = {"enricher": "abuseipdb", "status": "cached", "summary": {"abuse_confidence": 0, "total_reports": 0}}
    assert verify.headline(ab) == ("No abuse reports", "ok")
    old = {
        "enricher": "rdap",
        "status": "ok",
        "summary": {"registrar": "R", "created": "2024-06-02T12:16:00+00:00", "age_days": 860},
    }
    assert verify.headline(old) == ("Registered 2 Jun 2024 (2 years 4 months ago) via R", "info")
    skip = {"enricher": "virustotal", "status": "skipped", "skipped_reason": "no_api_key"}
    assert verify.headline(skip)[1] == "off"
    rows = dict(
        verify.fields(
            "abuseipdb", {"abuse_confidence": 87, "is_tor": True, "hostnames": ["a", "b"], "x": None}
        )
    )
    assert rows == {"Abuse confidence": "87 / 100", "Tor exit node": "yes", "Host names": ["a", "b"]}
    crt = dict(
        verify.fields(
            "crtsh", {"certificates": 1200, "first_issued": "2024-06-02T00:00:00", "names_total": 3}
        )
    )
    assert crt == {"Certificates": "1,200", "First issued": "2 Jun 2024"}  # names_total is not worth a row


def test_second_opinion_links_follow_tlp() -> None:
    clear = {link.title for link in verify.second_opinion("ipv4-addr", "1.2.3.4", "TLP:CLEAR")}
    green = {link.title for link in verify.second_opinion("ipv4-addr", "1.2.3.4", "TLP:GREEN")}
    amber = verify.second_opinion("ipv4-addr", "1.2.3.4", "TLP:AMBER")
    assert "VirusTotal" in clear
    assert "VirusTotal" not in green  # its searches are public
    assert "AbuseIPDB" in green
    assert amber == []


# ── flag malicious / not malicious ───────────────────────────────────────────


async def test_flag_a_new_value_creates_an_analyst_indicator(app: App) -> None:
    await app.login("anna")
    r = await app.c.post(
        "/app/api/verify/flag", json={"values": [NEW.replace(".", "[.]")], "verdict": "tp"}, headers=SAME
    )
    assert r.status_code == 200
    body = r.json()
    assert body["done"][0]["created"] is True
    assert body["done"][0]["value"] == "185[.]220[.]101[.]77"
    async with app.sm() as s:
        ind = await s.scalar(select(Indicator).join(ObsRow).where(ObsRow.value == NEW))
        audit = await s.scalar(select(AuditLog.action).where(AuditLog.action == "indicator.submit"))
    assert ind is not None
    assert verify.ANALYST_LABEL in ind.labels
    assert ind.analyst_verdict == "tp"
    assert (ind.priority_score or 0) > 0  # scored from the analyst signal
    assert audit == "indicator.submit"
    looked = lines((await app.c.get("/app/api/verify/stream", params={"q": NEW, "providers": "false"})).text)
    assert "analyst-submitted" in looked[-1]["known"]["labels"]
    again = await app.c.post("/app/api/verify/flag", json={"values": [NEW], "verdict": "fp"}, headers=SAME)
    assert again.json()["done"][0]["created"] is False
    async with app.sm() as s:
        assert (await s.scalar(select(Indicator.status).where(Indicator.id == ind.id))) == "false_positive"


async def test_flag_rules(app: App) -> None:
    await app.login("anna")
    r = await app.c.post(
        "/app/api/verify/flag",
        json={"values": ["185.220.101.78", "nonsense!"], "verdict": "fp"},
        headers=SAME,
    )
    assert r.status_code == 200
    why = [x["why"] for x in r.json()["refused"]]
    assert "nothing to mark not malicious" in why[0]
    assert "not an IP, domain" in why[1]
    assert (await app.c.post("/app/api/verify/flag", json={"values": [LIVE], "verdict": "tp"},
                             headers={"Sec-Fetch-Site": "cross-site"})).status_code == 403  # fmt: skip
    await app.login("vera")
    assert (
        await app.c.post("/app/api/verify/flag", json={"values": [LIVE], "verdict": "tp"}, headers=SAME)
    ).status_code == 403


async def test_blocking_refuses_private_values(app: App) -> None:
    await app.login("anna")
    made = await app.c.post("/api/v1/blocks", json={"value": NEW}, headers=SAME)
    assert made.status_code == 201
    assert made.json()["state"] == "monitor"
    refused = await app.c.post("/api/v1/blocks", json={"value": "10.0.0.1"}, headers=SAME)
    assert refused.status_code == 422
    assert "private or reserved" in refused.json()["detail"]


# ── bulk check ───────────────────────────────────────────────────────────────


async def test_bulk_stream_with_upload_and_autoblock(app: App) -> None:
    await app.login("anna")
    files = [("files", ("alert.log", f"conn to {LIVE}:443 and 162.243.103[.]246\n".encode(), "text/plain")),
             ("files", ("bin.exe", b"MZ\x00\x00 1.2.3.4", "application/octet-stream"))]  # fmt: skip
    r = await app.c.post(
        "/app/api/bulk/stream", data={"text": "evil-c2.top", "autoblock": "true"}, files=files, headers=SAME
    )
    assert r.status_code == 200
    evs = lines(r.text)
    assert evs[0]["event"] == "start"
    assert evs[0]["total"] == 3
    assert "bin.exe: skipped, not a text file" in evs[0]["notes"]
    rows = [e["row"] for e in evs if e["event"] == "row"]
    assert len(rows) == 3
    live = next(x for x in rows if x["query"]["value"] == "50[.]16[.]16[.]211")
    assert live["verdict"] == "malicious"
    assert live["block"]["mode"] == "monitor"
    assert evs[-1]["blocked"] == ["50[.]16[.]16[.]211"]
    async with app.sm() as s:
        b = await s.scalar(select(Block).where(Block.value == LIVE))
    assert b is not None
    assert (b.mode, b.reason, b.note) == ("monitor", "known_bad", "auto-blocked from a bulk check")
    assert LIVE not in r.text  # rows show values defanged
