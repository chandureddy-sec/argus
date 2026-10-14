"""Argus reading the REST API with its sign-in session, and the Argus-only
JSON (ADR 0015): live Verify and Bulk check as JSON events, flagging, block
actions, settings and the never-block list."""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import select

from tests.test_cases import LIVE, SAME, App
from tests.test_cases import app as app  # fixture (an explicit re-export)
from tests.test_enrich import FEODO_IP, Upstream, http, seeded, upstream  # noqa: F401  # fixtures
from threatlens.models import Block
from threatlens.users import create_user

CROSS = {"Sec-Fetch-Site": "cross-site"}


def events(text: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in text.splitlines() if line.strip()]


async def admin(app: App) -> None:
    async with app.sm() as s, s.begin():
        await create_user(s, "ada", "ada-password", "admin")
    await app.login("ada")


async def test_the_api_accepts_the_session_with_a_csrf_rule(app: App) -> None:
    assert (await app.c.get("/api/v1/indicators")).status_code == 401
    await app.login("vera")
    assert (await app.c.get("/api/v1/indicators")).status_code == 200
    assert (
        await app.c.post("/api/v1/blocks", json={"value": LIVE}, headers=SAME)
    ).status_code == 403  # viewer
    await app.login("anna")
    assert (await app.c.post("/api/v1/blocks", json={"value": LIVE}, headers=CROSS)).status_code == 403
    r = await app.c.post("/api/v1/blocks", json={"value": LIVE}, headers=SAME)
    assert r.status_code == 201
    assert r.json()["mode"] == "monitor"
    # API keys work as before, session or not
    assert (await app.c.get("/api/v1/indicators", headers=app.h("viewer"))).status_code == 200


async def test_verify_stream_is_json_and_defanged(app: App) -> None:
    await app.login("anna")
    r = await app.c.get("/app/api/verify/stream", params={"q": FEODO_IP, "tlp": "TLP:CLEAR"})
    assert r.headers["content-type"].startswith("application/x-ndjson")
    evs = events(r.text)
    assert evs[0]["event"] == "start"
    assert evs[0]["query"] == {
        "type": "ipv4-addr",
        "typeLabel": "IPv4 address",
        "value": "162[.]243[.]103[.]246",
    }
    assert {p["enricher"] for p in evs[0]["pending"]} >= {"rdap", "ripestat"}
    providers = [e["card"] for e in evs if e["event"] == "provider"]
    assert {c["title"] for c in providers} >= {"WHOIS registration", "Network & location"}
    ripe = next(c for c in providers if c["enricher"] == "ripestat")
    assert ripe["headline"]
    assert ["Network owner", "DIGITALOCEAN-ASN"] in ripe["rows"] or ripe["rows"]
    done = evs[-1]
    assert done["event"] == "done"
    assert done["verdictLabel"] in ("Malicious", "Suspicious", "No known threat", "Clean")
    assert done["known"]["sources"] == ["feodo"]
    assert done["blockable"] is True
    assert any(link["url"].startswith("https://www.abuseipdb.com/check/") for link in done["links"])
    without_links = json.dumps([e for e in evs if e["event"] != "done"] + [{**done, "links": []}])
    assert FEODO_IP not in without_links  # live values only in the second-opinion links


async def test_bulk_stream_rows_and_autoblock(app: App) -> None:
    await app.login("anna")
    r = await app.c.post(
        "/app/api/bulk/stream",
        data={"text": f"{LIVE}\n162.243.103[.]246\nevil-c2.top", "autoblock": "true"},
        headers=SAME,
    )
    evs = events(r.text)
    assert evs[0] == {"event": "start", "total": 3, "notes": []}
    rows = [e["row"] for e in evs if e["event"] == "row"]
    assert len(rows) == 3
    live = next(x for x in rows if x["query"]["value"] == "50[.]16[.]16[.]211")
    assert live["verdict"] == "malicious"
    assert live["block"]["mode"] == "monitor"
    assert evs[-1]["event"] == "done"
    assert evs[-1]["blocked"] == ["50[.]16[.]16[.]211"]
    assert LIVE not in r.text
    await app.login("vera")
    assert (await app.c.post("/app/api/bulk/stream", data={"text": LIVE}, headers=SAME)).status_code == 403


async def test_flag_and_block_actions(app: App) -> None:
    await app.login("anna")
    r = await app.c.post(
        "/app/api/verify/flag", json={"values": ["evil-c2.top"], "verdict": "tp"}, headers=SAME
    )
    assert r.json()["done"][0]["value"] == "evil-c2[.]top"
    b = (await app.c.post("/api/v1/blocks", json={"value": LIVE}, headers=SAME)).json()
    counts = (await app.c.get("/app/api/blocks/counts")).json()
    assert counts["counts"]["monitor"] >= 1
    ext = await app.c.post(f"/app/api/blocks/{b['id']}/extend", json={"days": 30}, headers=SAME)
    assert ext.status_code == 200
    assert ext.json()["expires_at"] > b["expires_at"]
    assert (
        await app.c.post(f"/app/api/blocks/{b['id']}/extend", json={"days": 999}, headers=SAME)
    ).status_code == 422


async def test_settings_tokens_and_never_block(app: App) -> None:
    await app.login("vera")
    st = (await app.c.get("/app/api/settings")).json()
    assert st["canEdit"] is False
    assert "ip.txt" in st["formats"]
    assert (await app.c.put("/app/api/settings/policy", json=st["policy"], headers=SAME)).status_code == 403
    await admin(app)
    policy = st["policy"] | {"manual_days": 5}
    assert (await app.c.put("/app/api/settings/policy", json=policy, headers=SAME)).json()["manual_days"] == 5
    bad = st["policy"] | {"export_max_tlp": "TLP:RED"}
    assert (await app.c.put("/app/api/settings/policy", json=bad, headers=SAME)).status_code == 422
    tok = await app.c.post("/app/api/settings/tokens", json={"name": "hq-firewall"}, headers=SAME)
    assert tok.headers["cache-control"] == "no-store"
    secret = tok.json()["token"]
    assert any(u.endswith("/ip.txt") and secret in u for u in tok.json()["urls"])
    listed = (await app.c.get("/app/api/settings")).json()["tokens"]
    assert listed[0]["name"] == "hq-firewall"
    assert secret not in json.dumps(listed)  # shown once only
    assert (await app.c.post(f"/app/api/settings/tokens/{listed[0]['id']}/revoke", headers=SAME)).json() == {
        "status": "revoked"
    }
    nb = await app.c.post(
        "/app/api/neverblock", json={"value": "203.0.113.0/24", "reason": "our office"}, headers=SAME
    )
    assert nb.json()["kind"] == "cidr"
    assert (await app.c.post("/app/api/neverblock", json={"value": "not a thing", "reason": "x y z"},
                             headers=SAME)).status_code == 422  # fmt: skip
    entries = (await app.c.get("/app/api/neverblock")).json()
    entry = next(e for e in entries["manual"] if e["value"].startswith("203[.]0[.]113"))
    assert (await app.c.delete(f"/app/api/neverblock/{entry['id']}", headers=SAME)).json() == {
        "status": "deleted"
    }
    assert (await app.c.get("/app/api/feeds/feodo/form")).status_code == 404  # built-in feeds have no form


async def test_blocks_made_in_argus_are_ordinary_blocks(app: App) -> None:
    await app.login("anna")
    await app.c.post("/api/v1/blocks", json={"value": LIVE, "note": "from Argus"}, headers=SAME)
    async with app.sm() as s:
        b = await s.scalar(select(Block).where(Block.value == LIVE))
    assert b is not None
    assert (b.created_by, b.note) == ("anna", "from Argus")
