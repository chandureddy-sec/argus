"""Blocklist and feed export (ADR 0010): the never-block guard, the block
lifecycle with four eyes, expiry and TLP on export, the export formats, the
token-protected feed URL, and the UI pages."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select, update

from tests.test_cases import SAME, App
from tests.test_cases import app as app  # fixture (an explicit re-export)
from tests.test_enrich import Upstream, http, seeded, upstream  # noqa: F401  # fixtures
from threatlens import blocking
from threatlens.auth import create_key
from threatlens.models import AllowlistEntry, Asset, AuditLog, Block, Indicator
from threatlens.models import Observable as ObsRow
from threatlens.users import create_user

LIVE = "50.16.16.211"  # the live Feodo C2 in the seeded feed
FREE = "185.220.101.34"  # a global address no fixture knows


async def _admins(app: App) -> None:
    async with app.sm() as s, s.begin():
        await create_user(s, "ada", "ada-password", "admin")
        await create_user(s, "bob", "bob-password", "admin")


async def _score(app: App, value: str, score: float) -> None:
    async with app.sm() as s, s.begin():
        oid = await s.scalar(select(ObsRow.id).where(ObsRow.value == value))
        await s.execute(update(Indicator).where(Indicator.observable_id == oid).values(priority_score=score))


# ── the never-block guard ────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("value", "why"),
    [
        ("10.1.2.3", "private or reserved"),
        ("192.168.0.0/24", "private or reserved"),
        ("100.64.1.1", "private or reserved"),  # CGNAT
        ("8.8.8.8", "public DNS resolver"),
        ("8.8.8.0/24", "public DNS resolver"),
        ("45.0.0.0/8", "broader than /16"),
        ("198.51.100.9", "private or reserved"),  # documentation range
        ("44d88612fea8a8f36de82e1278abb02f", "only IPs"),
        ("not a value at all", "not a valid"),
    ],
)
async def test_built_in_never_block_rules(app: App, value: str, why: str) -> None:
    async with app.sm() as s:
        with pytest.raises(blocking.BlockError, match=why):
            await blocking.create_block(s, value, actor="t", clearance="TLP:RED")


async def test_own_assets_and_allowlist_are_never_blocked(app: App) -> None:
    async with app.sm() as s, s.begin():
        s.add(
            Asset(
                kind="ip",
                value="93.184.216.34",
                canonical_key="ipv4-addr|93.184.216.34",
                target="ours-corp.com",
            )
        )
        s.add(Asset(kind="host", value="www.ours-corp.com", canonical_key="domain-name|www.ours-corp.com",
                    target="ours-corp.com"))  # fmt: skip
        s.add(
            AllowlistEntry(
                kind="cidr", value="151.101.0.0/16", effect="flag", reason="Fastly edge", origin="fastly"
            )
        )
        s.add(
            AllowlistEntry(
                kind="domain", value="google.com", effect="suppress", reason="Tranco top", origin="tranco"
            )
        )
        s.add(
            AllowlistEntry(
                kind="cidr", value="185.220.100.0/24", effect="flag", reason="office", origin="manual"
            )
        )
    async with app.sm() as s:
        guard = await blocking.load_guard(s)
        refused = {
            "93.184.216.34": "our asset",
            "93.184.216.0/24": "contains 93.184.216.34",
            "ours-corp.com": "contains www.ours-corp.com",
            "www.ours-corp.com": "our asset",
            "https://www.ours-corp.com/login": "our asset",
            "151.101.1.1": "Fastly edge",
            "google.com": "Tranco top",
            "185.220.100.7": "office",
        }
        for value, why in refused.items():
            with pytest.raises(blocking.BlockError, match=why):
                await blocking.create_block(s, value, actor="t", clearance="TLP:RED", guard=guard)
        # a bad URL on a popular site is still blockable; so is an unrelated sibling domain
        for ok in ("https://docs.google.com/evil-form", "evil-ours-corp.com", FREE):
            assert guard.why(blocking.parse_target(ok)) is None, ok


# ── lifecycle ────────────────────────────────────────────────────────────────


async def test_reason_and_duration_follow_the_policy(app: App) -> None:
    await _score(app, LIVE, 85)
    now = datetime.now(UTC)
    async with app.sm() as s, s.begin():
        bad = await blocking.create_block(
            s, LIVE, actor="anna", clearance="TLP:RED", origin="lookup", now=now
        )
        typed = await blocking.create_block(
            s, FREE, actor="anna", clearance="TLP:RED", origin="manual", now=now
        )
        guess = await blocking.create_block(
            s, "evil-c2.top", actor="anna", clearance="TLP:RED", origin="lookup", now=now
        )
        assert (bad.reason, bad.mode, bad.score) == ("known_bad", "monitor", 85)
        assert bad.indicator_id is not None
        assert bad.expires_at - now == timedelta(days=30)
        assert (typed.reason, typed.expires_at - now) == ("manual", timedelta(days=30))
        assert (guess.reason, guess.expires_at - now) == ("suspect", timedelta(days=6))
        with pytest.raises(blocking.BlockError, match="already blocked"):
            await blocking.create_block(s, "50.16.16[.]211", actor="anna", clearance="TLP:RED")
    async with app.sm() as s:
        actions = (await s.scalars(select(AuditLog.action).where(AuditLog.action.like("block.%")))).all()
    assert actions.count("block.create") == 3


async def test_an_indicator_above_clearance_is_treated_as_unknown(app: App) -> None:
    await _score(app, LIVE, 85)
    async with app.sm() as s, s.begin():
        oid = await s.scalar(select(ObsRow.id).where(ObsRow.value == LIVE))
        await s.execute(update(Indicator).where(Indicator.observable_id == oid).values(tlp="TLP:RED"))
        b = await blocking.create_block(s, LIVE, actor="vera", clearance="TLP:GREEN", origin="lookup")
        assert (b.reason, b.indicator_id, b.score, b.tlp) == ("suspect", None, None, "TLP:CLEAR")


async def test_enforcing_needs_a_second_admin(app: App) -> None:
    async with app.sm() as s, s.begin():
        b = await blocking.create_block(s, FREE, actor="anna", clearance="TLP:RED")
        with pytest.raises(blocking.BlockError, match="nobody has asked"):
            await blocking.approve(s, b, actor="ada", is_admin=True)
        await blocking.request_enforce(s, b, actor="ada", is_admin=True)
        assert blocking.state(b) == "pending"
        with pytest.raises(blocking.BlockError, match="admin role"):
            await blocking.approve(s, b, actor="anna", is_admin=False)
        with pytest.raises(blocking.BlockError, match="your own request"):
            await blocking.approve(s, b, actor="ada", is_admin=True)
        await blocking.approve(s, b, actor="bob", is_admin=True)
        assert (blocking.state(b), b.approved_by, b.requested_by) == ("enforce", "bob", "ada")
        with pytest.raises(blocking.BlockError, match="already enforced"):
            await blocking.request_enforce(s, b, actor="anna", is_admin=False)


async def test_without_four_eyes_an_admin_enforces_at_once(app: App) -> None:
    async with app.sm() as s, s.begin():
        await blocking.set_policy(s, {"require_second_approver": False}, actor="ada")
        b = await blocking.create_block(s, FREE, actor="anna", clearance="TLP:RED")
        await blocking.request_enforce(s, b, actor="anna", is_admin=False)  # an analyst still only asks
        assert blocking.state(b) == "pending"
        await blocking.approve(s, b, actor="anna", is_admin=True)  # own request is fine now
        c = await blocking.create_block(s, "evil-c2.top", actor="ada", clearance="TLP:RED")
        await blocking.request_enforce(s, c, actor="ada", is_admin=True)
        assert blocking.state(c) == "enforce"


async def test_decline_lift_extend_and_expiry(app: App) -> None:
    now = datetime.now(UTC)
    async with app.sm() as s, s.begin():
        b = await blocking.create_block(s, FREE, actor="anna", clearance="TLP:RED")
        await blocking.request_enforce(s, b, actor="anna", is_admin=False)
        with pytest.raises(blocking.BlockError, match="only an admin or the requester"):
            await blocking.decline(s, b, actor="someone", is_admin=False)
        await blocking.decline(s, b, actor="ada", is_admin=True)
        assert blocking.state(b) == "monitor"
        before = b.expires_at
        await blocking.extend(s, b, actor="anna", days=10)
        assert b.expires_at - before == timedelta(days=10)
        await blocking.lift(s, b, actor="anna", note="false alarm")
        assert blocking.state(b) == "lifted"
        with pytest.raises(blocking.BlockError, match="has lifted"):
            await blocking.lift(s, b, actor="anna")
        # lifted: the value can be blocked again
        again = await blocking.create_block(s, FREE, actor="anna", clearance="TLP:RED")
        again.expires_at = now - timedelta(minutes=1)
        assert blocking.state(again, now) == "expired"
        assert await blocking.live_block(s, again.canonical_key) is None
        live, _ = await blocking.list_blocks(s, "TLP:RED", view="live")
        gone, _ = await blocking.list_blocks(s, "TLP:RED", view="expired")
        assert again not in live
        assert again in gone


# ── export ───────────────────────────────────────────────────────────────────


async def _enforced(s: object, value: str, tlp: str = "TLP:CLEAR") -> Block:
    b = await blocking.create_block(s, value, actor="anna", clearance="TLP:RED")  # type: ignore[arg-type]
    b.mode, b.approved_by, b.tlp = "enforce", "bob", tlp
    return b


async def test_export_formats(app: App) -> None:
    async with app.sm() as s, s.begin():
        await _enforced(s, FREE)
        await _enforced(s, "185.220.101.128/25")
        await _enforced(s, "evil-c2.top")
        await _enforced(s, "hxxps://bad-site.top/path?q='x'")
        await blocking.create_block(s, "185.199.110.1", actor="anna", clearance="TLP:RED")  # monitor only
        entries = await blocking.export_entries(s)
    assert blocking.render(entries, "ip.txt") == f"185.220.101.128/25\n{FREE}\n"  # ranges, then addresses
    assert blocking.render(entries, "domain.txt") == "evil-c2.top\n"
    assert blocking.render(entries, "url.txt") == "bad-site.top/path?q='x'\n"
    csv_text = blocking.render(entries, "blocks.csv")
    assert csv_text.splitlines()[0] == "value,kind,reason,score,tlp,blocked_at,expires_at,approved_by"
    assert len(csv_text.splitlines()) == 5
    doc = json.loads(blocking.render(entries, "blocks.json"))
    assert doc["count"] == 4
    bundle = json.loads(blocking.render(entries, "stix.json"))
    assert bundle["type"] == "bundle"
    patterns = {o["pattern"] for o in bundle["objects"]}
    assert f"[ipv4-addr:value = '{FREE}']" in patterns
    assert "[url:value = 'https://bad-site.top/path?q=\\'x\\'']" in patterns
    assert all(o["object_marking_refs"] == [blocking.STIX_TLP["TLP:CLEAR"]] for o in bundle["objects"])
    assert all(o["valid_until"] > o["valid_from"] for o in bundle["objects"])


async def test_export_respects_tlp_expiry_and_a_second_guard_check(app: App) -> None:
    async with app.sm() as s, s.begin():
        await _enforced(s, FREE, "TLP:AMBER")
        await _enforced(s, "185.220.101.35", "TLP:RED")
        old = await _enforced(s, "185.220.101.36")
        old.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await _enforced(s, "185.220.101.37")
        await _enforced(s, "185.220.101.38")
        # made ours after it was enforced: the export drops it (checked twice)
        s.add(
            AllowlistEntry(
                kind="cidr", value="185.220.101.38/32", effect="flag", reason="new office", origin="manual"
            )
        )
    async with app.sm() as s:
        values = [b.value for b in await blocking.export_entries(s)]
    assert values == [FREE, "185.220.101.37"]
    async with app.sm() as s, s.begin():
        await blocking.set_policy(s, {"export_max_tlp": "TLP:GREEN"}, actor="ada")
    async with app.sm() as s:
        assert [b.value for b in await blocking.export_entries(s)] == ["185.220.101.37"]


@pytest.mark.parametrize(
    ("change", "why"),
    [
        ({"known_bad_days": 0}, "between 1 and 365"),
        ({"suspect_days": 400}, "between 1 and 365"),
        ({"known_bad_score": 101}, "between 0 and 100"),
        ({"export_max_tlp": "TLP:RED"}, "never leaves"),
    ],
)
async def test_policy_is_validated(app: App, change: dict[str, object], why: str) -> None:
    async with app.sm() as s, s.begin():
        with pytest.raises(blocking.BlockError, match=why):
            await blocking.set_policy(s, change, actor="ada")


# ── the feed URL ─────────────────────────────────────────────────────────────


async def test_feed_url_needs_a_live_token_and_never_logs_it(
    app: App, caplog: pytest.LogCaptureFixture
) -> None:
    async with app.sm() as s, s.begin():
        await _enforced(s, FREE)
        row, token = await blocking.create_token(s, "hq-palo-alto", actor="ada")
        with pytest.raises(blocking.BlockError, match="already exists"):
            await blocking.create_token(s, "hq-palo-alto", actor="ada")
    caplog.set_level(logging.INFO)
    ok = await app.c.get(f"/feeds/{token}/ip.txt")
    assert ok.status_code == 200
    assert ok.text == f"{FREE}\n"
    assert ok.headers["cache-control"] == "no-store"
    assert (
        (await app.c.get(f"/feeds/{token}/stix.json"))
        .headers["content-type"]
        .startswith("application/stix+json")
    )
    for bad in (f"/feeds/{token}x/ip.txt", "/feeds/tlf_nope/ip.txt", f"/feeds/{token}/secrets.txt"):
        assert (await app.c.get(bad)).status_code == 404, bad
    ours = " ".join(r.getMessage() for r in caplog.records if r.name == "threatlens.api")
    assert token not in ours  # (the test client's own httpx log shows the URL; uvicorn's access log is off)
    assert "/feeds/<token>/ip.txt" in ours
    async with app.sm() as s, s.begin():
        await blocking.revoke_token(s, row.id, actor="ada")
    assert (await app.c.get(f"/feeds/{token}/ip.txt")).status_code == 404


# ── API and UI ───────────────────────────────────────────────────────────────


async def test_blocks_api(app: App) -> None:
    async with app.sm() as s, s.begin():
        _, admin = await create_key(s, "boss", "admin")
    r = await app.c.post("/api/v1/blocks", json={"value": FREE, "note": "ticket 7"}, headers=app.h("viewer"))
    assert r.status_code == 403
    r = await app.c.post("/api/v1/blocks", json={"value": FREE, "note": "ticket 7"}, headers=app.h("analyst"))
    assert r.status_code == 201
    bid = r.json()["id"]
    assert r.json()["state"] == "monitor"
    bad = await app.c.post("/api/v1/blocks", json={"value": "10.0.0.1"}, headers=app.h("analyst"))
    assert bad.status_code == 422
    assert "never blocked" in bad.json()["detail"]
    assert (await app.c.post(f"/api/v1/blocks/{bid}/request-enforce", headers=app.h("analyst"))).json()[
        "state"
    ] == "pending"
    r = await app.c.post(f"/api/v1/blocks/{bid}/approve", headers={"X-API-Key": admin})
    assert r.json()["state"] == "enforce"
    listed = await app.c.get("/api/v1/blocks?view=enforce", headers=app.h("viewer"))
    assert [b["value"] for b in listed.json()["items"]] == [FREE]
    assert (await app.c.post(f"/api/v1/blocks/{bid}/lift", json={}, headers=app.h("analyst"))).json()[
        "state"
    ] == "lifted"


async def test_blocklist_flow_through_argus(app: App) -> None:
    await _admins(app)
    await app.login("anna")
    made = await app.c.post("/api/v1/blocks", json={"value": FREE, "note": "from alert 9"}, headers=SAME)
    assert made.status_code == 201
    bid = made.json()["id"]
    private = await app.c.post("/api/v1/blocks", json={"value": "10.0.0.1"}, headers=SAME)
    assert private.status_code == 422
    assert "private or reserved" in private.json()["detail"]
    again = await app.c.post("/api/v1/blocks", json={"value": FREE}, headers=SAME)
    assert again.status_code == 422
    assert "already blocked" in again.json()["detail"]
    asked = await app.c.post(f"/api/v1/blocks/{bid}/request-enforce", headers=SAME)
    assert asked.json()["state"] == "pending"
    assert (await app.c.post(f"/api/v1/blocks/{bid}/approve", headers=SAME)).status_code == 403  # analyst
    await app.login("ada")
    approved = await app.c.post(f"/api/v1/blocks/{bid}/approve", headers=SAME)
    assert (approved.json()["state"], approved.json()["approved_by"]) == ("enforce", "ada")
    cross = await app.c.post(f"/api/v1/blocks/{bid}/lift", json={}, headers={"Sec-Fetch-Site": "cross-site"})
    assert cross.status_code == 403
    await app.login("vera")
    assert (
        await app.c.post("/api/v1/blocks", json={"value": "185.220.101.40"}, headers=SAME)
    ).status_code == 403


async def test_never_block_and_settings(app: App) -> None:
    await _admins(app)
    await app.login("anna")
    office = {"value": "185.220.101.0/24", "reason": "office egress"}
    assert (await app.c.post("/app/api/neverblock", json=office, headers=SAME)).status_code == 403
    assert (await app.c.get("/app/api/settings")).json()["canEdit"] is False
    assert (
        await app.c.post("/app/api/settings/tokens", json={"name": "fw"}, headers=SAME)
    ).status_code == 403
    await app.login("ada")
    assert (await app.c.post("/app/api/neverblock", json=office, headers=SAME)).json()["kind"] == "cidr"
    refused = await app.c.post("/api/v1/blocks", json={"value": "185.220.101.9"}, headers=SAME)
    assert refused.status_code == 422
    assert "office egress" in refused.json()["detail"]
    policy = (await app.c.get("/app/api/settings")).json()["policy"]
    bad = await app.c.put("/app/api/settings/policy", json=policy | {"known_bad_days": 0}, headers=SAME)
    assert bad.status_code == 422
    new = policy | {
        "known_bad_days": 14,
        "suspect_days": 3,
        "known_bad_score": 70,
        "export_max_tlp": "TLP:GREEN",
        "require_second_approver": False,
    }
    assert (await app.c.put("/app/api/settings/policy", json=new, headers=SAME)).status_code == 200
    async with app.sm() as s:
        p = await blocking.get_policy(s)
    assert (p["known_bad_days"], p["known_bad_score"], p["require_second_approver"]) == (14, 70, False)
    made = await app.c.post("/app/api/settings/tokens", json={"name": "hq-fw"}, headers=SAME)
    assert made.headers["cache-control"] == "no-store"
    token = made.json()["token"]
    assert token.startswith("tlf_")
    assert token not in (await app.c.get("/app/api/settings")).text  # shown once
    assert (await app.c.get(f"/feeds/{token}/ip.txt")).status_code == 200
