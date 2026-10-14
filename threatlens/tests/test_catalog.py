"""Feed catalog (ADR 0012): custom feed parsing, validation and encrypted
keys; collection through the normal pipeline; switching, pulling and syncing
sources; removing a feed; and the pages and API that drive it."""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.test_collect import Clock, collector
from tests.test_enrich import KEYS, Upstream, http, seeded, upstream  # noqa: F401  # fixtures
from tests.uihelp import only_our_script
from threatlens import catalog, vault
from threatlens.api.app import create_app
from threatlens.auth import MemoryRateLimiter, create_key
from threatlens.connectors.base import SchemaDriftError
from threatlens.connectors.custom import FeedSpec, parse_spec
from threatlens.enrich.quota import MemoryQuotaStore
from threatlens.enrich.service import EnrichmentService
from threatlens.ioc.types import IOCType
from threatlens.models import AuditLog, CustomFeed, Indicator, Sighting, Source
from threatlens.models import Observable as ObsRow
from threatlens.net.http import SafeHttp
from threatlens.settings import Settings
from threatlens.users import create_user

SM = async_sessionmaker[AsyncSession]
SAME = {"Sec-Fetch-Site": "same-origin"}
SECRET = "feed-key-0123456789-do-not-leak"  # noqa: S105
TEST_KEY = "catalog-test-secret-0123456789"
SETTINGS = Settings(secret_key=TEST_KEY)  # type: ignore[arg-type]


def spec(fmt: str = "text", **kw: object) -> FeedSpec:
    return FeedSpec(name="custom_t", title="T", url="https://feeds.example/x", format=fmt, **kw)  # type: ignore[arg-type]


def values(s: FeedSpec, body: str) -> list[tuple[str, IOCType | None]]:
    return [(i.value, i.type) for i in parse_spec(s, body.encode())]


# ── reading feeds ────────────────────────────────────────────────────────────


def test_text_feed_skips_comments_and_takes_the_first_token() -> None:
    body = "# header\n\n185.220.101.34  # botnet\n45.155.205.233,443,c2\n; not a comment\nevil.example\n"
    got = values(spec(), body)
    assert [v for v, _ in got] == ["185.220.101.34", "45.155.205.233", "not", "evil.example"]
    assert all(t is None for _, t in got)  # "detect each value"


def test_csv_feed_sniffs_the_delimiter_and_reads_a_column() -> None:
    body = "id;ip;first_seen\n1;185.220.101.34;2026-10-01\n2;45.155.205.233;2026-10-02\n"
    assert [v for v, _ in values(spec("csv", value_column=1), body)] == [
        "ip",
        "185.220.101.34",
        "45.155.205.233",
    ]
    with pytest.raises(SchemaDriftError, match="column 9"):
        values(spec("csv", value_column=9), body)


def test_json_feed_walks_a_dotted_path() -> None:
    assert [v for v, _ in values(spec("json"), '["a.example", "b.example"]')] == ["a.example", "b.example"]
    body = '{"data": [{"host": {"ip": "185.220.101.34"}}, {"host": {"ip": "45.155.205.233"}}, {"x": 1}]}'
    assert [v for v, _ in values(spec("json", json_path="data.host.ip"), body)] == [
        "185.220.101.34",
        "45.155.205.233",
    ]
    with pytest.raises(SchemaDriftError, match="not JSON"):
        values(spec("json"), "<html>")
    with pytest.raises(SchemaDriftError, match=r"field 'data\.nope'"):
        values(spec("json", json_path="data.nope"), body)


def test_a_typed_feed_pins_the_type_so_other_kinds_are_rejected() -> None:
    got = values(
        spec(ioc_type="ip"), "185.220.101.34\n2a00:1450:4001:80b::200e\n45.155.205.0/24\nevil.example\n"
    )
    assert got == [
        ("185.220.101.34", IOCType.IPV4),
        ("2a00:1450:4001:80b::200e", IOCType.IPV6),
        ("45.155.205.0/24", IOCType.IPV4_NET),
        ("evil.example", IOCType.IPV4),  # checked as an IP, so rejected downstream with a reason
    ]


@pytest.mark.parametrize(
    ("change", "why"),
    [
        ({"url": "ftp://x.example/list"}, "http"),
        ({"url": "https://user:pw@x.example/list"}, "credentials"),
        ({"url": "http://10.0.0.5/list"}, "private"),
        ({"auth_header": "Cookie"}, "header name"),
        ({"secret": "k"}, "which header"),
        ({"interval_minutes": 5}, "15 minutes"),
        ({"json_path": "a..b"}, "JSON field"),
        ({"title": "x"}, "3 to 80"),
    ],
)
def test_validation(change: dict[str, object], why: str) -> None:
    f = catalog.FeedForm(title="Partner list", url="https://x.example/list.txt")
    for k, v in change.items():
        setattr(f, k, v)
    with pytest.raises(catalog.CatalogError, match=why):
        catalog.validate(f)


def test_vault_needs_a_secret_key_and_detects_a_changed_one() -> None:
    token = vault.seal(SETTINGS, SECRET)
    assert SECRET not in token
    assert vault.unseal(SETTINGS, token) == SECRET
    with pytest.raises(vault.VaultError, match="TL_SECRET_KEY"):
        vault.seal(Settings(secret_key=None), SECRET)
    other = Settings(secret_key="a-completely-different-key-42")  # type: ignore[arg-type]  # noqa: S106
    with pytest.raises(vault.VaultError, match="enter it again"):
        vault.unseal(other, token)


# ── collection through the normal pipeline ───────────────────────────────────


async def _add(sm: SM, **kw: object) -> str:
    f = catalog.FeedForm(title="Partner SOC bad IPs", url="https://feeds.example/bad.txt", ioc_type="ip")
    for k, v in kw.items():
        setattr(f, k, v)
    async with sm() as s, s.begin():
        src = await catalog.create(s, f, actor="ada", settings=SETTINGS)
        return src.name


def feed_server(body: str, seen: list[httpx.Request]) -> httpx.MockTransport:
    def handle(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, text=body, headers={"content-type": "text/plain"})

    return httpx.MockTransport(handle)


async def test_custom_feed_collects_like_a_builtin(sm: SM, tmp_path: Path) -> None:
    name = await _add(sm, secret=SECRET, auth_header="x-api-key", verdict="suspicious", confidence=90)
    assert name == "custom_partner_soc_bad_ips"
    seen: list[httpx.Request] = []
    http_ = SafeHttp(
        transport=feed_server("# list\n185.220.101.34\n45.155.205.233\nnot-an-ip\n10.0.0.1\n", seen)
    )
    c = collector(sm, http_, tmp_path, Clock(), secret_key=TEST_KEY)
    assert name in await c.due()  # the first pull is due at once
    run = await c.run(name)
    assert (run.status, run.items_total, run.items_new, run.items_rejected) == ("success", 4, 2, 2)
    assert seen[0].headers["x-api-key"] == SECRET
    async with sm() as s:
        src = await s.scalar(select(Source).where(Source.name == name))
        assert src is not None
        assert src.health == "ok"
        assert src.kind == "custom-suspicious"
        ind = await s.scalar(select(Indicator).join(ObsRow).where(ObsRow.value == "185.220.101.34"))
        assert ind is not None
        assert "custom-feed" in ind.labels
        # "suspicious" feeds add suspicion, never a malicious verdict on their own
        assert ind.score_breakdown is not None
        assert ind.score_breakdown["verdict"] == "suspicious"
        audit = (await s.scalars(select(AuditLog).where(AuditLog.action == "custom_feed.create"))).one()
        assert SECRET not in str(audit.details)
        assert audit.details["secret_set"] is True
        row = await s.scalar(select(CustomFeed))
        assert row is not None
        assert row.auth_secret
        assert SECRET not in row.auth_secret
    # a too-soon second pull is refused without fetching
    assert (await c.run(name)).status == "too_soon"
    assert len(seen) == 1


async def test_an_unreadable_key_skips_the_pull_with_the_reason(sm: SM, tmp_path: Path) -> None:
    name = await _add(sm, secret=SECRET, auth_header="Authorization")
    seen: list[httpx.Request] = []
    c = collector(sm, SafeHttp(transport=feed_server("185.220.101.34\n", seen)), tmp_path, Clock(),
                  secret_key="rotated-secret-key-0000000000")  # noqa: S106  # fmt: skip
    run = await c.run(name)
    assert run.status == "skipped"
    assert "enter it again" in (run.error or "")
    assert seen == []


async def test_bad_columns_are_reported_as_drift(sm: SM, tmp_path: Path) -> None:
    name = await _add(sm, format="csv", value_column=5)
    c = collector(sm, SafeHttp(transport=feed_server("a,b\n1,2\n", [])), tmp_path, Clock())
    run = await c.run(name)
    assert run.status == "failed"
    assert "column 5" in (run.error or "")
    async with sm() as s:
        src = await s.scalar(select(Source).where(Source.name == name))
        assert src is not None
        assert src.health == "failing"


async def test_removing_a_feed_revokes_only_what_it_alone_reported(seeded: SM, tmp_path: Path) -> None:  # noqa: F811
    name = await _add(seeded)
    body = "50.16.16.211\n185.220.101.34\n"  # the first is also on Feodo (seeded)
    c = collector(seeded, SafeHttp(transport=feed_server(body, [])), tmp_path, Clock())
    assert (await c.run(name)).status == "success"
    async with seeded() as s, s.begin():
        ids = await catalog.remove(s, name, actor="ada")
    assert len(ids) == 2
    async with seeded() as s:
        st = dict((await s.execute(select(ObsRow.value, Indicator.status).join(Indicator))).all())
        assert st["185.220.101.34"] == "revoked"
        assert st["50.16.16.211"] != "revoked"
        assert await s.scalar(select(Source).where(Source.name == name)) is None
        assert (await s.scalars(select(Sighting))).all()  # Feodo's stay
    with pytest.raises(catalog.CatalogError, match="built-in"):
        async with seeded() as s, s.begin():
            await catalog.remove(s, "feodo", actor="ada")


# ── pages and API ────────────────────────────────────────────────────────────


class Cat:
    def __init__(self, c: httpx.AsyncClient, sm: SM, keys: dict[str, str], queued: list[str]) -> None:
        self.c, self.sm, self.keys, self.queued = c, sm, keys, queued

    async def login(self, user: str) -> None:
        await self.c.post("/ui/logout", headers=SAME)
        r = await self.c.post(
            "/ui/login", data={"username": user, "password": user + "-password"}, headers=SAME
        )
        assert r.status_code == 303


@pytest.fixture
async def cat(seeded: SM, http: SafeHttp, upstream: Upstream) -> AsyncIterator[Cat]:  # noqa: F811
    keys = {}
    async with seeded() as s, s.begin():
        for name, role in (("admin", "admin"), ("analyst", "analyst"), ("viewer", "viewer")):
            _, keys[name] = await create_key(s, name, role)
        await create_user(s, "ada", "ada-password", "admin")
        await create_user(s, "vera", "vera-password", "viewer")
    settings = Settings(rate_limit_analyst=1000, rate_limit_viewer=1000, rate_limit_admin=1000,
                        secret_key=TEST_KEY, **KEYS)  # type: ignore[arg-type]  # fmt: skip
    queued: list[str] = []

    async def enqueue(name: str, force: bool) -> bool:
        if name in queued:
            return False  # like arq with a fixed job id
        queued.append(name)
        return True

    svc = EnrichmentService(seeded, http, MemoryQuotaStore(), settings, now=Clock())
    a = create_app(settings, checks={}, sessionmaker=seeded, limiter=MemoryRateLimiter(), enqueue=enqueue,
                   enrich=svc)  # fmt: skip
    async with (
        a.router.lifespan_context(a),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=a), base_url="http://test") as c,
    ):
        yield Cat(c, seeded, keys, queued)


FORM = {"title": "Partner SOC bad IPs", "url": "https://feeds.example/bad.txt", "format": "text",
        "ioc_type": "ip", "verdict": "malicious", "confidence": "80", "interval_minutes": "60",
        "tlp": "TLP:AMBER", "reliability": "B", "comment_char": "#", "value_column": "0", "json_path": "",
        "auth_header": "x-api-key", "secret": SECRET, "upstream": ""}  # fmt: skip


async def test_catalog_page_add_edit_toggle_pull_and_remove(cat: Cat) -> None:
    await cat.login("ada")
    r = await cat.c.get("/ui/sources")
    assert r.status_code == 200
    assert only_our_script(r.text)
    for text in ("Feed catalog", "Sync all feeds", "Add source", "Indicator feeds", "Knowledge sources",
                 "No feeds of your own yet", 'role="switch"'):  # fmt: skip
        assert text in r.text, text
    assert not re.search(r'\sstyle="', r.text)

    bad = await cat.c.post("/ui/sources/new", data=FORM | {"url": "http://192.168.1.5/x"}, headers=SAME)
    assert bad.status_code == 422
    assert "private" in bad.text
    assert SECRET not in bad.text
    r = await cat.c.post("/ui/sources/new", data=FORM, headers=SAME)
    assert r.status_code == 303
    assert r.headers["location"] == "/ui/sources/custom_partner_soc_bad_ips?done=added"
    page = await cat.c.get("/ui/sources/custom_partner_soc_bad_ips?done=added")
    assert page.status_code == 200
    for text in ("Feed added", "Edit this feed", "Remove this feed", "stored encrypted, sent in", "x-api-key",
                 "custom:feeds.example", "Never pulled yet"):  # fmt: skip
        assert text in page.text, text
    assert SECRET not in page.text  # the stored key never comes back

    # edit without a key keeps the stored one
    edit = FORM | {"secret": "", "confidence": "65", "upstream": "Abuse.ch"}
    r = await cat.c.post("/ui/sources/custom_partner_soc_bad_ips/edit", data=edit, headers=SAME)
    assert r.status_code == 303
    async with cat.sm() as s:
        found = await catalog.get_custom(s, "custom_partner_soc_bad_ips")
    assert found is not None
    src, feed = found
    assert (feed.confidence, src.upstream, src.tlp_default, src.reliability) == (
        65,
        "abuse-ch",
        "TLP:AMBER",
        "B",
    )
    assert feed.auth_secret
    assert vault.unseal(SETTINGS, feed.auth_secret) == SECRET

    r = await cat.c.post("/ui/sources/custom_partner_soc_bad_ips/pull", data={"next": "source"}, headers=SAME)
    assert r.headers["location"].endswith("?done=queued")
    assert cat.queued == ["custom_partner_soc_bad_ips"]
    r = await cat.c.post("/ui/sources/custom_partner_soc_bad_ips/pull", headers=SAME)
    assert r.headers["location"] == "/ui/sources?done=busy"

    r = await cat.c.post(
        "/ui/sources/custom_partner_soc_bad_ips/toggle", data={"enabled": "false"}, headers=SAME
    )
    assert r.headers["location"] == "/ui/sources?done=off"
    off = await cat.c.get("/ui/sources?show=off")
    assert "Partner SOC bad IPs" in off.text
    assert "Feodo" not in off.text
    assert (await cat.c.post("/ui/sources/custom_partner_soc_bad_ips/pull", headers=SAME)).status_code == 409

    r = await cat.c.post("/ui/sources/custom_partner_soc_bad_ips/delete", headers=SAME)
    assert r.headers["location"] == "/ui/sources?done=removed"
    assert (await cat.c.get("/ui/sources/custom_partner_soc_bad_ips")).status_code == 404
    async with cat.sm() as s:
        actions = [a for (a,) in (await s.execute(select(AuditLog.action).order_by(AuditLog.id))).all()]
    assert {"custom_feed.create", "custom_feed.update", "source.sync", "source.disable",
            "custom_feed.delete"} <= set(actions)  # fmt: skip


async def test_sync_all_queues_every_enabled_collectable_source(cat: Cat) -> None:
    await cat.login("ada")
    async with cat.sm() as s, s.begin():
        await catalog.set_enabled(s, "feodo", False, actor="ada")
    r = await cat.c.post("/ui/sources/sync", headers=SAME)
    assert r.headers["location"] == "/ui/sources?done=synced"
    assert "feodo" not in cat.queued
    assert cat.queued
    assert all(not n.startswith(("rdap", "ripestat")) for n in cat.queued)  # never enrichers


async def test_source_page_shows_history_and_contribution(cat: Cat) -> None:
    await cat.login("vera")
    r = await cat.c.get("/ui/sources/feodo")
    assert r.status_code == 200
    for text in ("Pull history", "Where it comes from", "Terms of use", "Top active indicators", "Indicators",
                 "Only here", "/ui/indicators?source=feodo"):  # fmt: skip
        assert text in r.text, text
    assert "Pull now" not in r.text
    assert 'role="switch"' not in r.text  # a viewer can't change anything
    assert "50[.]16[.]16[.]211" in r.text.replace('<span class="df">', "").replace("</span>", "")


async def test_only_admins_change_the_catalog(cat: Cat) -> None:
    await cat.login("vera")
    for path in ("/ui/sources/sync", "/ui/sources/feodo/toggle", "/ui/sources/feodo/pull", "/ui/sources/new"):
        r = await cat.c.post(path, data={"enabled": "false"} | FORM, headers=SAME)
        assert r.status_code == 403, path
    assert (await cat.c.get("/ui/sources/new")).status_code == 403
    await cat.login("ada")
    cross = {"Sec-Fetch-Site": "cross-site"}  # another site's page
    r = await cat.c.post("/ui/sources/feodo/toggle", data={"enabled": "false"}, headers=cross)
    assert r.status_code == 403
    assert cat.queued == []


async def test_switching_off_a_lookup_provider_applies_at_once(cat: Cat) -> None:
    await cat.login("ada")
    assert "Lookup providers" in (await cat.c.get("/ui/sources")).text  # listed before any lookup
    r = await cat.c.post("/ui/sources/ripestat/toggle", data={"enabled": "false"}, headers=SAME)
    assert r.status_code == 303
    body = (await cat.c.get("/api/v1/lookup/ipv4-addr/185.220.101.34?enrichers=ripestat",
                            headers={"X-API-Key": cat.keys["analyst"]})).json()  # fmt: skip
    e = next(x for x in body["enrichments"] if x["enricher"] == "ripestat")
    assert (e["status"], e["skipped_reason"]) == ("skipped", "disabled")


async def test_catalog_api(cat: Cat) -> None:
    h = {"X-API-Key": cat.keys["admin"]}
    payload = {"title": "Hash list", "url": "https://feeds.example/h.json", "format": "json",
               "ioc_type": "hash", "json_path": "items.sha256"}  # fmt: skip
    assert (await cat.c.post("/api/v1/sources/custom", json=payload,
                             headers={"X-API-Key": cat.keys["analyst"]})).status_code == 403  # fmt: skip
    r = await cat.c.post("/api/v1/sources/custom", json=payload, headers=h)
    assert r.status_code == 201
    assert r.json()["custom"] is True
    name = r.json()["name"]
    r = await cat.c.put(f"/api/v1/sources/custom/{name}", json=payload | {"verdict": "suspicious"}, headers=h)
    assert r.json()["kind"] == "custom-suspicious"
    r = await cat.c.patch(f"/api/v1/sources/{name}", json={"enabled": False}, headers=h)
    assert r.json()["enabled"] is False
    r = await cat.c.post("/api/v1/sources/sync", headers=h)
    assert r.status_code == 202
    assert name not in r.json()["sources"]
    assert (await cat.c.post(f"/api/v1/sources/{name}/run", headers=h)).status_code == 202
    c = (
        await cat.c.get("/api/v1/sources/feodo/contribution", headers={"X-API-Key": cat.keys["viewer"]})
    ).json()
    assert c["total"] >= 1
    assert "[.]" in c["top"][0]["value"]
    assert (await cat.c.delete(f"/api/v1/sources/custom/{name}", headers=h)).json()["removed"] == name
    assert (await cat.c.delete("/api/v1/sources/custom/feodo", headers=h)).status_code == 404
