"""Collection pipeline against a real (SQLite) database and a mock transport."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.conftest import fixture_bytes
from threatlens.allowlist import Entry, org_profile_entries
from threatlens.collect import Collector, stix_pattern
from threatlens.ioc.types import IOCType, Observable
from threatlens.models import ConnectorRun, Indicator, RawDocument, Sighting, Source
from threatlens.models import Observable as ObsRow
from threatlens.net.http import SafeHttp
from threatlens.rawstore import RawStore
from threatlens.settings import Settings

SM = async_sessionmaker[AsyncSession]
MakeHttp = Callable[[Callable[[httpx.Request], httpx.Response]], SafeHttp]

FEEDS = {
    "known_exploited_vulnerabilities.json": "cisa_kev.json",
    "csv_recent": "urlhaus.csv",
    "ipblocklist.json": "feodo.json",
    "drop_v4.json": "spamhaus_drop.ndjson",
    "drop_v6.json": None,  # v6 lines are already in the combined fixture
    "torbulkexitlist": "tor_exits.txt",
    "feed.txt": "openphish.txt",
    "api/v1/": "threatfox.json",
}


class Clock:
    def __init__(self) -> None:
        self.t = datetime(2026, 10, 8, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.t

    def advance(self, **kw: float) -> None:
        self.t += timedelta(**kw)


def feed_handler(etag: str | None = None) -> Callable[[httpx.Request], httpx.Response]:
    def handle(req: httpx.Request) -> httpx.Response:
        for suffix, name in FEEDS.items():
            if req.url.path.rstrip("/").endswith(suffix.rstrip("/")):
                if etag and req.headers.get("if-none-match") == etag:
                    return httpx.Response(304)
                body = fixture_bytes(name) if name else b""
                return httpx.Response(200, content=body, headers={"ETag": etag} if etag else {})
        return httpx.Response(404)

    return handle


def collector(sm: SM, http: SafeHttp, tmp_path: Path, clock: Clock, **settings: object) -> Collector:
    return Collector(sm, http, RawStore(tmp_path / "data"), Settings(**settings), now=clock)  # type: ignore[arg-type]


async def count(sm: SM, model: type) -> int:
    async with sm() as s:
        return int(await s.scalar(select(func.count()).select_from(model)) or 0)


async def test_rerun_creates_zero_duplicates(sm: SM, mock_http: MakeHttp, tmp_path: Path) -> None:
    clock = Clock()
    c = collector(sm, mock_http(feed_handler()), tmp_path, clock)

    first = await c.run("cisa_kev")
    assert (first.status, first.items_total, first.items_new) == ("success", 3, 3)
    counts = [await count(sm, m) for m in (ObsRow, Indicator, Sighting, RawDocument)]
    assert counts == [3, 3, 3, 1]

    clock.advance(hours=7)
    second = await c.run("cisa_kev")  # identical payload
    assert second.status == "unchanged"

    clock.advance(hours=7)
    forced = await c.run("cisa_kev", force=True)  # full reprocess of the same data
    assert (forced.status, forced.items_new, forced.items_updated) == ("success", 0, 3)
    assert [await count(sm, m) for m in (ObsRow, Indicator, Sighting, RawDocument)] == counts

    async with sm() as s:
        sg = (await s.scalars(select(Sighting))).first()
        assert sg is not None
        assert sg.times_reported == 2
        runs = (await s.scalars(select(ConnectorRun.status).order_by(ConnectorRun.id))).all()
    assert runs == ["success", "unchanged", "success"]


async def test_same_ioc_from_two_sources_is_one_indicator(
    sm: SM, mock_http: MakeHttp, tmp_path: Path
) -> None:
    clock = Clock()
    c = collector(sm, mock_http(feed_handler()), tmp_path, clock, abusech_auth_key=SecretStr("k"))
    await c.run("urlhaus")  # has http://93.184.216.34:60557/bin.sh
    await c.run("threatfox")  # has 93.184.216.34 as an IP
    await c.run("openphish")  # has http://93.184.216.34/paypal/
    async with sm() as s:
        ip = await s.scalar(select(ObsRow).where(ObsRow.canonical_key == "ipv4-addr|93.184.216.34"))
        assert ip is not None
        assert ip.sightings_count == 1
        n = await s.scalar(
            select(func.count()).select_from(ObsRow).where(ObsRow.value.like("%93.184.216.34%"))
        )
    assert n == 3  # the IP and two distinct URLs — never merged across types


async def test_rejections_are_counted(sm: SM, mock_http: MakeHttp, tmp_path: Path) -> None:
    c = collector(sm, mock_http(feed_handler()), tmp_path, Clock())
    r = await c.run("urlhaus")
    assert r.items_total == 4
    assert r.items_rejected == 1  # http://10.0.0.5/ — private host
    assert any("non-public" in reason for reason in r.rejected_reasons)


async def test_allowlisted_domains_never_become_active(sm: SM, mock_http: MakeHttp, tmp_path: Path) -> None:
    c = collector(sm, mock_http(feed_handler()), tmp_path, Clock(), abusech_auth_key=SecretStr("k"))
    await c.sync_sources()
    await c.replace_allowlist("org_profile", org_profile_entries(["example.org"], []))
    await c.replace_allowlist(
        "tranco", [Entry("domain", "microsoft.com", "suppress", "Tranco top 10000 (#9)", "tranco")]
    )

    r = await c.run("threatfox")  # c2-panel.example.org is under our own domain
    assert r.items_allowlisted >= 1
    await c.run("urlhaus")  # https://login.microsoft.com/evil: a URL on a popular domain
    async with sm() as s:
        rows = {
            o.value: i
            for i, o in (
                await s.execute(select(Indicator, ObsRow).join(ObsRow, Indicator.observable_id == ObsRow.id))
            ).all()
        }
    own = rows["c2-panel.example.org"]
    assert own.status == "false_positive"
    assert "own domain" in (own.allowlist_reason or "")
    assert "own-asset" in own.labels
    stage = rows["https://payload.example.org/stage2.bin"]
    assert stage.status == "false_positive"  # own domains suppress URLs under them too
    popular = rows["https://login.microsoft.com/evil"]
    assert popular.status == "active"  # content on a popular host stays active…
    assert "popular-domain-host" in popular.labels  # …but is flagged


async def test_allowlist_changes_are_reapplied(sm: SM, mock_http: MakeHttp, tmp_path: Path) -> None:
    c = collector(sm, mock_http(feed_handler()), tmp_path, Clock())
    await c.run("feodo")
    async with sm() as s:
        ip_value = (await s.scalars(select(ObsRow.value))).first()
    assert ip_value

    await c.replace_allowlist(
        "manual", [Entry("cidr", f"{ip_value}/32", "suppress", "analyst: sinkhole", "manual")]
    )
    assert await c.reapply_allowlist() == 1
    async with sm() as s:
        ind = await s.scalar(select(Indicator).join(ObsRow).where(ObsRow.value == ip_value))
        assert ind is not None
        assert ind.status == "false_positive"

    await c.replace_allowlist("manual", [])
    assert await c.reapply_allowlist() == 1
    async with sm() as s:
        ind = await s.scalar(select(Indicator).join(ObsRow).where(ObsRow.value == ip_value))
        assert ind is not None
        assert ind.status == "active"
        assert ind.allowlist_reason is None


async def test_analyst_false_positive_is_not_overwritten(sm: SM, mock_http: MakeHttp, tmp_path: Path) -> None:
    clock = Clock()
    c = collector(sm, mock_http(feed_handler()), tmp_path, clock)
    await c.run("feodo")
    async with sm() as s, s.begin():
        ind = (await s.scalars(select(Indicator))).first()
        assert ind is not None
        ind.status = "false_positive"  # analyst decision: allowlist_reason stays NULL
    clock.advance(hours=1)
    await c.run("feodo", force=True)
    assert await c.reapply_allowlist() == 0
    async with sm() as s:
        statuses = (await s.scalars(select(Indicator.status))).all()
    assert "false_positive" in statuses


async def test_conditional_get_not_modified(sm: SM, mock_http: MakeHttp, tmp_path: Path) -> None:
    clock = Clock()
    c = collector(sm, mock_http(feed_handler(etag='"v1"')), tmp_path, clock)
    assert (await c.run("tor_exits")).status == "success"
    clock.advance(hours=1)
    r = await c.run("tor_exits")
    assert r.status == "not_modified"
    async with sm() as s:
        src = await s.scalar(select(Source).where(Source.name == "tor_exits"))
    assert src is not None
    assert src.health == "ok"
    assert src.checkpoint["etag"] == '"v1"'


async def test_missing_key_is_skipped_not_failed(sm: SM, mock_http: MakeHttp, tmp_path: Path) -> None:
    c = collector(sm, mock_http(feed_handler()), tmp_path, Clock())
    r = await c.run("otx")
    assert r.status == "skipped"
    assert "TL_OTX_API_KEY" in (r.error or "")
    async with sm() as s:
        src = await s.scalar(select(Source).where(Source.name == "otx"))
    assert src is not None
    assert src.health == "skipped"


async def test_failures_degrade_health_and_back_off(sm: SM, mock_http: MakeHttp, tmp_path: Path) -> None:
    clock = Clock()
    ok = True

    def handler(req: httpx.Request) -> httpx.Response:
        return feed_handler()(req) if ok else httpx.Response(503)

    c = collector(sm, mock_http(handler), tmp_path, clock)
    assert (await c.run("feodo")).status == "success"

    ok = False
    clock.advance(minutes=31)
    r = await c.run("feodo")
    assert r.status == "failed"
    assert r.http_status is None
    assert "503" in (r.error or "")
    async with sm() as s:
        src = await s.scalar(select(Source).where(Source.name == "feodo"))
    assert src is not None
    assert src.health == "degraded"  # succeeded recently
    assert src.consecutive_failures == 1
    assert src.next_run_at is not None
    assert src.next_run_at.replace(tzinfo=UTC) - clock() == timedelta(minutes=5)

    clock.advance(hours=3)  # long after the last success
    await c.run("feodo")
    async with sm() as s:
        src = await s.scalar(select(Source).where(Source.name == "feodo"))
    assert src is not None
    assert src.health == "failing"
    assert src.consecutive_failures == 2


async def test_schema_drift_marks_source_failing(sm: SM, mock_http: MakeHttp, tmp_path: Path) -> None:
    c = collector(
        sm, mock_http(lambda _: httpx.Response(200, content=b'{"unexpected": true}')), tmp_path, Clock()
    )
    r = await c.run("cisa_kev")
    assert r.status == "failed"
    assert "SchemaDriftError" in (r.error or "")
    async with sm() as s:
        src = await s.scalar(select(Source).where(Source.name == "cisa_kev"))
        doc = (await s.scalars(select(RawDocument))).first()
    assert src is not None
    assert src.health == "failing"
    assert doc is not None
    assert doc.parse_status == "failed"


async def test_source_rate_limit_is_respected(sm: SM, mock_http: MakeHttp, tmp_path: Path) -> None:
    clock = Clock()
    c = collector(sm, mock_http(feed_handler()), tmp_path, clock)
    await c.run("spamhaus_drop")
    clock.advance(hours=12)  # DROP asks for at most one fetch per day
    assert (await c.run("spamhaus_drop")).status == "too_soon"
    assert (await c.run("spamhaus_drop", force=True)).status == "success"  # explicit operator override
    clock.advance(hours=24, minutes=1)
    assert (await c.run("spamhaus_drop")).status == "unchanged"  # fetched again; same body


async def test_due_and_tlp(sm: SM, mock_http: MakeHttp, tmp_path: Path) -> None:
    clock = Clock()
    c = collector(sm, mock_http(feed_handler()), tmp_path, clock)
    await c.sync_sources()
    assert set(await c.due()) == set(c.registry)  # never run → all due
    await c.run("tor_exits")
    assert "tor_exits" not in await c.due()
    clock.advance(hours=2)
    assert "tor_exits" in await c.due()


def test_stix_patterns() -> None:
    assert stix_pattern(Observable(IOCType.DOMAIN, "evil.com")) == "[domain-name:value = 'evil.com']"
    assert stix_pattern(Observable(IOCType.SHA256, "ab" * 32)) == f"[file:hashes.'SHA-256' = '{'ab' * 32}']"
    assert stix_pattern(Observable(IOCType.URL, "http://x.com/a'b")) == "[url:value = 'http://x.com/a\\'b']"
    assert stix_pattern(Observable(IOCType.CVE, "CVE-2024-1")) is None


@pytest.mark.parametrize("name", ["cisa_kev", "urlhaus", "feodo", "spamhaus_drop", "tor_exits", "openphish"])
async def test_every_anonymous_connector_ingests(
    name: str, sm: SM, mock_http: MakeHttp, tmp_path: Path
) -> None:
    r = await collector(sm, mock_http(feed_handler()), tmp_path, Clock()).run(name)
    assert r.status == "success", r
    assert r.items_new > 0, r
