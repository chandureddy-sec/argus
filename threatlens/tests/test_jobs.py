"""Shared jobs (allowlist refresh, due collection), the worker functions and
the CLI commands built on them."""

from __future__ import annotations

import asyncio
import io
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import func, select

import threatlens.models
from tests.test_collect import Clock, collector, feed_handler
from threatlens import cli, worker
from threatlens.allowlist import Entry
from threatlens.collect import Collector
from threatlens.db import Base, make_engine
from threatlens.jobs import allowlist_fetchers, collect_due, open_collector, refresh_allowlists
from threatlens.models import AllowlistEntry, Indicator, Source
from threatlens.net.http import SafeHttp
from threatlens.settings import Settings

MakeHttp = Callable[[Callable[[httpx.Request], httpx.Response]], SafeHttp]


def tranco_zip(domains: list[str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("top-1m.csv", "".join(f"{i},{d}\n" for i, d in enumerate(domains, 1)))
    return buf.getvalue()


def allowlist_handler(fail: tuple[str, ...] = ()) -> Callable[[httpx.Request], httpx.Response]:
    def handle(req: httpx.Request) -> httpx.Response:
        host = req.url.host
        if any(f in host for f in fail):
            return httpx.Response(503)
        if host == "tranco-list.eu":
            return httpx.Response(200, content=tranco_zip(["google.com", "example.org", "github.com"]))
        if host == "www.cloudflare.com":
            body = "104.16.0.0/13\n" if req.url.path.endswith("v4") else "2606:4700::/32\n"
            return httpx.Response(200, text=body)
        if host == "api.fastly.com":
            return httpx.Response(200, json={"addresses": ["151.101.0.0/16"], "ipv6_addresses": []})
        return httpx.Response(404)

    return handle


def profile(tmp_path: Path) -> Path:
    p = tmp_path / "org.yaml"
    p.write_text(
        "org:\n  name: Acme\n  domains: [acme.com]\n  ip_ranges: [203.0.113.0/24]\n", encoding="utf-8"
    )
    return p


async def origins(c: Collector) -> dict[str, int]:
    async with c.sm() as s:
        rows = (
            await s.execute(select(AllowlistEntry.origin, func.count()).group_by(AllowlistEntry.origin))
        ).all()
    return {str(o): int(n) for o, n in rows}


# ── allowlist refresh ───────────────────────────────────────────────────────


async def test_refresh_all_origins(sm: Any, mock_http: MakeHttp, tmp_path: Path) -> None:
    c = collector(sm, mock_http(allowlist_handler()), tmp_path, Clock(), tranco_top=2)
    c.settings.profile_path = profile(tmp_path)
    out = await refresh_allowlists(c)
    assert out == {"org_profile": 2, "tranco": 2, "cloudflare": 2, "fastly": 1}
    assert await origins(c) == {"org_profile": 2, "tranco": 2, "cloudflare": 2, "fastly": 1}


async def test_failed_origin_keeps_previous_entries(sm: Any, mock_http: MakeHttp, tmp_path: Path) -> None:
    c = collector(sm, mock_http(allowlist_handler()), tmp_path, Clock(), tranco_top=3)
    c.settings.profile_path = profile(tmp_path)
    await refresh_allowlists(c)

    c.http = mock_http(allowlist_handler(fail=("tranco", "fastly")))
    out = await refresh_allowlists(c)
    assert isinstance(out["tranco"], str)
    assert "FetchError" in out["tranco"]
    assert await origins(c) == {"org_profile": 2, "tranco": 3, "cloudflare": 2, "fastly": 1}


async def test_empty_public_list_is_not_applied(sm: Any, mock_http: MakeHttp, tmp_path: Path) -> None:
    c = collector(sm, mock_http(allowlist_handler()), tmp_path, Clock())
    await c.replace_allowlist("tranco", [Entry("domain", "google.com", "suppress", "t", "tranco")])

    async def empty(_: Collector) -> list[Entry]:
        return []

    out = await refresh_allowlists(c, {"tranco": empty})
    assert out == {"tranco": "empty response; kept previous entries"}
    assert await origins(c) == {"tranco": 1}


async def test_broken_profile_is_reported(sm: Any, mock_http: MakeHttp, tmp_path: Path) -> None:
    c = collector(sm, mock_http(allowlist_handler()), tmp_path, Clock())
    c.settings.profile_path = tmp_path / "missing.yaml"
    out = await refresh_allowlists(c, {"org_profile": allowlist_fetchers(c.settings)["org_profile"]})
    assert isinstance(out["org_profile"], str)


async def test_refresh_reapplies_to_existing_indicators(sm: Any, mock_http: MakeHttp, tmp_path: Path) -> None:
    c = collector(sm, mock_http(feed_handler()), tmp_path, Clock())
    await c.run("feodo")
    async with sm() as s:
        ip = await s.scalar(
            select(threatlens.models.Observable.value).where(threatlens.models.Observable.type == "ipv4-addr")
        )
    assert ip

    async def mine(_: Collector) -> list[Entry]:
        return [Entry("cidr", f"{ip}/32", "suppress", "own IP range (org profile)", "org_profile")]

    await refresh_allowlists(c, {"org_profile": mine})
    async with sm() as s:
        reasons = (await s.scalars(select(Indicator.allowlist_reason))).all()
    assert any(r and "own" in r for r in reasons)


# ── due collection ──────────────────────────────────────────────────────────


async def test_collect_due_runs_only_due_sources(sm: Any, mock_http: MakeHttp, tmp_path: Path) -> None:
    clock = Clock()
    c = collector(sm, mock_http(feed_handler()), tmp_path, clock)
    await c.sync_sources()
    first = {r.source: r.status for r in await collect_due(c)}
    assert first["cisa_kev"] == "success"
    assert first["otx"] == "skipped"  # no key configured
    assert await collect_due(c) == []  # nothing due straight after
    clock.advance(hours=13)
    again = {r.source for r in await collect_due(c)}
    assert "tor_exits" in again
    assert "spamhaus_drop" not in again  # once a day at most
    clock.advance(hours=12)
    assert "spamhaus_drop" in {r.source for r in await collect_due(c)}


# ── worker ──────────────────────────────────────────────────────────────────


class FakeArqRedis:
    def __init__(self) -> None:
        self.jobs: list[tuple[str, tuple[Any, ...], str]] = []
        self.store: dict[str, tuple[str, int | None]] = {}

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        self.store[key] = (value, ex)

    async def enqueue_job(self, fn: str, *args: Any, _job_id: str) -> object | None:
        if any(j[2] == _job_id for j in self.jobs):
            return None  # arq refuses a duplicate job id
        self.jobs.append((fn, args, _job_id))
        return object()


async def test_worker_enqueue_and_collect(sm: Any, mock_http: MakeHttp, tmp_path: Path) -> None:
    c = collector(sm, mock_http(feed_handler()), tmp_path, Clock())
    await c.sync_sources()
    r = FakeArqRedis()
    ctx: dict[str, Any] = {"redis": r, "collector": c}
    queued = await worker.enqueue_due(ctx)
    assert "cisa_kev" in queued
    assert ("collect_source", ("cisa_kev", False), "collect:cisa_kev") in r.jobs
    assert await worker.enqueue_due(ctx) == []  # already queued

    result = await worker.collect_source(ctx, "cisa_kev")
    assert result["status"] == "success"
    assert result["items_new"] == 3


async def test_worker_startup_builds_collector(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, engine: Any
) -> None:
    url = str(engine.url)
    monkeypatch.setattr(
        worker,
        "get_settings",
        lambda: Settings(database_url=url, data_dir=tmp_path / "d"),  # type: ignore[arg-type]
    )
    r = FakeArqRedis()
    ctx: dict[str, Any] = {"redis": r}
    await worker.startup(ctx)
    try:
        assert isinstance(ctx["collector"], Collector)
        async with ctx["collector"].sm() as s:
            assert await s.scalar(select(func.count()).select_from(Source)) == 8
        assert worker.HEARTBEAT_KEY in r.store
    finally:
        await worker.shutdown(ctx)


# ── CLI ─────────────────────────────────────────────────────────────────────


@pytest.fixture
def cli_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Settings:
    url = f"sqlite+aiosqlite:///{(tmp_path / 'cli.db').as_posix()}"

    async def create() -> None:
        e = make_engine(url)
        async with e.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        await e.dispose()

    asyncio.run(create())
    settings = Settings(database_url=url, data_dir=tmp_path / "data", profile_path=profile(tmp_path))  # type: ignore[arg-type]
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    return settings


def use_http(monkeypatch: pytest.MonkeyPatch, handler: Callable[[httpx.Request], httpx.Response]) -> None:
    def opener(settings: Settings) -> Any:
        return open_collector(settings, http=SafeHttp(transport=httpx.MockTransport(handler), retries=0))

    monkeypatch.setattr(cli, "open_collector", opener)


def test_cli_keys(cli_db: Settings, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["keys", "create", "soc", "--role", "analyst", "--expires-days", "30"]) == 0
    out = capsys.readouterr()
    assert out.out.startswith("tl_")
    assert "not shown again" in out.err
    assert cli.main(["keys", "create", "soc"]) == 2
    assert cli.main(["keys", "list"]) == 0
    listing = capsys.readouterr().out
    assert "soc" in listing
    assert "analyst" in listing
    assert "expires" in listing
    assert out.out.strip() not in listing  # the key itself is never listed
    assert cli.main(["keys", "revoke", "soc"]) == 0
    assert cli.main(["keys", "revoke", "soc"]) == 2
    with pytest.raises(SystemExit):
        cli.main(["keys", "create"])


def test_cli_collect_and_sources(
    cli_db: Settings, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    use_http(monkeypatch, feed_handler())
    assert cli.main(["collect", "cisa_kev", "feodo"]) == 0
    out = capsys.readouterr().out
    assert "cisa_kev" in out
    assert "success" in out

    assert cli.main(["collect", "nope"]) == 2
    assert cli.main(["collect"]) == 2
    assert cli.main(["collect", "--due"]) == 0  # the rest are due; otx/threatfox skip without keys

    assert cli.main(["sources", "disable", "tor_exits"]) == 0
    capsys.readouterr()
    assert cli.main(["sources"]) == 0
    listing = capsys.readouterr().out
    tor = next(line for line in listing.splitlines() if line.startswith("tor_exits"))
    assert " n " in tor
    assert "(non-commercial)" in next(line for line in listing.splitlines() if line.startswith("openphish"))
    assert cli.main(["sources", "enable", "nope"]) == 2


def test_cli_collect_failure_exit_code(cli_db: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    use_http(monkeypatch, lambda _: httpx.Response(500))
    assert cli.main(["collect", "feodo"]) == 1


def test_cli_allowlist_refresh(
    cli_db: Settings, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    use_http(monkeypatch, allowlist_handler())
    assert cli.main(["allowlist-refresh"]) == 0
    out = capsys.readouterr().out
    assert "org_profile  2 entries" in out
    use_http(monkeypatch, allowlist_handler(fail=("fastly",)))
    assert cli.main(["allowlist-refresh"]) == 1


def test_cli_extract(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = tmp_path / "report.txt"
    f.write_text("beacon to evil-c2[.]net from 10.1.2.3 and 45.9.148.3", encoding="utf-8")
    assert cli.main(["extract", str(f), "--defang", "--rejected"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert "domain-name\tevil-c2[.]net" in lines
    assert "ipv4-addr\t45[.]9[.]148[.]3" in lines
    assert any(line.startswith("rejected\t10.1.2.3") for line in lines)


def test_cli_init_db(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    url = f"sqlite+aiosqlite:///{(tmp_path / 'new.db').as_posix()}"
    monkeypatch.setattr(cli, "get_settings", lambda: Settings(database_url=url))  # type: ignore[arg-type]
    assert cli.main(["init-db"]) == 0
    assert cli.main(["init-db"]) == 0  # idempotent
    assert cli.main(["keys", "list"]) == 0
    monkeypatch.setattr(cli, "get_settings", lambda: Settings())
    assert cli.main(["init-db"]) == 2  # Postgres is migrated with Alembic
