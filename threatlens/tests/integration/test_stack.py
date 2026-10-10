"""End-to-end checks against a real Postgres and Redis.

Run with the compose stack up:  ``make test-integration``
(or ``TL_INTEGRATION=1 uv run pytest -m integration``). Skipped otherwise.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import uuid
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from threatlens.api.app import create_app
from threatlens.db import make_engine
from threatlens.settings import get_settings

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("TL_INTEGRATION") != "1", reason="set TL_INTEGRATION=1 with the stack up"
    ),
]

ROOT = Path(__file__).resolve().parents[2]


def _env_from_dotenv() -> None:
    """With the compose stack up, point at its published ports using the
    password from .env, so `make test-integration` needs no extra setup."""
    if "TL_DATABASE_URL" in os.environ or not (ROOT / ".env").exists():
        return
    for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
        if line.startswith("POSTGRES_PASSWORD="):
            pw = line.split("=", 1)[1].strip()
            os.environ["TL_DATABASE_URL"] = f"postgresql+asyncpg://threatlens:{pw}@127.0.0.1:5432/threatlens"
            os.environ.setdefault("TL_REDIS_URL", "redis://127.0.0.1:6379/0")
            get_settings.cache_clear()


_env_from_dotenv()


def _head() -> str:
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    head = ScriptDirectory.from_config(Config(str(ROOT / "alembic.ini"))).get_current_head()
    assert head is not None
    return head


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    e = make_engine(get_settings().database_url.get_secret_value())
    yield e
    await e.dispose()


def test_migrations_apply_and_are_idempotent() -> None:
    for _ in range(2):  # a second upgrade must be a no-op
        subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=ROOT, check=True)


async def test_baseline_schema(engine: AsyncEngine) -> None:
    async with engine.connect() as conn:
        version = (await conn.execute(text("SELECT version_num FROM alembic_version"))).scalar_one()
        baseline = (
            await conn.execute(text("SELECT value FROM app_meta WHERE key = 'schema_baseline'"))
        ).scalar_one()
        exts = set((await conn.execute(text("SELECT extname FROM pg_extension"))).scalars())
    assert version == _head()
    assert baseline == "0001"
    assert {"pg_trgm", "citext"} <= exts


async def test_redis_roundtrip() -> None:
    r: Redis = Redis.from_url(get_settings().redis_url.get_secret_value())
    try:
        await r.set("threatlens:test", "1", ex=10)
        assert await r.get("threatlens:test") == b"1"
    finally:
        await r.aclose()


def test_readyz_against_real_dependencies() -> None:
    with TestClient(create_app()) as c:
        r = c.get("/readyz")
    assert r.status_code == 200, r.text
    assert r.json()["checks"]["postgres"]["ok"]
    assert r.json()["checks"]["redis"]["ok"]


def test_models_match_migrations() -> None:
    """`alembic check` compares the migrated schema with the models (types included)."""
    subprocess.run([sys.executable, "-m", "alembic", "check"], cwd=ROOT, check=True)


@pytest.fixture
def scratch_db() -> Iterator[str]:
    """A throwaway database, migrated to head, for pipeline tests on real Postgres."""
    base = get_settings().database_url.get_secret_value()
    name = f"tl_it_{uuid.uuid4().hex[:10]}"

    async def ddl(sql: str) -> None:
        e = make_engine(base)
        async with e.connect() as conn:
            await conn.execution_options(isolation_level="AUTOCOMMIT")
            await conn.execute(text(sql))
        await e.dispose()

    asyncio.run(ddl(f"CREATE DATABASE {name}"))
    url = base.rsplit("/", 1)[0] + f"/{name}"
    env = {**os.environ, "TL_DATABASE_URL": url}
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=ROOT, check=True, env=env)
    try:
        yield url
    finally:
        asyncio.run(ddl(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)"))


async def test_pipeline_and_graph_on_postgres(scratch_db: str, tmp_path: Path) -> None:
    """Phases 1-2 end to end on Postgres (JSONB, ON CONFLICT), with recorded fixtures."""
    import httpx

    from tests.kb_helpers import KbUpstream, combined
    from tests.test_collect import Clock, feed_handler
    from threatlens.collect import Collector
    from threatlens.db import make_sessionmaker
    from threatlens.kb import graph
    from threatlens.net.http import SafeHttp
    from threatlens.rawstore import RawStore
    from threatlens.settings import Settings

    async def no_sleep(_: float) -> None:
        return None

    engine = make_engine(scratch_db)
    sm = make_sessionmaker(engine)
    http = SafeHttp(
        transport=httpx.MockTransport(combined(feed_handler(), KbUpstream(attack_versions=["19.2"]))),
        sleep=no_sleep,
        retries=0,
    )
    c = Collector(sm, http, RawStore(tmp_path), Settings(), now=Clock(), sleep=no_sleep)
    try:
        for name in ("feodo", "mitre_attack", "cisa_kev", "nvd", "epss", "osv"):
            r = await c.run(name)
            assert r.status == "success", (name, r.error)
        again = await c.run("feodo", force=True)
        assert again.items_new == 0
        async with sm() as s:
            feodo = json.loads((ROOT / "tests" / "fixtures" / "feodo.json").read_text())
            emotet_ip = next(d["ip_address"] for d in feodo if d.get("malware") == "Emotet")
            ip = await graph.resolve(s, emotet_ip)
            t = await graph.resolve(s, "T1047")
            assert ip is not None
            assert t is not None
            res = await graph.paths(s, ip.ref, t.ref)
        assert res.length == 2
        assert [e["source"] for e in res.paths[0]] == ["feodo", "mitre_attack"]
    finally:
        await http.aclose()
        await engine.dispose()


async def test_redis_quota_store() -> None:
    """The quota book shared by API and worker: windows, refusals that cost
    nothing, provider blocks, usage."""
    from threatlens.enrich.base import Quota
    from threatlens.enrich.quota import RedisQuotaStore

    r: Redis = Redis.from_url(get_settings().redis_url.get_secret_value())
    name = f"it_{uuid.uuid4().hex[:8]}"
    q = RedisQuotaStore(r)
    quotas = (Quota(2, 60), Quota(5, 86400))
    try:
        assert [await q.take(name, quotas) for _ in range(2)] == [0.0, 0.0]
        assert 0 < await q.take(name, quotas) <= 60
        assert await q.usage(name, quotas) == {"2/minute": 2, "5/day": 2}  # the refusal cost nothing
        await q.block(name + "b", 5)
        assert 0 < await q.take(name + "b", ()) <= 5
    finally:
        keys = [k async for k in r.scan_iter(match=f"{RedisQuotaStore.PREFIX}{name}*")]
        if keys:
            await r.delete(*keys)
        await r.aclose()


async def test_enrichment_on_postgres(scratch_db: str, tmp_path: Path) -> None:
    """Phase 3 on Postgres: lookup, JSONB summaries, provenance rows, cache hit."""
    import httpx

    from tests.test_collect import Clock, feed_handler
    from tests.test_enrich import FEODO_IP, Upstream
    from threatlens.collect import Collector
    from threatlens.db import make_sessionmaker
    from threatlens.enrich.quota import MemoryQuotaStore
    from threatlens.enrich.service import EnrichmentService
    from threatlens.ioc.types import IOCType, Observable
    from threatlens.models import Enrichment
    from threatlens.net.http import SafeHttp
    from threatlens.rawstore import RawStore
    from threatlens.settings import Settings

    async def no_sleep(_: float) -> None:
        return None

    e = make_engine(scratch_db)
    sm = make_sessionmaker(e)
    try:
        feeds = SafeHttp(transport=httpx.MockTransport(feed_handler()), sleep=no_sleep)
        await Collector(sm, feeds, RawStore(tmp_path), Settings(), now=Clock()).run("feodo")
        http = SafeHttp(transport=httpx.MockTransport(Upstream()), sleep=no_sleep, retries=0)
        svc = EnrichmentService(sm, http, MemoryQuotaStore(), Settings())
        ip = Observable(IOCType.IPV4, FEODO_IP)
        first = await svc.lookup(ip, actor="it")
        assert first["verdict"] == "malicious"
        again = await svc.lookup(ip, actor="it")
        assert {r["status"] for r in again["enrichments"] if r["enricher"] == "ripestat"} == {"cached"}
        assert again["took_ms"] < 2000
        async with sm() as s:
            country = await s.scalar(
                text("SELECT summary->>'country' FROM enrichments WHERE enricher = 'ripestat'")
            )
            rows = (await s.execute(text("SELECT count(*) FROM enrichments"))).scalar_one()
        assert country == "US"
        assert rows == 4
        assert Enrichment.__tablename__ == "enrichments"
        await svc.enrich_backlog(10)
    finally:
        await e.dispose()
