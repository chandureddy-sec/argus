"""End-to-end checks against a real Postgres and Redis.

Run with the compose stack up:  ``make test-integration``
(or ``TL_INTEGRATION=1 uv run pytest -m integration``). Skipped otherwise.
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import AsyncIterator
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
    assert version == "0001"
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
