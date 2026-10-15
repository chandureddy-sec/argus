from __future__ import annotations

import os
from collections.abc import AsyncIterator, Callable
from pathlib import Path

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

import threatlens.models  # noqa: F401 - register tables
from threatlens.db import Base, make_engine, make_sessionmaker
from threatlens.net.http import SafeHttp

FIXTURES = Path(__file__).parent / "fixtures"

# Tests run against the synthetic "Example Corp" profile; the shipped config/ is
# the real (initially blank) one. Set before any Settings is built.
os.environ.setdefault("TL_PROFILE_PATH", str(FIXTURES / "example_org_profile.yaml"))
os.environ.setdefault("TL_PIRS_PATH", str(FIXTURES / "example_pirs.yaml"))


def fixture_bytes(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    e = make_engine(f"sqlite+aiosqlite:///{(tmp_path / 'tl.db').as_posix()}")
    async with e.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield e
    await e.dispose()


@pytest.fixture
def sm(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return make_sessionmaker(engine)


async def _no_sleep(_: float) -> None:
    return None


@pytest.fixture
def mock_http() -> Callable[[Callable[[httpx.Request], httpx.Response]], SafeHttp]:
    """Build a SafeHttp whose transport is a handler function (no network)."""

    def make(handler: Callable[[httpx.Request], httpx.Response]) -> SafeHttp:
        return SafeHttp(transport=httpx.MockTransport(handler), sleep=_no_sleep, retries=2)

    return make
