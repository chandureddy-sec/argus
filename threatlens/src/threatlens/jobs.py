"""Collection jobs shared by the worker and the CLI.

Both paths build the same :class:`Collector` (one engine, one hardened HTTP
client, one raw store) so a source behaves identically whether a cron tick, an
API trigger or ``threatlens collect`` ran it.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

import httpx

from threatlens.allowlist import Entry, fetch_cloudflare, fetch_fastly, fetch_tranco, org_profile_entries
from threatlens.collect import Collector, RunSummary
from threatlens.db import make_engine, make_sessionmaker
from threatlens.logs import get_logger
from threatlens.net.guard import BlockedAddressError
from threatlens.net.http import FetchError, SafeHttp
from threatlens.profile import ProfileError, load_profile
from threatlens.rawstore import RawStore
from threatlens.settings import Settings

log = get_logger("threatlens.jobs")


@asynccontextmanager
async def open_collector(settings: Settings, http: SafeHttp | None = None) -> AsyncIterator[Collector]:
    """Yield a ready collector; ``http`` overrides the real client (tests)."""
    engine = make_engine(settings.database_url.get_secret_value())
    http = http or SafeHttp()
    try:
        c = Collector(make_sessionmaker(engine), http, RawStore(settings.data_dir), settings)
        await c.sync_sources()
        yield c
    finally:
        await http.aclose()
        await engine.dispose()


async def collect_due(c: Collector) -> list[RunSummary]:
    """Run every enabled source whose next run time has passed, one by one."""
    return [await c.run(name) for name in await c.due()]


AllowlistFetcher = Callable[[Collector], Awaitable[list[Entry]]]


def _profile_entries(settings: Settings) -> AllowlistFetcher:
    async def fetch(_: Collector) -> list[Entry]:
        org = load_profile(settings.profile_path).org
        return org_profile_entries(org.domains, org.ip_ranges)

    return fetch


def allowlist_fetchers(settings: Settings) -> dict[str, AllowlistFetcher]:
    async def tranco(c: Collector) -> list[Entry]:
        return await fetch_tranco(c.http, settings.tranco_top)

    async def cloudflare(c: Collector) -> list[Entry]:
        return await fetch_cloudflare(c.http)

    async def fastly(c: Collector) -> list[Entry]:
        return await fetch_fastly(c.http)

    return {
        "org_profile": _profile_entries(settings),
        "tranco": tranco,
        "cloudflare": cloudflare,
        "fastly": fastly,
    }


async def refresh_allowlists(
    c: Collector, fetchers: dict[str, AllowlistFetcher] | None = None
) -> dict[str, int | str]:
    """Refresh each automatic allowlist origin, then re-evaluate indicators.

    An origin that fails keeps its previous entries: a temporary outage of
    Tranco must not suddenly turn google.com into an active indicator.
    Returns entries per origin, or the error for origins that failed.
    """
    out: dict[str, int | str] = {}
    for origin, fetch in (fetchers or allowlist_fetchers(c.settings)).items():
        try:
            entries = await fetch(c)
        except (
            FetchError,
            BlockedAddressError,
            httpx.HTTPError,
            ProfileError,
            OSError,
            ValueError,
            KeyError,
        ) as e:
            out[origin] = f"{type(e).__name__}: {e}"[:300]
            log.warning("allowlist.refresh_failed", origin=origin, error=out[origin])
            continue
        if not entries and origin != "org_profile":
            # An empty answer from a public list is an upstream fault, not news.
            out[origin] = "empty response; kept previous entries"
            continue
        out[origin] = await c.replace_allowlist(origin, entries)
    changed = await c.reapply_allowlist()
    log.info("allowlist.refreshed", origins=out, indicators_changed=changed)
    return out
