"""Background worker (arq on Redis).

* ``enqueue_due`` (every minute) queues one ``collect_source`` job per source
  whose next run time has passed. The job id is ``collect:<name>``, so a source
  is never queued twice, whether by the cron tick or an API trigger.
* ``collect_source`` runs one connector through the collection pipeline.
* ``refresh_allowlist`` (daily) refreshes Tranco, CDN ranges and the org
  profile entries, then re-evaluates every indicator.

Run with: ``arq threatlens.worker.WorkerSettings``
"""

from __future__ import annotations

import time
from contextlib import AsyncExitStack
from dataclasses import asdict
from typing import Any, ClassVar

from arq import cron
from arq.connections import RedisSettings
from arq.worker import func

from threatlens.jobs import open_collector, refresh_allowlists
from threatlens.logs import configure_logging, get_logger
from threatlens.settings import get_settings

log = get_logger("threatlens.worker")

HEARTBEAT_KEY = "threatlens:worker:heartbeat"
COLLECT_TIMEOUT_S = 15 * 60


async def heartbeat(ctx: dict[str, Any]) -> None:
    """Record that the worker is alive; the API can surface its age later."""
    await ctx["redis"].set(HEARTBEAT_KEY, str(int(time.time())), ex=600)


async def collect_source(ctx: dict[str, Any], name: str, force: bool = False) -> dict[str, Any]:
    summary = await ctx["collector"].run(name, force=force)
    return asdict(summary)


async def enqueue_due(ctx: dict[str, Any]) -> list[str]:
    queued = []
    for name in await ctx["collector"].due():
        if await ctx["redis"].enqueue_job("collect_source", name, False, _job_id=f"collect:{name}"):
            queued.append(name)
    if queued:
        log.info("worker.enqueued", sources=queued)
    return queued


async def refresh_allowlist(ctx: dict[str, Any]) -> dict[str, int | str]:
    return await refresh_allowlists(ctx["collector"])


async def startup(ctx: dict[str, Any]) -> None:
    s = get_settings()
    configure_logging(s.log_level, s.log_json)
    stack = AsyncExitStack()
    ctx["collector"] = await stack.enter_async_context(open_collector(s))
    ctx["stack"] = stack
    await heartbeat(ctx)
    log.info("worker.startup")


async def shutdown(ctx: dict[str, Any]) -> None:
    stack: AsyncExitStack | None = ctx.get("stack")
    if stack is not None:
        await stack.aclose()
    log.info("worker.shutdown")


class WorkerSettings:
    redis_settings = RedisSettings.from_dsn(get_settings().redis_url.get_secret_value())
    functions: ClassVar[list[Any]] = [
        heartbeat,
        # keep_result=0: a finished job must not block the next trigger of the
        # same source (arq refuses a job id while its result is still stored).
        func(collect_source, keep_result=0, timeout=COLLECT_TIMEOUT_S),
        func(refresh_allowlist, keep_result=0, timeout=COLLECT_TIMEOUT_S),
    ]
    cron_jobs: ClassVar[list[Any]] = [
        cron(heartbeat, minute=set(range(0, 60, 5))),
        cron(enqueue_due, second=10, unique=True),
        cron(refresh_allowlist, hour=3, minute=17, unique=True, timeout=COLLECT_TIMEOUT_S),
    ]
    on_startup = startup
    on_shutdown = shutdown
