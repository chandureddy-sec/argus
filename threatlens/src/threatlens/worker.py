"""Background worker (arq on Redis).

Phase 0 only proves the worker starts, connects to Redis and runs a scheduled
job. Connectors (Phase 1) register their collection jobs here.

Run with: ``arq threatlens.worker.WorkerSettings``
"""

from __future__ import annotations

import time
from typing import Any, ClassVar

from arq import cron
from arq.connections import RedisSettings

from threatlens.logs import configure_logging, get_logger
from threatlens.settings import get_settings

log = get_logger("threatlens.worker")

HEARTBEAT_KEY = "threatlens:worker:heartbeat"


async def heartbeat(ctx: dict[str, Any]) -> None:
    """Record that the worker is alive; the API can surface its age later."""
    await ctx["redis"].set(HEARTBEAT_KEY, str(int(time.time())), ex=600)


async def startup(ctx: dict[str, Any]) -> None:
    s = get_settings()
    configure_logging(s.log_level, s.log_json)
    await heartbeat(ctx)
    log.info("worker.startup")


async def shutdown(ctx: dict[str, Any]) -> None:
    log.info("worker.shutdown")


class WorkerSettings:
    redis_settings = RedisSettings.from_dsn(get_settings().redis_url.get_secret_value())
    functions: ClassVar[list[Any]] = [heartbeat]
    cron_jobs: ClassVar[list[Any]] = [cron(heartbeat, minute=set(range(0, 60, 5)))]
    on_startup = startup
    on_shutdown = shutdown
