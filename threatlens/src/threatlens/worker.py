"""Background worker (arq on Redis).

* ``enqueue_due`` (every minute) queues one ``collect_source`` job per source
  whose next run time has passed. The job id is ``collect:<name>``, so a source
  is never queued twice, whether by the cron tick or an API trigger.
* ``collect_source`` runs one connector through the collection pipeline.
* ``refresh_allowlist`` (daily) refreshes Tranco, CDN ranges and the org
  profile entries, then re-evaluates every indicator.
* ``enrich_backlog`` (every 30 minutes) enriches new active IP indicators
  with the free passive enrichers (ASN, location); TL_ENRICH_AUTO_PER_RUN=0
  turns it off.
* ``daily_scoring`` (daily) re-derives source weights from analyst feedback,
  recomputes patch priorities, and re-scores every indicator: decay and
  expiry (ADR 0008). Collection runs score what they touched as they go.
* ``build_products`` (daily, 06:05 UTC) generates the daily brief and the
  vulnerability priority list, and on Mondays (or the first run after) the
  weekly CTI report and the executive one-pager (ADR 0021).
* ``scan_lookalikes`` (daily) looks for domains imitating ours in CT logs and
  our feeds (ADR 0021).

Run with: ``arq threatlens.worker.WorkerSettings``
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from contextlib import AsyncExitStack
from dataclasses import asdict
from typing import Any, ClassVar

from arq import cron
from arq.connections import RedisSettings
from arq.worker import func

from threatlens.enrich.quota import RedisQuotaStore
from threatlens.enrich.service import EnrichmentService, enrichment_http
from threatlens.jobs import daily_scoring as run_daily_scoring
from threatlens.jobs import open_collector, refresh_allowlists
from threatlens.logs import configure_logging, get_logger
from threatlens.recon import Engine, EngineError, import_new_reports
from threatlens.scoring.store import rescore
from threatlens.settings import get_settings

log = get_logger("threatlens.worker")

HEARTBEAT_KEY = "threatlens:worker:heartbeat"
HEARTBEAT_TTL_S = 600
# A long paced job keeps the heartbeat fresh through its pacing sleeps, so the
# 5-min heartbeat cron being starved for the length of the run doesn't flip the
# worker unhealthy. The NVD sync can pace for ~15 min (6.5 s between requests
# without a key); the cron's TTL is only 600 s. Throttled so a fast loop of
# short sleeps doesn't write to Redis on every tick.
HEARTBEAT_REFRESH_EVERY_S = 60
COLLECT_TIMEOUT_S = 15 * 60


async def _beat(redis: Any) -> None:
    await redis.set(HEARTBEAT_KEY, str(int(time.time())), ex=HEARTBEAT_TTL_S)


async def heartbeat(ctx: dict[str, Any]) -> None:
    """Record that the worker is alive; the API can surface its age later."""
    await _beat(ctx["redis"])


def heartbeat_sleep(ctx: dict[str, Any]) -> Callable[[float], Awaitable[None]]:
    """A pacing sleep that also refreshes the heartbeat.

    Collectors pace their requests through this callable, so wiring it to the
    heartbeat means a long run (the NVD sync, above all) stays healthy even
    while the heartbeat cron gets no turn. The refresh is throttled to
    ``HEARTBEAT_REFRESH_EVERY_S`` and a Redis hiccup is logged, never raised:
    a liveness refresh must not fail the job it is riding on.
    """

    async def sleep(delay: float) -> None:
        await asyncio.sleep(delay)
        now = time.time()
        if now - ctx.get("last_beat", 0.0) >= HEARTBEAT_REFRESH_EVERY_S:
            ctx["last_beat"] = now
            try:
                await _beat(ctx["redis"])
            except Exception as e:  # liveness refresh is best-effort
                log.warning("worker.heartbeat_refresh_failed", error=str(e)[:200])

    return sleep


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


async def enrich_backlog(ctx: dict[str, Any]) -> dict[str, int]:
    service: EnrichmentService = ctx["enrich"]
    return await service.enrich_backlog(service.settings.enrich_auto_per_run)


async def import_recon_reports(ctx: dict[str, Any]) -> dict[str, int]:
    """Scheduled ReconX monitor runs save reports on their own: import them as assets."""
    engine: Engine | None = ctx.get("recon")
    if engine is None:
        return {"seen": 0, "imported": 0, "failed": 0}
    try:
        out = await import_new_reports(ctx["collector"].sm, engine)
    except EngineError as e:
        log.warning("worker.recon_unreachable", error=str(e)[:200])
        return {"seen": 0, "imported": 0, "failed": 0}
    if out["imported"]:
        await rescore(ctx["collector"].sm, ctx["collector"].settings)
    return out


async def daily_scoring(ctx: dict[str, Any]) -> dict[str, Any]:
    collector = ctx["collector"]
    return await run_daily_scoring(collector.sm, collector.settings)


async def push_integrations(ctx: dict[str, Any]) -> dict[str, Any]:
    """Push shareable indicators to every integration whose interval has passed (ADR 0019)."""
    from threatlens.share import integrations

    collector = ctx["collector"]
    out: dict[str, Any] = {}
    for ident in await integrations.due(collector.sm):
        try:
            res = await integrations.push(collector.sm, collector.settings, ident)
        except integrations.IntegrationError as e:
            res = {"status": "failed", "error": str(e)}
        out[str(ident)] = {"status": res.get("status"), "sent": res.get("sent", 0)}
    if out:
        log.info("integrations.pushed", runs=out)
    return out


async def evaluate_alerts(ctx: dict[str, Any]) -> dict[str, int]:
    """Raise and deliver alerts for every enabled rule (deduplicated, rate-limited)."""
    from threatlens.share import alerts

    collector = ctx["collector"]
    res = await alerts.evaluate(collector.sm, collector.settings)
    if res["raised"]:
        log.info("alerts.evaluated", **res)
    return res


async def build_retro_hunts(ctx: dict[str, Any]) -> dict[str, Any]:
    """Query packs for new high-priority indicators, to run over historical logs (ADR 0020)."""
    from threatlens.detect import retro

    collector = ctx["collector"]
    pack = await retro.build(collector.sm, collector.settings)
    if pack is not None:
        log.info("retrohunt.pack", id=pack)
    return {"pack": pack}


async def build_products(ctx: dict[str, Any]) -> dict[str, Any]:
    from datetime import UTC, datetime

    from threatlens.products import store

    collector = ctx["collector"]
    now = datetime.now(UTC)
    out: dict[str, Any] = {}
    for kind in await store.due(collector.sm, now):
        row = await store.generate(collector.sm, collector.settings, kind, now)
        out[kind] = row.id
    if out:
        log.info("products.built", products=out)
    return out


async def scan_lookalikes(ctx: dict[str, Any]) -> dict[str, Any]:
    from threatlens import lookalike
    from threatlens.net.http import SafeHttp

    collector = ctx["collector"]
    domains, ours = lookalike.org_domains(collector.settings)
    if not domains:
        return {"domains": [], "candidates": 0, "new": 0, "errors": []}
    async with SafeHttp(timeout=90.0, retries=1) as http:
        res = await lookalike.scan(collector.sm, http, domains, ours, use_ct=collector.settings.lookalike_ct)
    log.info("lookalikes.scanned", **{k: v for k, v in res.items() if k != "domains"})
    return res


async def startup(ctx: dict[str, Any]) -> None:
    s = get_settings()
    configure_logging(s.log_level, s.log_json)
    stack = AsyncExitStack()
    ctx["last_beat"] = time.time()
    ctx["collector"] = await stack.enter_async_context(open_collector(s, sleep=heartbeat_sleep(ctx)))
    http = await stack.enter_async_context(enrichment_http(s))
    ctx["enrich"] = EnrichmentService(ctx["collector"].sm, http, RedisQuotaStore(ctx["redis"]), s)
    ctx["recon"] = Engine(s.reconx_url) if s.reconx_url else None
    if ctx["recon"] is not None:
        stack.push_async_callback(ctx["recon"].aclose)
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
        func(enrich_backlog, keep_result=0, timeout=COLLECT_TIMEOUT_S),
        func(daily_scoring, keep_result=0, timeout=COLLECT_TIMEOUT_S),
        func(import_recon_reports, keep_result=0, timeout=COLLECT_TIMEOUT_S),
        func(push_integrations, keep_result=0, timeout=COLLECT_TIMEOUT_S),
        func(evaluate_alerts, keep_result=0, timeout=COLLECT_TIMEOUT_S),
        func(build_retro_hunts, keep_result=0, timeout=COLLECT_TIMEOUT_S),
        func(build_products, keep_result=0, timeout=COLLECT_TIMEOUT_S),
        func(scan_lookalikes, keep_result=0, timeout=COLLECT_TIMEOUT_S),
    ]
    cron_jobs: ClassVar[list[Any]] = [
        cron(heartbeat, minute=set(range(0, 60, 5))),
        cron(enqueue_due, second=10, unique=True),
        cron(refresh_allowlist, hour=3, minute=17, unique=True, timeout=COLLECT_TIMEOUT_S),
        cron(enrich_backlog, minute={7, 37}, unique=True, timeout=COLLECT_TIMEOUT_S),
        cron(daily_scoring, hour=2, minute=47, unique=True, timeout=COLLECT_TIMEOUT_S),
        cron(import_recon_reports, minute=set(range(3, 60, 10)), unique=True, timeout=COLLECT_TIMEOUT_S),
        cron(push_integrations, minute=set(range(1, 60, 5)), unique=True, timeout=COLLECT_TIMEOUT_S),
        cron(evaluate_alerts, minute=set(range(2, 60, 5)), unique=True, timeout=COLLECT_TIMEOUT_S),
        cron(build_retro_hunts, minute={4, 19, 34, 49}, unique=True, timeout=COLLECT_TIMEOUT_S),
        cron(build_products, hour=6, minute=5, unique=True, timeout=COLLECT_TIMEOUT_S),
        cron(scan_lookalikes, hour=4, minute=23, unique=True, timeout=COLLECT_TIMEOUT_S),
    ]
    on_startup = startup
    on_shutdown = shutdown
