from __future__ import annotations

import time

import pytest

from threatlens import worker


class FakeRedis:
    def __init__(self) -> None:
        self.store: dict[str, tuple[str, int | None]] = {}
        self.sets = 0

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        self.store[key] = (value, ex)
        self.sets += 1


async def test_heartbeat_records_timestamp_with_expiry() -> None:
    r = FakeRedis()
    await worker.heartbeat({"redis": r})
    value, ttl = r.store[worker.HEARTBEAT_KEY]
    assert abs(int(value) - time.time()) < 5
    assert ttl == 600  # a dead worker's heartbeat disappears instead of looking fresh


async def test_heartbeat_sleep_refreshes_during_a_long_paced_job(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A long NVD run paces through this sleep; each paced wait keeps the
    # heartbeat fresh so the 5-min cron being starved can't flip it unhealthy.
    async def instant(_delay: float) -> None:
        return None

    monkeypatch.setattr(worker.asyncio, "sleep", instant)
    r = FakeRedis()
    ctx: dict[str, object] = {"redis": r, "last_beat": 0.0}
    sleep = worker.heartbeat_sleep(ctx)

    await sleep(6.5)  # first paced wait refreshes right away
    assert worker.HEARTBEAT_KEY in r.store
    value, ttl = r.store[worker.HEARTBEAT_KEY]
    assert abs(int(value) - time.time()) < 5
    assert ttl == worker.HEARTBEAT_TTL_S

    # a wait within the throttle window does not write again
    before = r.sets
    await sleep(6.5)
    assert r.sets == before

    # once the throttle window has elapsed, the next wait refreshes again
    ctx["last_beat"] = time.time() - worker.HEARTBEAT_REFRESH_EVERY_S - 1
    await sleep(6.5)
    assert r.sets == before + 1


async def test_heartbeat_sleep_never_fails_the_job(monkeypatch: pytest.MonkeyPatch) -> None:
    async def instant(_delay: float) -> None:
        return None

    monkeypatch.setattr(worker.asyncio, "sleep", instant)

    class BoomRedis:
        async def set(self, *_a: object, **_k: object) -> None:
            raise RuntimeError("redis down")

    ctx: dict[str, object] = {"redis": BoomRedis(), "last_beat": 0.0}
    sleep = worker.heartbeat_sleep(ctx)
    await sleep(1.0)  # a Redis hiccup must be swallowed, not raised into the job


def test_worker_settings_schedule_heartbeat() -> None:
    ws = worker.WorkerSettings
    assert worker.heartbeat in ws.functions
    names = {getattr(f, "name", getattr(f, "__name__", "")) for f in ws.functions}
    assert {"collect_source", "refresh_allowlist", "enrich_backlog"} <= names
    assert {c.name for c in ws.cron_jobs} == {
        "cron:heartbeat",
        "cron:enqueue_due",
        "cron:refresh_allowlist",
        "cron:daily_scoring",
        "cron:enrich_backlog",
        "cron:import_recon_reports",  # saved monitor runs become assets (ADR 0014)
        "cron:push_integrations",  # SIEM/TIP pushes (ADR 0019)
        "cron:evaluate_alerts",  # alert rules (ADR 0019)
        "cron:build_retro_hunts",  # retro-hunt packs (ADR 0020)
        "cron:build_products",  # intelligence products (ADR 0021)
        "cron:scan_lookalikes",  # lookalike domains (ADR 0021)
    }
    assert ws.redis_settings.host  # parsed from TL_REDIS_URL
