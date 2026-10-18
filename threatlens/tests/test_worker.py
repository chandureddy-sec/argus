from __future__ import annotations

import time

from threatlens import worker


class FakeRedis:
    def __init__(self) -> None:
        self.store: dict[str, tuple[str, int | None]] = {}

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        self.store[key] = (value, ex)


async def test_heartbeat_records_timestamp_with_expiry() -> None:
    r = FakeRedis()
    await worker.heartbeat({"redis": r})
    value, ttl = r.store[worker.HEARTBEAT_KEY]
    assert abs(int(value) - time.time()) < 5
    assert ttl == 600  # a dead worker's heartbeat disappears instead of looking fresh


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
    }
    assert ws.redis_settings.host  # parsed from TL_REDIS_URL
