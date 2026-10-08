"""Liveness and readiness.

* Liveness (``/healthz``): the process is up and serving. It never touches a
  dependency, so an orchestrator won't restart the API just because Postgres
  is down (restarting wouldn't fix Postgres).
* Readiness (``/readyz``): every dependency answers within a timeout. Load
  balancers stop sending traffic while it fails.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

Check = Callable[[], Awaitable[None]]


@dataclass(frozen=True)
class CheckResult:
    name: str
    ok: bool
    latency_ms: float
    error: str | None = None


async def run_check(name: str, check: Check, timeout_s: float) -> CheckResult:
    start = time.perf_counter()
    try:
        await asyncio.wait_for(check(), timeout=timeout_s)
    except TimeoutError:
        return CheckResult(name, False, _ms(start), f"timed out after {timeout_s:g}s")
    except Exception as e:  # a readiness probe must report, never raise
        # Only the exception type: messages can carry DSNs or hostnames.
        return CheckResult(name, False, _ms(start), type(e).__name__)
    return CheckResult(name, True, _ms(start))


async def run_checks(checks: dict[str, Check], timeout_s: float) -> list[CheckResult]:
    return list(await asyncio.gather(*(run_check(n, c, timeout_s) for n, c in checks.items())))


def _ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 1)
