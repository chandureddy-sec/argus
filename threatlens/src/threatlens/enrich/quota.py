"""Provider quotas, shared by the API and the worker.

Two mechanisms, both needed:

* **Our own count** of metered calls per fixed window (minute, day, week),
  so we stop *before* a provider refuses us.
* **The provider's word**: rate-limit headers or a 429 block the provider
  until the time it gave. Our count can drift (another tool using the same
  key, a provider resetting at a different hour); the provider's headers win.

``take`` checks every window first and only then counts, so a refused call
doesn't use up quota.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from typing import Protocol

from redis.asyncio import Redis

from threatlens.enrich.base import Quota


class QuotaStore(Protocol):
    async def take(self, name: str, quotas: Sequence[Quota], units: int = 1) -> float:
        """Spend ``units`` if every window allows it: 0.0, else seconds until
        the earliest window that blocks resets."""
        ...

    async def block(self, name: str, seconds: float) -> None:
        """The provider said stop: refuse calls for ``seconds``."""
        ...

    async def usage(self, name: str, quotas: Sequence[Quota]) -> dict[str, int]:
        """Units spent in each current window, keyed by ``Quota.label``."""
        ...


def _window(q: Quota, now: float) -> tuple[int, float]:
    w = int(now // q.window_s)
    return w, (w + 1) * q.window_s - now


class MemoryQuotaStore:
    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._counts: dict[tuple[str, int, int], int] = {}
        self._blocked: dict[str, float] = {}
        self._clock = clock

    async def take(self, name: str, quotas: Sequence[Quota], units: int = 1) -> float:
        now = self._clock()
        until = self._blocked.get(name, 0.0)
        if until > now:
            return until - now
        waits = []
        for q in quotas:
            w, left = _window(q, now)
            if self._counts.get((name, q.window_s, w), 0) + units > q.limit:
                waits.append(left)
        if waits:
            return max(waits)  # every blocking window must have reset
        for q in quotas:
            w, _ = _window(q, now)
            self._counts[(name, q.window_s, w)] = self._counts.get((name, q.window_s, w), 0) + units
        return 0.0

    async def block(self, name: str, seconds: float) -> None:
        self._blocked[name] = max(self._blocked.get(name, 0.0), self._clock() + max(1.0, seconds))

    async def usage(self, name: str, quotas: Sequence[Quota]) -> dict[str, int]:
        now = self._clock()
        return {q.label: self._counts.get((name, q.window_s, _window(q, now)[0]), 0) for q in quotas}


class RedisQuotaStore:
    PREFIX = "threatlens:quota:"

    def __init__(self, redis: Redis, clock: Callable[[], float] = time.time) -> None:
        self._redis = redis
        self._clock = clock

    def _key(self, name: str, q: Quota, w: int) -> str:
        return f"{self.PREFIX}{name}:{q.window_s}:{w}"

    async def take(self, name: str, quotas: Sequence[Quota], units: int = 1) -> float:
        now = self._clock()
        ttl = await self._redis.pttl(f"{self.PREFIX}{name}:blocked")
        if ttl and ttl > 0:
            return float(ttl) / 1000
        windows = [(q, *_window(q, now)) for q in quotas]
        if windows:
            counts = await self._redis.mget([self._key(name, q, w) for q, w, _ in windows])
            waits = [
                left for (q, _, left), c in zip(windows, counts, strict=True) if int(c or 0) + units > q.limit
            ]
            if waits:
                return max(waits)
            pipe = self._redis.pipeline()
            for q, w, left in windows:
                key = self._key(name, q, w)
                pipe.incrby(key, units)
                pipe.expire(key, int(left) + 60)
            await pipe.execute()
        return 0.0

    async def block(self, name: str, seconds: float) -> None:
        await self._redis.set(f"{self.PREFIX}{name}:blocked", "1", px=int(max(1.0, seconds) * 1000))

    async def usage(self, name: str, quotas: Sequence[Quota]) -> dict[str, int]:
        if not quotas:
            return {}
        now = self._clock()
        counts = await self._redis.mget([self._key(name, q, _window(q, now)[0]) for q in quotas])
        return {q.label: int(c or 0) for q, c in zip(quotas, counts, strict=True)}
