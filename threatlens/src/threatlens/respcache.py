"""A short-lived response cache for dashboard aggregates (Phase 9).

The home page, landscape, threat map and calendar each run several
aggregates over every indicator (100-360 ms on 44k indicators). Their data
changes when a collection run finishes, every few minutes, so recomputing
them for every page view and every analyst is waste. Answers are cached per
endpoint, query and **TLP clearance** (never per user: none of these answers
depends on who asks, only on what they may read) for
``Settings.dashboard_cache_s`` seconds (0 turns it off; tests do).

One computation per key at a time: concurrent requests for a cold key wait
for the first instead of all hitting the database.
"""

from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Hashable
from typing import Any

from fastapi import Request


class TTLCache:
    def __init__(self, ttl: float, max_items: int = 256, clock: Callable[[], float] = time.monotonic) -> None:
        self.ttl = ttl
        self.max_items = max_items
        self.clock = clock
        self._data: OrderedDict[Hashable, tuple[float, Any]] = OrderedDict()
        self._locks: dict[Hashable, asyncio.Lock] = {}
        self.hits = 0
        self.misses = 0

    def _fresh(self, key: Hashable) -> tuple[bool, Any]:
        hit = self._data.get(key)
        if hit is not None and hit[0] > self.clock():
            return True, hit[1]
        return False, None

    async def get[T](self, key: Hashable, make: Callable[[], Awaitable[T]]) -> T:
        if self.ttl <= 0:
            return await make()
        ok, value = self._fresh(key)
        if ok:
            self.hits += 1
            return value  # type: ignore[no-any-return]
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            ok, value = self._fresh(key)  # another request filled it while we waited
            if ok:
                self.hits += 1
                return value  # type: ignore[no-any-return]
            self.misses += 1
            fresh = await make()
            self._data[key] = (self.clock() + self.ttl, fresh)
            self._data.move_to_end(key)
            while len(self._data) > self.max_items:
                old, _ = self._data.popitem(last=False)
                self._locks.pop(old, None)
        return fresh


def cache(request: Request) -> TTLCache:
    state = request.app.state
    c: TTLCache | None = getattr(state, "dash_cache", None)
    if c is None:
        c = state.dash_cache = TTLCache(state.settings.dashboard_cache_s)
    return c


async def cached[T](request: Request, key: tuple[Hashable, ...], make: Callable[[], Awaitable[T]]) -> T:
    """``make()``'s answer for ``key`` (endpoint, clearance, parameters), at most ttl seconds old."""
    return await cache(request).get(key, make)
