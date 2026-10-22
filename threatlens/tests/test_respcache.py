from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

from threatlens.respcache import TTLCache


class Clock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


def counter() -> tuple[list[int], Callable[[], Awaitable[int]]]:
    calls: list[int] = []

    async def make() -> int:
        calls.append(1)
        return len(calls)

    return calls, make


async def test_answer_is_reused_until_ttl() -> None:
    clock = Clock()
    c = TTLCache(30, clock=clock)
    _, make = counter()
    assert await c.get(("kpis", "TLP:GREEN"), make) == 1
    clock.t = 29.9
    assert await c.get(("kpis", "TLP:GREEN"), make) == 1
    clock.t = 30.0
    assert await c.get(("kpis", "TLP:GREEN"), make) == 2
    assert (c.hits, c.misses) == (1, 2)


async def test_clearance_is_part_of_the_key() -> None:
    c = TTLCache(30, clock=Clock())
    _, make = counter()
    assert await c.get(("kpis", "TLP:GREEN"), make) == 1
    assert await c.get(("kpis", "TLP:AMBER"), make) == 2


async def test_concurrent_cold_requests_compute_once() -> None:
    c = TTLCache(30)
    calls = 0
    gate = asyncio.Event()

    async def make() -> str:
        nonlocal calls
        calls += 1
        await gate.wait()
        return "landscape"

    waiting = [asyncio.create_task(c.get(("landscape", "TLP:CLEAR"), make)) for _ in range(10)]
    await asyncio.sleep(0)
    gate.set()
    assert await asyncio.gather(*waiting) == ["landscape"] * 10
    assert calls == 1
    assert (c.hits, c.misses) == (9, 1)


async def test_oldest_entries_are_evicted() -> None:
    c = TTLCache(30, max_items=2, clock=Clock())
    _, make = counter()
    for k in ("a", "b", "c"):
        await c.get((k,), make)
    assert list(c._data) == [("b",), ("c",)]
    assert ("a",) not in c._locks


async def test_zero_ttl_turns_the_cache_off() -> None:
    c = TTLCache(0)
    calls, make = counter()
    await c.get(("kpis",), make)
    await c.get(("kpis",), make)
    assert len(calls) == 2
    assert not c._data
