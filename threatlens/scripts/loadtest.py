"""Load test: cached indicator lookups per second (Phase 9, docs/PERFORMANCE.md).

    uv run python scripts/loadtest.py http://127.0.0.1:8000 KEYFILE \\
        [--values 50] [--enrichers ripestat] [--concurrency 16] [--duration 30]

1. Takes ``--values`` IPv4 indicators from /api/v1/indicators.
2. Warms the cache: one lookup per value, one at a time (this is the only
   step that may reach the enrichment providers).
3. For ``--duration`` seconds, ``--concurrency`` clients look the values up in
   a loop. Every answer must be 200 with every enrichment ``cached``;
   anything else counts as an error.

Prints requests/s, latency percentiles and errors. The API key's role needs a
rate limit above the target (TL_RATE_LIMIT_ANALYST / _ADMIN).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import time
from pathlib import Path
from typing import Any

import httpx


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("base")
    ap.add_argument("keyfile")
    ap.add_argument("--values", type=int, default=50)
    ap.add_argument("--enrichers", default="ripestat", help="subset to look up (comma-separated)")
    ap.add_argument("--concurrency", type=int, default=16)
    ap.add_argument("--duration", type=float, default=30.0)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    key = Path(args.keyfile).read_text().strip()
    limits = httpx.Limits(max_connections=args.concurrency, max_keepalive_connections=args.concurrency)
    async with httpx.AsyncClient(
        base_url=args.base, headers={"X-API-Key": key}, timeout=60, limits=limits
    ) as c:
        page = (
            await c.get(
                "/api/v1/indicators", params={"type": "ipv4-addr", "status": "active", "limit": args.values}
            )
        ).json()
        values = [i["value"] for i in page["items"]]
        if not values:
            raise SystemExit("no active IPv4 indicators to look up")
        params = {"enrichers": args.enrichers}
        t0 = time.perf_counter()
        for v in values:  # warm-up, sequential and polite
            r = await c.get(f"/api/v1/lookup/ipv4-addr/{v}", params=params)
            r.raise_for_status()
        warm = time.perf_counter() - t0

        lat: list[float] = []
        errors: dict[str, int] = {}
        stop = time.perf_counter() + args.duration

        async def client(n: int) -> None:
            i = n
            while time.perf_counter() < stop:
                v = values[i % len(values)]
                i += 1
                t = time.perf_counter()
                try:
                    r = await c.get(f"/api/v1/lookup/ipv4-addr/{v}", params=params)
                except httpx.HTTPError as e:
                    errors[type(e).__name__] = errors.get(type(e).__name__, 0) + 1
                    continue
                lat.append((time.perf_counter() - t) * 1000)
                if r.status_code != 200:
                    errors[str(r.status_code)] = errors.get(str(r.status_code), 0) + 1
                elif any(e["status"] != "cached" for e in r.json()["enrichments"]):
                    errors["not-cached"] = errors.get("not-cached", 0) + 1

        start = time.perf_counter()
        await asyncio.gather(*(client(n) for n in range(args.concurrency)))
        took = time.perf_counter() - start
    q = statistics.quantiles(lat, n=100) if len(lat) >= 100 else [0.0] * 99
    out: dict[str, Any] = {
        "values": len(values),
        "enrichers": args.enrichers,
        "warmup_s": round(warm, 1),
        "concurrency": args.concurrency,
        "duration_s": round(took, 1),
        "requests": len(lat),
        "rps": round(len(lat) / took, 1),
        "p50_ms": round(q[49], 1),
        "p95_ms": round(q[94], 1),
        "p99_ms": round(q[98], 1),
        "max_ms": round(max(lat), 1) if lat else None,
        "errors": errors,
    }
    print(json.dumps(out) if args.json else "\n".join(f"{k:12} {v}" for k, v in out.items()))


if __name__ == "__main__":
    asyncio.run(main())
