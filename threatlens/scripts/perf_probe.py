"""Time the API's read paths against a running stack (Phase 9 tuning).

    uv run python scripts/perf_probe.py http://127.0.0.1:8000 KEYFILE [--repeat 5] [--user NAME --passfile F]

/api/v1 paths use the API key; /app/api paths (Argus) need a session, so give
an account to sign in with.

Each endpoint is called ``--repeat`` times; the median and maximum wall time
are printed. Pair it with Postgres ``log_min_duration_statement`` to see which
SQL is slow, then ``EXPLAIN (ANALYZE, BUFFERS)`` that SQL.
"""

from __future__ import annotations

import argparse
import statistics
import time
from pathlib import Path

import httpx

PATHS = [
    "/api/v1/indicators?sort=priority&min_score=60&limit=50",
    "/api/v1/indicators?limit=50",
    "/api/v1/indicators?type=url&limit=50&offset=20000",
    "/api/v1/vulnerabilities?patch_priority=P1&sort=patch",
    "/app/api/kpis?range=Week",
    "/app/api/kpis?range=Year",
    "/app/api/activity?range=Month",
    "/app/api/types",
    "/app/api/collection",
    "/app/api/indicators?limit=50",
    "/app/api/indicators?q=login&limit=50",
    "/app/api/indicators?q=185.220&limit=50",
    "/app/api/landscape",
    "/app/api/attack",
    "/app/api/search?q=qakbot",
    "/app/api/threatmap",
    "/app/api/calendar",
    "/api/v1/detections/coverage",
    "/api/v1/products",
    "/api/v1/lookalikes",
]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("base")
    ap.add_argument("keyfile")
    ap.add_argument("--repeat", type=int, default=5)
    ap.add_argument("--user")
    ap.add_argument("--passfile")
    args = ap.parse_args()
    key = Path(args.keyfile).read_text().strip()
    c = httpx.Client(base_url=args.base, headers={"X-API-Key": key}, timeout=120)
    app = httpx.Client(base_url=args.base, headers={"Sec-Fetch-Site": "same-origin"}, timeout=120)
    if args.user and args.passfile:
        pw = Path(args.passfile).read_text().strip()
        app.post("/app/api/session", json={"username": args.user, "password": pw}).raise_for_status()
    print(f"{'path':58} {'status':>6} {'median ms':>10} {'max ms':>8} {'bytes':>9}")
    for p in PATHS:
        times, status, size = [], 0, 0
        for _ in range(args.repeat):
            t = time.perf_counter()
            r = (app if p.startswith("/app/") else c).get(p)
            times.append((time.perf_counter() - t) * 1000)
            status, size = r.status_code, len(r.content)
        print(f"{p[:58]:58} {status:>6} {statistics.median(times):>10.1f} {max(times):>8.1f} {size:>9}")


if __name__ == "__main__":
    main()
