# Performance (Phase 9)

Measured 2026-10-22 on the developer laptop: Docker Desktop on Windows 11
(WSL 2 VM, 16 CPUs, 8 GB), Postgres 16 with default settings, the real
collection data (44,461 indicators; observables: 39,948 URL, 1,754
vulnerability, 1,705 IPv4 network, 1,313 IPv4 address, 91 IPv6 network).
Numbers are from one machine and vary run to run by about ±15 %; treat them as
orders of magnitude.

## Target: ≥ 100 cached lookups per second

`scripts/loadtest.py`: 50 active IPv4 indicators, enricher `ripestat`, warmed
once, then 16 concurrent clients for 30 s calling `/api/v1/lookup/ipv4-addr/…`.
Every answer must be 200 with every enrichment `cached`. The client ran inside
the Compose network (from Windows, Docker Desktop's port forwarding becomes the
bottleneck: 4 workers measured 84 req/s through it).

| API processes (`TL_API_WORKERS`) | req/s | p50 ms | p95 ms | p99 ms | errors |
|---|---|---|---|---|---|
| 1 | 92 – 103 | 150 – 171 | 206 – 230 | 252 – 262 | 0 |
| **2 (default)** | **214** | 58 | 123 | 174 | 0 |
| 4 | 258 – 334 | 27 – 37 | 102 – 163 | 146 – 368 | 0 |

One process sits right at the target, so Compose runs two
(`WEB_CONCURRENCY=${TL_API_WORKERS:-2}`; about 110 MB each). Running several
is safe: rate limits and enrichment quotas live in Redis, and the dashboard
cache is per process by design (at most one recomputation per process per TTL).

Where a cached lookup's time goes (cProfile, 300 lookups in-process, 14–19 ms
each): about 16 database statements and a few Redis calls run one after the
other (feed knowledge, graph neighbours, own-asset match, cached enrichments,
auth and rate limit), plus SQLAlchemy statement overhead. CPU in our own code
is small. Merging those reads is the next lever if one process must do more.

## Dashboard response cache

`scripts/perf_probe.py`, 7 calls per path, median (max) in ms. "Off" is
`TL_DASHBOARD_CACHE_S=0`; "on" is the default 30 s, where the first call
computes (the max) and the rest are served from the cache.

| Path | cache off | cache on |
|---|---|---|
| `/app/api/landscape` | 343 (397) | 3.7 (417) |
| `/app/api/kpis` | 95 – 102 | 4.0 – 4.2 |
| `/app/api/activity?range=Month` | 103 (167) | 4.4 (91) |
| `/app/api/threatmap` | 92 (157) | 5.7 (170) |
| `/app/api/calendar` | 85 (172) | 3.9 (80) |
| `/app/api/types` | 41 (68) | 5.0 (36) |

Entries are keyed by endpoint, parameters and TLP clearance, never by user:
none of these answers depends on who asks, only on what they may read. Data
changes when a collection run ends (minutes), so 30 s of staleness is not
visible in practice.

## Query and index tuning (migration 0015)

`EXPLAIN (ANALYZE, BUFFERS)`, second (warm) run. "Before" drops the 0015
indexes and restores the 0014 one inside a transaction that is rolled back.

| Query | Before | After | Plan after |
|---|---|---|---|
| Newest 50 indicators (`ORDER BY created_at DESC, id DESC`) | 26 ms, seq scan + top-N sort | **0.08 ms** | index-only scan backward on `ix_indicators_created` |
| Substring `value ILIKE '%login%'` | 20 ms (`lower(value) LIKE`, seq scan) | **1.2 ms** | bitmap scan on `ix_observables_value_trgm` |
| Substring `value ILIKE '%185.220%'` | 28 ms, seq scan | **2.2 ms** | bitmap scan on `ix_observables_value_trgm` |
| URLs newest first, first page | 0.58 ms (incremental sort over 301 rows) | **0.11 ms** | index scan backward on `ix_observables_type_seen`, no sort |
| IPv4 newest first, first page | 1.5 ms (incremental sort over 1,229 rows) | **0.10 ms** | same |
| URLs newest first, `OFFSET 20000` | 77 ms | 76 – 83 ms | unchanged: seq scan + external merge sort (4 MB to disk) |

`ANALYZE` now runs after the nightly rescore, which rewrites every indicator.

### Known gaps

* **Deep offsets.** With default costs the planner prefers a full sort for
  `OFFSET 20000`; forcing the index path costs 26–58 ms, and
  `random_page_cost = 1.1` (SSD) makes the planner choose it (28–58 ms). Not
  changed: page 400 of one type is rare, and the real fix is keyset paging
  (`?after=<last_seen,id>`), not planner settings.
* **`/api/v1/indicators?limit=50` without a type** takes 65 ms, mostly the
  `count(*)` for `total` over the join. A cheaper total (estimate, or cached)
  is the fix if it matters.
* **Worker stall during NVD sync.** While these measurements ran, the worker
  logged nothing for 15 minutes (no `enqueue_due`, no heartbeat) until the NVD
  job hit its 900 s timeout, and its health check reported unhealthy. Something
  in that job blocks the event loop; to be investigated.

## Reproduce

```
uv run python scripts/perf_probe.py http://127.0.0.1:8000 KEYFILE --repeat 7 --user NAME --passfile F
uv run python scripts/loadtest.py http://127.0.0.1:8000 KEYFILE --concurrency 16 --duration 30
```

The key's role needs a rate limit above the target (`TL_RATE_LIMIT_ADMIN`);
the measurements above used separate API containers with a raised limit so
the running stack's settings were not touched.
