# Progress

| Phase | State | Notes |
|---|---|---|
| 0 Foundation | code complete; awaiting Docker verification | Unit tests, lint, strict typing, bandit and pip-audit pass locally. `docker compose up` and the integration tests run once Docker Desktop is installed; CI runs them on push. |
| 1 Collection core | complete; awaiting Docker verification | 8 connectors, hardened HTTP client, IOC extraction, allowlist, idempotent pipeline, API keys/RBAC/rate limits, v1 API, worker scheduling, CLI. Live collection checked on SQLite (below). |
| 2–9 | not started | see PLAN.md |

## Phase 0 log
- 2026-10-08: scaffold, settings, structured logging, org profile + PIR validation, API health/readiness, worker heartbeat, Alembic baseline (pg_trgm, citext, app_meta), Dockerfile + Compose, CI workflow, pre-commit, PLAN, ADR 0001/0002, threat model, sources register, learning notes.

## Phase 1 log
- 2026-10-08: SSRF-guarded HTTP client, IOC extract/normalize/defang, allowlist engine, raw store, 8 connectors with fixtures, collection pipeline, migration 0002, API keys + RBAC + rate limiting, v1 routes.
- 2026-10-09: worker jobs (`enqueue_due` every minute, `collect_source`, daily `refresh_allowlist`), CLI (`collect`, `sources`, `allowlist-refresh`, `keys`, `extract`, `init-db`), API/auth/jobs/CLI tests, writable raw-data volume for the read-only worker container, bandit B101 asserts replaced with explicit checks, Spamhaus licence and interval corrected (see SOURCES.md corrections log), docs (DATA_MODEL, SOURCES, ADR 0003, learn/phase-1).

### Live collection check (2026-10-09, SQLite, real feeds)
| Source | Status | Items | New |
|---|---|---|---|
| cisa_kev | success | 1 739 | 1 739 |
| feodo | success | 5 | 5 |
| openphish | success | 300 | 299 (1 rejected) |
| spamhaus_drop | success | 1 763 | 1 762 |
| tor_exits | success | 1 198 | 1 198 |
| urlhaus | success | 32 855 | 32 854 |
| otx, threatfox | skipped (no key) | — | — |

Allowlist refresh: 10 000 Tranco, 22 Cloudflare, 21 Fastly, 3 org-profile
entries. 37 857 observables = indicators = sightings. A forced re-run gave
`not_modified` (KEV, Feodo via ETag) and `0 new / 1762 updated` (DROP): no
duplicates. 1 556 URLhaus URLs carry `popular-domain-host` (flagged, still
active). The raw archive was 1.5 MB.
