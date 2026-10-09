# Progress

| Phase | State | Notes |
|---|---|---|
| 0 Foundation | **complete** (Docker verified 2026-10-09) | `docker compose up --wait` healthy in 65 s; migrations 0001→0003 apply and re-apply cleanly; `/readyz` ready. CI workflow not yet run (no remote). |
| 1 Collection core | **complete** (Docker verified) | 8 connectors, hardened HTTP client, IOC extraction, allowlist, idempotent pipeline, API keys/RBAC/rate limits, v1 API, worker scheduling, CLI. Live collection checked on SQLite (below). |
| 2 Knowledge base | **complete** (Docker verified) | ATT&CK (3 domains, versioned, diffed), NVD/EPSS/KEV/OSV vulnerability records, relationship graph with provenance, path API. Live checks on SQLite and in the Docker stack (below). |
| 3–9 | not started | see PLAN.md |

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

## Phase 2 log
- 2026-10-09: verified ATT&CK index/bundles, NVD API 2.0 (live responses), EPSS CSV, OSV API; recorded fixtures. Entities/aliases/relationships/vulnerabilities/products/releases/changes (migration 0003), ATT&CK loader with meaningful-change diffing, NVD (scoped, paced, budgeted, resumable), EPSS, OSV, KEV from the Phase 1 connector, feed → graph linking with merge into ATT&CK, graph resolve/neighbours/shortest paths, `/api/v1` knowledge routes, `attack-load` CLI. Fixed during live testing: feed entities created before ATT&CK was loaded (now merged), naive/aware timestamp compare making every reload rewrite all rows, an O(n²) set rebuild (identical reload 145 s → 4 s), non-resumable NVD baseline.
- Spamhaus DROP fixture replaced with synthetic records (terms grant no redistribution); ATT&CK fixture notice added.

### Live check (2026-10-09, SQLite, real sources, no NVD key)
| Step | Result | Time |
|---|---|---|
| `collect cisa_kev feodo` | 1 739 KEV CVEs, 5 Feodo C2 IPs | 13 s |
| `collect mitre_attack` | Enterprise, Mobile, ICS 19.2: 30 894 objects → 5 931 entities, 24 788 relationships, 290 CVE-mention edges | 22 s |
| `collect nvd` (budget 30) | `partial` as designed: KEV + tech-stack baseline done, 6 214 CVEs with NVD data | 294 s |
| `collect epss` | 384 993 scores; 6 224 tracked CVEs updated | 8 s |
| `collect osv` (150) | 29 CVEs with GHSA advisories | 142 s |
| ATT&CK identical reload / 19.1 → 19.2 diff | 4 s / 17 meaningful changes, 237 relationships added | 4–11 s |

Acceptance, through the API:
* Techniques linked to malware: `GET /api/v1/entities/Emotet/techniques` → 47 techniques, each with MITRE's relationship and cited description.
* CVE flags: CVE-2024-3400 → `kev: true` (2024-04-12), EPSS 0.99999 (percentile 1.0), CVSS 10.0; exploit signals: exploited-in-the-wild, ransomware-use, exploitation-active, public-exploit-reference.
* Graph paths with provenance: live Feodo IP 162.243.103.246 → T1071.001 Web Protocols, length 2 (`indicates` via feodo, `uses` via mitre_attack). Emotet → CVE-2021-44228: 5 shortest paths of length 3 (via campaign C0017's ATT&CK text) in 0.06 s.
* Tech stack (PIR-2): 20 FortiOS CVEs in KEV via `?vendor=fortinet&product=fortios&kev=true`.

## Docker verification (2026-10-09)
Docker Desktop 4.94.0 (engine 29.8.2, Compose v5.5.1) on Windows 11 Home with WSL 2.
* `docker compose up -d --build --wait`: db, redis, migrate (exit 0), api, worker all healthy in 65 s.
* Integration tests (`make test-integration`), 6/6 passed: migrations apply twice, schema at head,
  **`alembic check` finds no model/migration drift**, Redis round-trip, `/readyz` against real
  dependencies, and the **full Phase 1–2 pipeline on Postgres** (JSONB, `ON CONFLICT`) in a
  throwaway database.
* The worker collected every source on its own schedule within a minute of starting: ATT&CK
  3 domains in ~20 s, URLhaus 32 934 URLs in ~45 s, KEV, Spamhaus, Tor, Feodo, OpenPhish;
  OTX/ThreatFox `skipped` (no keys).
* API through the published port with a real key: Emotet → 47 techniques; CVE-2024-3400 KEV +
  signals; live Feodo IP → T1071.001 path of length 2 (feodo, mitre_attack), with Feodo collected
  *before* ATT&CK, so the feed-entity merge also works on Postgres; 401 without a key.

Found and fixed during verification:
* `localhost` resolves to `::1` first on Windows, but the ports are published on IPv4: arq's 1 s
  connect timeout failed. Native defaults and docs now use `127.0.0.1` (integration suite 43 s → 8 s).
* The integration test still expected schema version `0001`; it now compares with Alembic's head.
* On a fresh stack EPSS ran before NVD stored any CVE and wouldn't run again for 24 h. EPSS now
  polls every 6 h with a conditional GET and, when the file is unchanged, scores newly tracked CVEs
  from the archived copy.
