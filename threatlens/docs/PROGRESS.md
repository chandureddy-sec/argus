# Progress

| Phase | State | Notes |
|---|---|---|
| 0 Foundation | **complete** (Docker verified 2026-10-09) | `docker compose up --wait` healthy in 65 s; migrations 0001→0003 apply and re-apply cleanly; `/readyz` ready. CI workflow not yet run (no remote). |
| 1 Collection core | **complete** (Docker verified) | 8 connectors, hardened HTTP client, IOC extraction, allowlist, idempotent pipeline, API keys/RBAC/rate limits, v1 API, worker scheduling, CLI. Live collection checked on SQLite (below). |
| 2 Knowledge base | **complete** (Docker verified) | ATT&CK (3 domains, versioned, diffed), NVD/EPSS/KEV/OSV vulnerability records, relationship graph with provenance, path API. Live checks on SQLite and in the Docker stack (below). |
| 3 Enrichment | **complete** (Docker verified 2026-10-10) | 9 enrichers (RDAP, DNS-over-HTTPS, RIPEstat ASN/geo, AbuseIPDB, GreyNoise, VirusTotal, urlscan, MalwareBazaar, crt.sh), DB-backed TTL cache with provenance, shared quota book, passive-first + TLP policy, lookup / bulk / catalogue API, background ASN/geo enrichment, UI panel, CLI `lookup`. ADR 0005. |
| 3b ReconX link | **complete** (live-verified 2026-10-10) | ReconX `scan --threatlens` → verdicts in JSON/HTML/MD reports, dashboard tab, `threat_intel_flagged` monitor rule; `--threatlens-assets` / `import-reconx` → own assets + observed tech stack (migration 0005), feed-listed assets first, own-asset lookups say investigate, PIR-2/NVD include observed applications. ADR 0006. |
| 4 Scoring, trust, TLP, feedback | **complete** (Docker verified 2026-10-11) | Scoring model v1 (configurable YAML, stored breakdown + config version, monotonic decay, independent-upstream corroboration, PIR/asset relevance, FP penalties), Admiralty credibility, daily rescore + expiry, CVE patch priority P1-P4 (KEV floor), analyst TP/FP feedback with audited source weights, TLP 2.0 clearance on every read path and sink. Migration 0007, ADR 0008. |
| 5 Analyst experience | **complete** (browser-verified 2026-10-18) | Landscape dashboard (triage queue, PIR matches, trending malware/techniques, ATT&CK tactic heat, KEV vs. our stack, feed health), indicator page (verdict, score breakdown, pivots with provenance, ATT&CK techniques via malware, timeline, stored enrichment cards, notes, TP/FP), search + saved views, bulk check (500 values, CSV), cases with Markdown and PDF reports. Walkthrough in `docs/DEMO.md` (3–5 s machine time). |
| Response (SecIncyte parity, step 1 of 4) | **complete** (Docker verified 2026-10-11) | Blocklist (monitor → enforce with four eyes, expiry, lift/extend), never-block guard checked on block and export, `/api/v1/blocks`, token-protected feed export (EDL text, CSV, JSON, STIX 2.1), Settings (policy, tokens). Migration 0009, ADR 0010. |
| Investigate (SecIncyte parity, step 2 of 4) | **complete** (browser-verified 2026-10-11) | Verify an indicator (live provider cards, verdict, second-opinion links by TLP, Block / Flag malicious / Not malicious in place), Bulk check (file upload, rows streaming in, progress, filters, select threats, detail pane, block/flag/case on selected, auto-block), streaming lookup in the service, self-hosted `app.js` under CSP `script-src 'self'`. ADR 0011. |
| Interactivity (SecIncyte parity, step 4 of 4) | **complete** (browser-verified 2026-10-18) | Threat map (zoom/pan, hover lists every IP at a place, filterable side list, feed landscape vs. blocked & flagged), chart drill-downs (area, bar, rings → filtered Indicators), activity calendar, threat journey (7 stages, indicator page + drawer from the Indicators list). ADR 0018. |
| 6 Dissemination | **complete** (live-verified 2026-10-18) | STIX 2.1 with TLP 2.0 markings (validated by stix2-validator), read-only TAXII 2.1 server (4 TLP/confidence collections; consumed by the OASIS taxii2-client and by another ThreatLens's TAXII feed reader), licence/TLP-aware exports (EDL, CSV, JSON, STIX, Wazuh CDB), integrations (Splunk HEC, Elastic/ECS, Sentinel STIX upload, MISP push, webhook; MISP and TAXII pull as feed formats), SIEM sightings + Wazuh webhook, alert rules to Slack/Teams/Telegram/email/webhook (once, within TLP, rate-limited). Migration 0012, ADR 0019, docs/INTEGRATIONS.md. |
| 7 Detection engineering | **complete** (live-verified 2026-10-18) | Rules from indicators: Sigma (pySigma → Splunk SPL, KQL, Elastic Lucene), Suricata (IP, DNS, TLS SNI, HTTP; CI runs the real `suricata -T`), YARA (hash module, compiled and match-tested), Wazuh XML over the CDB exports; every rule validated with author/date/references/ATT&CK/TLP/confidence/FP metadata. 14-technique hunt library, ATT&CK Navigator layers, coverage gaps vs. an imported Sigma inventory, retro-hunt packs every 15 min. Migration 0013, ADR 0020. |
| 8 Products and AI | **complete** (live-verified 2026-10-18; AI model not measured: no key) | Daily brief, weekly CTI report, vulnerability priority list, executive one-pager (HTML + PDF, cited, TLP-capped, deterministic with a verify endpoint; built daily at 06:05 UTC). Lookalike domains from dnstwist permutations, crt.sh and our feeds (passive), review/block, `lookalike` alerts. Guarded AI report assistant (Claude, off by default): structured output, grounding of every item against the report, injection quarantine, fingerprints, draft → approved case. SYNTHETIC 36-report evaluation set and harness. Migration 0014, ADR 0021/0022. |
| 9 Hardening and release | **in progress** | Performance done (Docker verified 2026-10-23, docs/PERFORMANCE.md): migration 0015, dashboard cache (≈100 ms → 4 ms), 2 API processes by default (214 cached lookups/s; 1 process ≈ 100). Still to do: observability, backup/restore, ZAP baseline, docs, v1.0.0; worker stall during NVD sync found. |

## Phase 9 log
- 2026-10-22: migration 0015 (observables (type, last_seen, id) replaces (type, last_seen); indicators (created_at, id); trigram GIN on observables.value/.defanged on Postgres), `/indicators?q=` uses ILIKE so the trigram index applies, `respcache.py` (dashboard aggregates cached per endpoint, parameters and TLP clearance for `TL_DASHBOARD_CACHE_S`, default 30 s; one computation per cold key) on kpis, activity, types, landscape, threat map and calendar, `ANALYZE` after the daily rescore, `scripts/perf_probe.py`, `scripts/loadtest.py`.
- Verified: 689 tests pass (5 new cache tests), ruff/mypy clean, migration 0015 renders offline for Postgres (both GIN indexes). Not verified yet: Docker was not running, so no upgrade/downgrade on Postgres, no `alembic check`, no load-test or EXPLAIN numbers.
- 2026-10-23 (Docker stack, 44,461 indicators): migration 0015 upgrade → `alembic check` (no drift) → downgrade 0014 → upgrade on a scratch database; real database at 0015 with no drift. EXPLAIN before/after in a rolled-back transaction: newest indicators 26 → 0.08 ms, substring search 20–28 → 1–2 ms, first page per type 0.6–1.5 → 0.1 ms; deep `OFFSET 20000` unchanged (~80 ms, known gap). Dashboard endpoints 41–343 ms → 4–6 ms with the cache. Load test: 1 API process 92–103 req/s, 2 → 214, 4 → 258–334, no errors; Compose now runs `TL_API_WORKERS` (default 2). Found: the worker stalls for the whole NVD job (no heartbeat for 15 min, health check unhealthy) — open.

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

## Phase 3 log
- 2026-10-10: provider docs and terms checked (AbuseIPDB, GreyNoise, VirusTotal, urlscan, MalwareBazaar, RIPEstat, IANA RDAP bootstrap, Cloudflare DoH, crt.sh), live keyless responses recorded as fixtures; `SafeHttp` gained response headers, accepted 4xx statuses and form posts; enricher framework, quota store (memory/Redis), v0 verdict, enrichment service, migration 0004 (`enrichments`), `/api/v1/lookup`, `/api/v1/enrich`, `/api/v1/enrichers`, worker `enrich_backlog` (every 30 min), CLI `lookup` / `enrich-backlog`, UI indicator enrichment panel and map geo from enrichment.
- Found and fixed during testing: concurrent first lookups raced to insert the enricher `sources` rows (UNIQUE violation on a fresh database); `/sources` reported key status from process settings instead of the app's.
- Note: a forked agent briefly wrote `enrich/service.py` in parallel; its version was reviewed and kept.

### Live check (2026-10-10, Docker stack, real providers, no enrichment keys)
| Check | Result |
|---|---|
| `GET /lookup/ipv4-addr/162.243.103.246` (Feodo C2), cold | `malicious` 70 → `block`, 1.27 s; RDAP (DigitalOcean), RIPEstat AS14061 Secaucus US, GreyNoise not observed, urlscan no scans; AbuseIPDB/VT `skipped: no_api_key`, `partial: true` |
| same, cache hit | **51 ms** end to end (acceptance: < 2 s) |
| `71.6.199.23` (Shodan) | `benign` → `no_action`: GreyNoise "known benign scanner: Shodan.io" |
| `domain-name/crawhyderabad.in` | RDAP: 860 days old; crt.sh `error` (service down, 502/404 all day): reported, rest returned |
| `?active=true&enrichers=dns` | A 72.61.230.175, Cloudflare NS; `enrich.active` audit row written |
| `POST /enrich` with an EDR alert text + `10.1.2.3` | 4 observables extracted and deduplicated, private IP rejected with reason, worst first, budget spent 3 |
| `.\tl enrich-backlog --limit 40` | 40 IP indicators enriched in the container; dashboard map 5 → 46 located IPs |
| Integration tests on Postgres/Redis | 8/8 incl. `alembic check` (0004 matches the models), Redis quota store, enrichment pipeline on Postgres |

## UI accounts (2026-10-10, ADR 0007)
- The owner asked for a username and password on the sign-in page instead of pasting an API key. Migration 0006 (`users`), `threatlens.users` (scrypt hashing, case-insensitive usernames), `threatlens users create|passwd|role|disable|enable|list`, `.\tl user` / `.\tl passwd` (password typed twice, sent on stdin). Sessions are bound to the password; sign-in is rate-limited per address and per account. API keys remain for `/api/v1` and ReconX only.
- Also removed: the Swagger `/docs` page and its links (owner request), and Docker's "What's next" hints in `tl` output.

## Phase 4 log
- 2026-10-11: `threatlens.scoring` (config, model, store, feedback, vulns), `threatlens.tlp`, migration 0007 (credibility, feedback weights, `verdicts`, clearances, patch priority), lookups on the v1 model (the v0 interim verdict is removed), feedback API + UI buttons, score panel, priority sort, patch-priority column, daily `daily_scoring` cron + `threatlens rescore`, `--clearance` on keys and users. OTX now stores pulse `targeted_countries` / `industries`.
- Found while building: Feodo still lists 162.243.103.246 (Phase 3's "malicious/block" example), but reports it offline since 2026-03-07. v1 decays it to 0 ("monitor"). Also: an unknown clearance first mapped to RED (fail-open); fixed to CLEAR and tested.
- Coverage of async code after a SQLAlchemy greenlet switch was under-reported; `concurrency = ["greenlet", "thread"]` fixed the measurement (feedback.py 56% → 89%).

### Live check (2026-10-11, Docker stack, real data)
| Check | Result |
|---|---|
| `.\tl rescore` | 38,868 indicators scored in 14.1 s; 5,266 expired (5,262 URLhaus URLs offline long ago, 4 Feodo C2s offline since March); 6,225 vulnerabilities given a patch priority; config `1.0/103eb59b` |
| Distribution (active) | Spamhaus DROP ≈ 95 (block); OpenPhish ≈ 64; URLhaus 16,876 ≥ 60 and 5,324 at 30-59; Tor exits ≈ 30 (monitor); 1 live Feodo C2 at 80.75 |
| Live Feodo C2 50.16.16.211 | `70.75 + 0 + 10 − 0 = 80.75` malicious; +10 = linked malware uses a PIR-1 technique; valid until 2026-11-07 unless re-listed |
| Lookup 162.243.103.246 | cold 0.22 s, cached **21 ms**; `unknown` / `monitor`; evidence "listed by feodo; offline since 2026-03-07 … 217.75 days ago" |
| Patch priority | P1 821 (808 KEV), P2 1,233, P3 4,083, P4 88; CVE-2018-13379 (FortiOS, in the profile stack) P1 with 120 points |
| UI as a viewer | `/ui` 0.55 s, indicators/indicator/vulnerability/sources/assets pages 0.03-0.12 s; no feedback buttons for viewers |
| Integration (Postgres/Redis) | 8/8 incl. `alembic check` (0007 matches the models) |

## Phase 5 log
- Before 2026-10-18: the analyst pages were built during the Argus rebuild (ADR 0013–0016): Landscape, Indicators + indicator page, Verify, Bulk check, Cases, Search.
- 2026-10-18 (closing the phase against the spec):
  * `GET /app/api/indicators/{id}/related` returns stored enrichment cards (no new lookups), graph pivots grouped by type with provenance, ATT&CK techniques (the indicator's own plus those of its malware/actors), and a sightings + enrichment timeline.
  * Saved views: `/app/api/searches`, per account, Argus paths only; views saved by the old `/ui` pages still open.
  * Case PDF export: `threatlens.pdf`, fpdf2 + bundled Inter (OFL), TLP marking on every page.
  * "Add to case" can open a new case in one click.
- Found and fixed:
  * Free text in case reports (title, summary, conclusion, notes) was not defanged; now both the Markdown and the PDF reports defang it.
  * A table row taller than a page crashed the PDF; table cells are now capped.
  * The audit-log CSV export allowed spreadsheet formula injection (found by semgrep in CI); cells are neutralised (`sheet_safe`), and the file name is sanitised.
  * Zone-less timestamps (SQLite) were read as local time.
- CI (first run on GitHub, 2026-10-15) was red:
  * bandit flagged asserts and SSO placeholders;
  * the Trivy action tag no longer existed;
  * the image build lacked the web build context;
  * `compose up --wait` failed on the worker with no healthcheck.

  All fixed. The worker now has a heartbeat healthcheck, and a web typecheck/build/audit job was added.

### Live check (2026-10-18, throwaway SQLite instance, real feeds)
Feodo 5, CISA KEV 1,748, ATT&CK 20.0 (6,340 entities), URLhaus 33,521; `scripts/demo_walkthrough.py` in headless Chrome.

| Step finished | Feodo C2 50.16.16.211 | URLhaus URL |
|---|---|---|
| Indicator page with pivots and techniques | 0.5 s | 0.8 s |
| Verdict recorded | 3.6 s | 2.3 s |
| Case opened with the evidence | 3.9 s | 2.5 s |
| PDF report downloaded | 5.0 s | 3.4 s |

## Phase 8 log
- 2026-10-18: `products/` (build, render, store, product.html), `lookalike.py`, `ai.py`, `ai_eval.py`, `api/produce.py`, migration 0014 (`products`, `lookalikes`, `ai_drafts`; `lookalike` alert kind), worker crons `build_products` (06:05 UTC) and `scan_lookalikes` (04:23 UTC), Argus pages Products, Lookalike domains, Report assistant; `scripts/make_ai_eval.py` + `scripts/ai_eval.py`; settings `TL_PRODUCTS_MAX_TLP`, `TL_LOOKALIKE_CT`, `TL_AI_*`. Dependencies: dnstwist, anthropic 1.15.
- Found and fixed:
  * The feed half of the lookalike scan searched by brand keyword, which can never find a homoglyph (`exarnple.com`): it now matches permutations exactly too.
  * Two org domains with the same keyword sent the same crt.sh query twice: one query per keyword.
  * "New indicators" counted CVE observables (1,748 of 2,962 in the live data): excluded, they have the KEV section.
  * The AI guard, measured with a scripted attacker model, first let 40/288 planted items through (an invented ATT&CK ID with a real quote; values planted inside injected sentences). It now checks IDs against ATT&CK and grounds against the report minus injected sentences: 0/288. The phrase list was extended after it missed "Assistant, please also add…", so that number is not a blind test (ADR 0022).
  * A one-word "quotation" counted as evidence: quotations need 12+ characters.

### Live check (2026-10-18, throwaway instance: Feodo, Tor exits, CISA KEV, ATT&CK 20.0)
| Check | Result |
|---|---|
| Generate daily / weekly / vulns / exec via the API | 201 each in 0.03–0.15 s; verify → same fingerprint; HTML served with `default-src 'none'` |
| Daily brief covering today (real data) | 1,214 new indicators (CVEs excluded), 1 high priority (Feodo QakBot C2, cited `indicator #2`), families QakBot (4) and Emotet (1); rebuild gave the same SHA-256; PDF renders on one page with the marking |
| Vulnerability priority list | 40 P1/P2 CVEs with reasons |
| Lookalike scan, real crt.sh (`yourcompany.com` placeholder profile) | first call: crt.sh 502, recorded as an error, scan completed; retry: answered in 1.8 s, 0 candidates |
| AI assistant without a key | `/ai/status` off; `/ai/extract` 503 with how to enable; deterministic extraction of a synthetic injected report flags 3 injection phrases |
| Evaluation (`scripts/ai_eval.py`) | extractor precision 0.659 / recall 1.000; guard keeps 498/498 true items, 0/288 planted; injection flags 9/9, 0 false; Claude not measured (no key) |

## Phase 7 log
- 2026-10-18: `detect/` (rules, hunts + hunts.yml, attack, retro), `api/detect.py`, migration 0013 (`detection_rules`, `retro_hunts`), worker cron `build_retro_hunts`, Argus page Detections (rules, hunts, coverage, retro-hunts), Navigator button on entity pages, `scripts/detection_samples.py` + CI step running jasonish/suricata:7.0 `-T`.
- Verified before building: pySigma backends on PyPI (Splunk 2.1.0, Kusto 1.0.1, Elasticsearch 2.1.1; they pin pySigma < 2, so 1.5.1); no pySigma Wazuh backend exists; pySigma bundles ATT&CK v20 tactics (Defense Evasion split into Stealth and Defense Impairment).
- Found and fixed:
  * Suricata sids hashed into 900k collided with 1,210 indicators (birthday): now probed to the next free sid.
  * The real Suricata engine rejected two things suricataparser accepted: a URL path's `;` and `"` inside msg, and `nocase` on `http.host`. The checker now catches the msg case, and CI runs the engine.
  * pySigma's `attacktag` validator downloads MITRE data at run time: disabled; ATT&CK tags are checked offline.
  * Hunts tagged `attack.defense-evasion` (gone in ATT&CK v18+): now `attack.stealth`.

### Live check (2026-10-18, throwaway instance: Feodo, Tor exits, CISA KEV, ATT&CK 20.0)
| Check | Result |
|---|---|
| Generate at score 30 (TLP:GREEN) | Sigma, Suricata, Wazuh for 1,210 indicators; 0 validator problems |
| Suricata 7.0.17 `-T` (Docker) | all 1,210 generated rules load; every rule shape (DNS, TLS SNI, HTTP with escaped path, IPv6) loads |
| Zip pack | 36 files, README starts with the marking |
| Navigator layer for QakBot (S0650) | 71 techniques, ATT&CK 20 |
| Coverage with 2 imported rules | 71 relevant techniques (QakBot), 1 covered (T1059.001), gaps ranked |

## Phase 6 log
- 2026-10-18: `share/` package (select, stix, taxii, export, sinks, integrations, alerts, sightings), `api/share.py`, migration 0012 (integrations, integration_runs, alert_rules, alert_events; custom_feeds.allow_internal and formats taxii/misp), worker crons `push_integrations` and `evaluate_alerts`, Argus pages Integrations and Alerts, feed form TAXII/MISP + internal network, `scripts/sink.py`, `integrations/wazuh/custom-argus`.
- Verified before building: OASIS TLP 2.0 marking ids, Sentinel STIX objects upload API (preview, ≤100 objects, 100 req/min), Splunk HEC format, MISP OpenAPI (restSearch, events/add, Authorization header), Wazuh CDB list format, ECS threat fields (marking.tlp accepts CLEAR and AMBER+STRICT).
- Found and fixed:
  * stix2-validator 3.3.1 on PyPI ships without its schemas: pinned 3.2.0.
  * TAXII date-added headers at millisecond precision made a resumed pull repeat the last object: now microseconds.
  * Exports listed our own SIEM as a "source": environment sources are now excluded from everything that leaves.
  * The integration sink logged MISP's bare API key: now masked.
  * SIEM sightings would have counted as feed reports in scoring: environment sources are excluded from scoring.
- Migration 0012: upgrade, `alembic check` (no drift), downgrade, upgrade on a scratch Postgres database.

### Live check (2026-10-18, throwaway instance, real Feodo / Tor exits / CISA KEV)
| Check | Result |
|---|---|
| OASIS `taxii2-client` (HTTP Basic, key as password) | 4 collections; CLEAR ≥30: 1,214 objects in 7 pages in 0.17 s; valid STIX 2.1 |
| Exports | ip.txt 1,210 lines, wazuh-ip.cdb 1,210, CSV 1,211, stix.json valid |
| Splunk HEC / Elastic / MISP / webhook → sink | test OK; 1,210 sent each; second push 0 |
| Alert rule "seen in our environment" → Slack sink | SIEM sighting of 50.16.16.211 → 1 raised, 1 delivered; second evaluation 0 |
| Wazuh `custom-argus` script | exit 0; sighting recorded and shown in the threat journey |

## Phase 3b log
- 2026-10-10: ReconX: `internal/threatlens` client (batches of 100, TLP, budget, clear errors), `ScanReport.threat_intel`, scan flags `--threatlens[=url]`, `--threatlens-tlp`, `--threatlens-budget`, `--threatlens-assets`, key-store entry + key test, HTML/Markdown sections, dashboard tab and scan option, `RunScanPipeline` option, monitor runs include ThreatLens when configured, rule `threat_intel_flagged`. Contract fixture recorded from the live API.
- ThreatLens: migration 0005 (`asset_imports`, `assets`, `asset_products`), `assets.py` importer and read side, `/api/v1/assets` (import, list, products, imports), CLI `import-reconx`, Assets UI page, own-asset context in lookups, observed stack in PIR-2 and NVD scope.
- Found during the live check: ReconX's IP list includes name-server/mail/CDN addresses (16 of 17 IPs in a real scan); the importer now keeps only addresses the scanned hosts resolve to, minus CDN edges, and reports why each other one was left out. Country names were being cut to 8 characters.

### Live check (2026-10-10, ThreatLens Docker stack + reconx.exe)
| Check | Result |
|---|---|
| `reconx scan crawhyderabad.in --threatlens` | 19 hosts/IPs checked in one batch: 19 unknown (clean), each with evidence (RDAP, RIPEstat, GreyNoise) and its skip reasons (`abuseipdb: no_api_key`, `virustotal: tlp` at GREEN); 27 metered calls; report JSON/HTML/MD carry the section; scan 62 s |
| `reconx scan example.com --threatlens --threatlens-assets --threatlens-tlp TLP:AMBER` | verdict + import (1 new asset); test rows removed afterwards |
| `threatlens import-reconx` of the real crawhyderabad.in report (throwaway SQLite) | 2 hosts + their server IP imported; 16 name-server/CDN IPs left out with reasons |
| ReconX dashboard `/api/config` with ThreatLens env | `threatlens: true`, URL shown; tab and scan option served |
| Go | `go vet ./...` clean, 32 packages pass (client against the recorded contract, batching, partial failures, monitor rule, reports) |
