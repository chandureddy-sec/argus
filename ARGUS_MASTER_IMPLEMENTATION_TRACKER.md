# Argus — Master Implementation Tracker

**Single source of truth for task status.** Reconciles the external
[`THREAT_INTELLIGENCE_AND_RECONNAISSANCE_BUILD_GUIDE.md`](../TEST%20FILE/THREAT_INTELLIGENCE_AND_RECONNAISSANCE_BUILD_GUIDE.md)
(research baseline 25 Oct 2026) against the Argus codebase, its phase log
([`threatlens/docs/PROGRESS.md`](threatlens/docs/PROGRESS.md)), plan
([`threatlens/PLAN.md`](threatlens/PLAN.md)) and 22 ADRs
([`threatlens/docs/adr/`](threatlens/docs/adr/)).

- **Reconciled:** 2026-10-26
- **Companion docs:** [`ARGUS_IMPLEMENTATION_ROADMAP.md`](ARGUS_IMPLEMENTATION_ROADMAP.md) (execution order) · [`ARGUS_IMPLEMENTATION_CHANGELOG.md`](ARGUS_IMPLEMENTATION_CHANGELOG.md) (history)
- **Rule:** *Implemented* ≠ *Verified*. Verified requires acceptance evidence (tests I ran, documented live/Docker/browser checks, or validators). The guide is the requirement source; the repo is assessed only for status.

---

## 1. How status was established (evidence basis)

| Evidence type | What was done this session |
|---|---|
| Go/ReconX test suite | `go test ./...` → **all 37 test packages pass, exit 0** (2026-10-26). |
| Python test suite | **692 unit tests pass, exit 0** (this session, `uv run pytest --ignore=tests/integration`, 5m13s); separate `integration/` suite + Docker `alembic check` documented in PROGRESS (2026-10-23). |
| Data model | `threatlens/src/threatlens/models.py` holds **40+ ORM tables**; 15 Alembic migrations `0001`→`0015`. |
| Code inspection | Verified presence/absence of multi-tenancy (`tenant_id` → **0 hits**), object storage (filesystem `rawstore.py`, **no S3/boto3/minio**), OpenTelemetry (**absent**), backup scripts (**absent**), recon scope gate (`internal/cli/authorize.go`). |
| Documented verification | PROGRESS.md records dated live/Docker/browser checks per phase; treated as supporting evidence, corroborated by code where possible, never taken alone. |

**Verification gaps (status marked conservatively):** the AI/Claude path is unmeasured (no API key); SIEM sink integrations are exercised only against a local test sink, not real Splunk/Elastic/Sentinel; TAXII/STIX are validated by their standard validators but not against a third production server.

---

## 2. Progress summary

### 2.1 Headline numbers

| Metric | Value |
|---|---|
| **Weighted progress** (Critical=4/High=3/Med=2/Low=1; V=100%, Impl=75%, Partial=50%, InProgress=25%, NotStarted=0%) | **90.9 %** (earned 247.25 / 272 included weight) |
| **Raw task count — Verified only** | **79.8 %** (79 of 99 included tasks Verified) |
| **Raw task count — Verified + Implemented** | **82.8 %** (82 of 99) |
| Included tasks | 99 |
| Deferred/excluded from denominator | 4 (reported separately in §5) |

**Denominator & exclusions:** the 4 Deferred items (multi-tenancy, S3 object storage, multi-tenant sharing groups, graph database) are **excluded** from the weighted denominator because each is an explicit, documented design decision for a single-host single-org deployment (PLAN §3, ADR 0001), not pending work. Parent/child double-counting avoided: each capability is one row. The weighted figure is reported alongside the raw count so incomplete high-priority work cannot hide behind the weighting.

### 2.2 Status distribution (included tasks)

| Status | Count |
|---|---|
| Verified | 79 |
| Implemented (not verified) | 3 |
| Partially complete | 10 |
| In progress | 0 |
| Not started | 7 |
| **Deferred (excluded)** | 4 |

### 2.3 Per-workstream progress (weighted)

| # | Workstream | Weighted | Status |
|---|---|---|---|
| WS1 | Core architecture, data models, shared infra | 100 % | Complete |
| WS2 | Asset & evidence management | 91 % | Near-complete |
| WS3 | Passive recon & OSINT | 100 % | Complete |
| WS4 | Active recon & authorized scanning | 91 % | Near-complete (scope record, kill switch) |
| WS5 | TI ingestion & IOC management | 100 % | Complete |
| WS6 | Enrichment, correlation, relationships | 95 % | Near-complete (attribution workflow) |
| WS7 | Attack-surface mapping & change detection | 94 % | Near-complete (alert grouping) |
| WS8 | Threat analysis, attribution, prioritization | 93 % | Near-complete (AI unmeasured, clustering) |
| WS9 | APIs, integrations, exports, interop | 96 % | Near-complete (SIEM live-test, OpenAPI) |
| WS10 | Frontend workflows & UX | 94 % | Near-complete (active-run scope UI) |
| WS11 | Security, testing, reliability, ops readiness | 73 % | **In progress — the gap** |
| WS12 | Advanced / future enhancements | 25 % | Mostly deferred/optional |

**The entire remaining gap is operational readiness (WS11) plus a handful of partials.** All Critical-priority tasks are Verified; no Critical work is incomplete.

---

## 3. Task catalogue

Columns: **ID · Capability · Priority · Status · Completion · Evidence · Remaining / verification needed**.
Priority P: C=Critical, H=High, M=Medium, L=Low. Status S: V=Verified, I=Implemented, P=Partial, IP=InProgress, NS=NotStarted, D=Deferred.

### WS1 — Core architecture, data models, shared infrastructure

| ID | Capability | P | S | % | Evidence | Remaining / verification |
|---|---|---|---|---|---|---|
| WS1-01 | Evidence-first data model (sources, raw_documents, observables, indicators, sightings, entities, relationships) | C | V | 100 | `models.py` 40+ tables; migrations 0001–0015; `test_ioc`, `test_collect` | — |
| WS1-02 | Idempotent ingestion + stable dedupe keys | C | V | 100 | `collect.py`, `intake.py`; PROGRESS live "not_modified / 0 new / 1762 updated" | — |
| WS1-03 | Normalization (domain/IP/URL/hash/IDNA, UTC + source ts) | C | V | 100 | `ioc/normalize.py`, `ioc/defang.py`; `test_ioc` | — |
| WS1-04 | Raw artifact store with provenance + replay | H | V | 100 | `rawstore.py` content-addressed gzip + SHA-256 verify; archive tests | Deviation: filesystem, not S3 (acceptable single-host) |
| WS1-05 | Job/queue/scheduler (arq worker, cron, leases) | C | V | 100 | `worker.py`, `jobs.py`; `test_worker`, `test_jobs`; Docker worker heartbeat | — |
| WS1-06 | Hardened HTTP client (SSRF guard, size/time caps, retry/backoff, ETag) | C | V | 100 | `net/guard.py`; `test_http` (bypass cases) | — |
| WS1-07 | Config + secret handling (TL_SECRET_KEY vault, encrypted feed keys) | H | V | 100 | `vault.py`, `settings.py`, `.env.example` | — |
| WS1-10 | Text search (guide allows PG FTS early) | M | V | 100 | trigram GIN (migration 0015), `/indicators?q=` ILIKE | OpenSearch intentionally deferred |

### WS2 — Asset & evidence management

| ID | Capability | P | S | % | Evidence | Remaining / verification |
|---|---|---|---|---|---|---|
| WS2-01 | Asset model + ReconX import (assets, asset_products, asset_imports) | H | V | 100 | `assets.py`, migration 0005, `test_assets`; live import check | — |
| WS2-02 | Evidence timeline / observations per entity | H | V | 100 | `argus_api` related endpoint; `test_analyst` | — |
| WS2-03 | Org profile / seeds (domains, ranges, brands, tech stack) | H | V | 100 | `profile.py`, `config/org_profile.yaml`; `test_profile` | — |
| WS2-04 | Asset ownership, criticality, remediation tracking | M | P | 50 | assets carry source/first-seen; no owner/criticality/remediation-status workflow | Add owner + criticality fields and remediation state; tests |

### WS3 — Passive recon & OSINT

| ID | Capability | P | S | % | Evidence | Remaining / verification |
|---|---|---|---|---|---|---|
| WS3-01 | Passive subdomain sources (crt.sh, OTX, HackerTarget, Anubis, Wayback, urlscan, CertSpotter, GitHub) | C | V | 100 | `internal/providers/*` + per-provider tests pass | — |
| WS3-02 | Certificate Transparency parsing (issuer/validity/SAN/fingerprint) | H | V | 100 | `internal/intel` certs; tests | — |
| WS3-03 | Passive / historical DNS | H | V | 100 | Wayback + OTX passive DNS providers; tests | — |
| WS3-04 | RDAP / WHOIS | H | V | 100 | `internal/whois`; TL `enrich/rdap.py` | — |
| WS3-05 | ASN / IP-range context (ip-api, RIPEstat, Team Cymru) | H | V | 100 | `internal/enrich`; cross-check reported | — |
| WS3-06 | Shodan InternetDB / CVEDB | M | V | 100 | `internal/intel`; tests | — |
| WS3-07 | Candidate vs resolved separation + source attribution/confidence | H | V | 100 | `internal/normalize` dedup+confidence; tests | — |
| WS3-08 | Historical snapshots / change detection | H | V | 100 | `internal/monitor` diff; Argus Compare page | — |
| WS3-09 | Public repo/document discovery (GitHub code search) | M | V | 100 | `providers/githubcode`; tests | — |
| WS3-10 | Per-provider caching + source health | M | V | 100 | orchestrator status; Sources table | — |

### WS4 — Active recon & authorized scanning

| ID | Capability | P | S | % | Evidence | Remaining / verification |
|---|---|---|---|---|---|---|
| WS4-01 | Authorization gate (`--authorize` / `RECONX_AUTHORIZE`) | C | V | 100 | `internal/cli/authorize.go`; tests; audited confirmation | — |
| WS4-02 | Formal scope/authorization **record** (approver, ticket, expiry, exclusions) | H | P | 50 | scope **file** matches host/CIDR in-worker (`targetInScope`); active confirm is audited | Guide wants a persisted authorization record w/ approver identity, ticket ref, start/end, exclusions. Build record + enforce from it |
| WS4-03 | DNS enumeration + wildcard detection | H | V | 100 | `internal/dns`; tests | — |
| WS4-04 | TCP connect scan (open/closed/filtered/error) | H | V | 100 | `modules/portscan`; tests | — |
| WS4-05 | Service + TLS capture | M | V | 100 | `modules/tls`; tests | — |
| WS4-06 | HTTP probing + SSRF/redirect validation | H | V | 100 | `modules/httprobe`, `modules/headers`; SSRF in net guard | — |
| WS4-07 | Technology fingerprinting (data-driven signatures) | M | V | 100 | `modules/techdetect`; tests | — |
| WS4-08 | Web content / API discovery (crawler, jsanalysis, apicapture) | M | V | 100 | `modules/*`; tests | — |
| WS4-09 | nmap integration (gated) | M | V | 100 | `modules/nmap`, `cli/nmap.go`; tests | — |
| WS4-10 | Scope-escape test coverage (private-IP redirect, rebinding) | H | V | 100 | net guard bypass tests pass | Recon-side escape cases could be broadened |
| WS4-11 | Kill switch / emergency stop for active runs | M | P | 50 | runs bounded by timeout/budget; no explicit mid-run kill switch | Add cancel/kill control + audit; test cancellation |

### WS5 — Threat intelligence ingestion & IOC management

| ID | Capability | P | S | % | Evidence | Remaining / verification |
|---|---|---|---|---|---|---|
| WS5-01 | Feed connectors (URLhaus, ThreatFox, Feodo, OpenPhish, Spamhaus, Tor, OTX, KEV, NVD, EPSS, OSV, ATT&CK) | C | V | 100 | `collect.py`, `connectors/`; live collection table in PROGRESS | — |
| WS5-02 | Connector contract (test/fetch/parse/checkpoint) + health/diagnostics | C | V | 100 | `catalog.py`, `connectors/`; `test_connectors` | — |
| WS5-03 | IOC lifecycle (first/last seen, expiry, active/expired/revoked/FP/historical) | C | V | 100 | scoring decay/expiry, migration 0007; `test_scoring` | — |
| WS5-04 | Allowlist / warning lists / suppression | H | V | 100 | `allowlist.py`; `test_allowlist`; live Tranco/CDN refresh | — |
| WS5-05 | Bulk import/export + review queue | H | V | 100 | Bulk check (500 values), Verify; `test_verify` | — |
| WS5-06 | Observable vs indicator distinction | H | V | 100 | separate `observables` + `indicators` tables | — |
| WS5-07 | Malformed-record quarantine | M | V | 100 | `intake.py`; PROGRESS "1 rejected" | — |
| WS5-08 | Feed catalog UI + custom feeds | H | V | 100 | `catalog.py`, Feeds page, `custom_feeds` (migration 0010) | — |

### WS6 — Enrichment, correlation & relationship analysis

| ID | Capability | P | S | % | Evidence | Remaining / verification |
|---|---|---|---|---|---|---|
| WS6-01 | Enrichment providers (RDAP, DNS, RIPEstat, AbuseIPDB, GreyNoise, VT, urlscan, MalwareBazaar, crt.sh) | C | V | 100 | `enrich/*`; `test_enrich`; live lookups | — |
| WS6-02 | TTL cache + quota book; provider/query-time/cache-age shown | H | V | 100 | `enrich/quota.py`, `enrichments` table; cache-hit 21–51 ms live | — |
| WS6-03 | Deterministic relationship graph with provenance | C | V | 100 | `kb/graph.py`, `relationships`; live shortest-path checks | — |
| WS6-04 | Weak-association labeling (shared hosting / CDN) | M | V | 100 | allowlist `popular-domain-host`; own-asset context | — |
| WS6-05 | ATT&CK mapping + technique pivots | H | V | 100 | `kb/attack.py`; Emotet→47 techniques live | — |
| WS6-06 | Attribution discipline (competing hypotheses, "unknown") | M | P | 50 | actors/campaigns modeled + pivots; no explicit competing-hypothesis/ACH workflow | Add hypothesis object w/ supporting+contradictory evidence; UI uncertainty |
| WS6-07 | Internal sightings correlation (SIEM/EDR) | M | V | 100 | `share/sightings.py`, Wazuh webhook; live sighting | — |

### WS7 — Attack-surface mapping & change detection

| ID | Capability | P | S | % | Evidence | Remaining / verification |
|---|---|---|---|---|---|---|
| WS7-01 | Scan diff / baseline comparison | H | V | 100 | Compare page; monitor baseline | — |
| WS7-02 | Scheduled passive monitors + alerts | H | V | 100 | `internal/monitor`, Monitors page | — |
| WS7-03 | Change grouping / alert-storm + grace period | M | P | 50 | min-severity + first-run baseline; limited grouping/suppression windows | Add change grouping + suppression windows; outage-grace tests |
| WS7-04 | Dangling DNS / takeover candidate | M | V | 100 | monitor dangling-DNS rule | — |
| WS7-05 | Email posture (SPF/DMARC/DKIM/MTA-STS) | M | V | 100 | DNS posture in `internal/intel` | — |
| WS7-06 | Lookalike / impersonation domains | M | V | 100 | `lookalike.py` (dnstwist+crt.sh+feeds); live scan | — |
| WS7-07 | Vulnerability→asset correlation (KEV/EPSS/CVSS, P1–P4) | H | V | 100 | `scoring/vulns.py`; live patch-priority distribution | — |
| WS7-08 | Threat map / geo visualization | L | V | 100 | `ThreatMap.tsx`, embedded world-atlas | — |

### WS8 — Threat analysis, attribution & prioritization

| ID | Capability | P | S | % | Evidence | Remaining / verification |
|---|---|---|---|---|---|---|
| WS8-01 | Explainable scoring (config YAML, stored breakdown, policy version) | C | V | 100 | `scoring/`, `scoring.yaml`, migration 0007; live `1.0/103eb59b` | — |
| WS8-02 | Confidence/severity/reliability/recency kept distinct | H | V | 100 | Admiralty credibility + monotonic decay | — |
| WS8-03 | Analyst cases + verdicts + notes + audit | H | V | 100 | `cases.py`, `verdicts`, `notes`, `audit_log`; `test_cases` | — |
| WS8-04 | FP feedback propagation + source weights | H | V | 100 | `scoring/feedback.py`; `test_feedback` | — |
| WS8-05 | PIR / intelligence-requirements tracking | M | V | 100 | `config/pirs.yaml`, Landscape PIR matches | — |
| WS8-06 | Trend / churn / decay / timelines | M | V | 100 | threat journey, calendar, timelines | — |
| WS8-07 | Guarded AI report extraction (grounding, injection quarantine, human review) | M | I | 75 | `ai.py`, `ai_eval.py`, ADR 0022; deterministic guard 0/288 planted. **Claude path unmeasured (no key)** | Measure LLM extraction with a key; keep off-by-default |
| WS8-08 | Automated clustering of shared infra as hypotheses | L | NS | 0 | not implemented | Design clustering (infra/temporal/cert) presenting evidence+uncertainty |

### WS9 — APIs, integrations, exports & interoperability

| ID | Capability | P | S | % | Evidence | Remaining / verification |
|---|---|---|---|---|---|---|
| WS9-01 | REST API v1 (RBAC, API keys, rate limits) | C | V | 100 | `api/v1.py`; `test_api_v1`; 401 without key | — |
| WS9-02 | STIX 2.1 export (validated) | H | V | 100 | `share/stix.py`; stix2-validator; live valid output | — |
| WS9-03 | TAXII 2.1 server (collections, pagination, TLP) | H | V | 100 | `share/taxii.py`; OASIS taxii2-client live | — |
| WS9-04 | TAXII / MISP pull as feed formats | M | V | 100 | `custom_feeds` formats taxii/misp | — |
| WS9-05 | Blocklist feed export (EDL/CSV/JSON/STIX, token) | H | V | 100 | `blocking.py`, `feed_tokens`; live export counts | — |
| WS9-06 | SIEM/sink integrations (Splunk HEC, Elastic, Sentinel, MISP, webhook) | M | I | 75 | `share/integrations.py`, `share/sinks.py`; tested vs local `scripts/sink.py`, **not real SIEMs** | Validate against a real instance of ≥1 SIEM |
| WS9-07 | Alert rules (Slack/Teams/Telegram/email/webhook) | M | V | 100 | `share/alerts.py`; live Slack delivery | — |
| WS9-08 | Detection export (Sigma/Suricata/YARA/Wazuh) | H | V | 100 | `detect/`; real `suricata -T` in CI; live generation | — |
| WS9-09 | OpenAPI docs + idempotency keys | L | P | 50 | FastAPI app exists; Swagger `/docs` removed by owner; idempotency keys not explicit | Decide on documented schema surface; add idempotency keys for creates |

### WS10 — Frontend workflows & UX

| ID | Capability | P | S | % | Evidence | Remaining / verification |
|---|---|---|---|---|---|---|
| WS10-01 | Unified Argus UI (32 pages, light/dark, auth+2FA) | C | V | 100 | `web/`; browser-verified; ADR 0013–0016 | — |
| WS10-02 | Recon workflow (new scan, progress, assets, graph, map, compare) | H | V | 100 | NewScan/ScanView/InfraGraph/ThreatMap/Compare | — |
| WS10-03 | TI workflow (verify, bulk, indicators, pivots, cases) | H | V | 100 | browser-verified DEMO walkthrough | — |
| WS10-04 | Provenance/time/confidence visible; partial-success shown | H | V | 100 | source tables + skip reasons surfaced | — |
| WS10-05 | Saved searches/views, bulk actions, drill-downs | M | V | 100 | `SavedViews.tsx`; chart drill-downs | — |
| WS10-06 | Empty states + quota/freshness display | L | V | 100 | `states.tsx`; feed health | — |
| WS10-07 | Scope/authorization visible during active runs | M | P | 50 | active gated + authorize option in New scan | Add explicit target/ports/rate **preview** + live scope panel per guide §13 |

### WS11 — Security, testing, reliability & operational readiness  ← remaining gap

| ID | Capability | P | S | % | Evidence | Remaining / verification |
|---|---|---|---|---|---|---|
| WS11-01 | AuthN/AuthZ (viewer/analyst/admin), 2FA TOTP, session binding | C | V | 100 | `auth.py`, `totp.py`, `users.py`; `test_team_security` | — |
| WS11-02 | TLP 2.0 enforcement at query/export boundaries | C | V | 100 | `tlp.py`, clearances; `test_tlp` | — |
| WS11-03 | Audit logging of security actions | H | V | 100 | `audit_log`, `logs.py`; CSV export neutralised | — |
| WS11-04 | SSRF guard + egress safety (bypass suite) | C | V | 100 | `net/guard.py`; `test_http` | — |
| WS11-05 | Blocking safety (monitor-first, four-eyes, expiry, never-block) | H | V | 100 | `blocking.py`; `test_blocking`; live four-eyes | — |
| WS11-06 | Injection defence (CSV formula, defang, size caps) | H | V | 100 | `sheet_safe`, defang; semgrep-driven fixes | — |
| WS11-07 | Unit + integration suites green | C | V | 100 | **Go exit 0 + 692 Python unit tests pass (both this session)**; Docker `alembic check` + pipeline documented | Integration suite verified via Docker in PROGRESS, not re-run here (needs Postgres/Redis) |
| WS11-08 | CI (lint/type/bandit/semgrep/trivy, suricata, web build) | H | V | 100 | `.github/workflows`; PROGRESS CI-green notes | — |
| WS11-09 | Performance (query tuning, response cache, load test) | H | V | 100 | migration 0015, `respcache.py`, `PERFORMANCE.md`; Docker 2026-10-23 | — |
| WS11-10 | **Observability** (OpenTelemetry, metrics, structured telemetry) | H | NS | 0 | **absent** (no `opentelemetry` in deps/src); only structured logs | Add OTel traces/metrics per guide §19.1; wire API+worker+connectors |
| WS11-11 | **Backup / restore** (tested recovery) | H | NS | 0 | **no backup script**; mentioned only in docs | Add pg_dump/restore + raw-store backup; run a restore test |
| WS11-12 | Security scan (ZAP baseline / DAST) | M | NS | 0 | not present | Add ZAP baseline job; triage findings |
| WS11-13 | **Worker NVD-sync stall fix** (known bug) | H | I | 75 | **Fixed 2026-10-26**: `worker.heartbeat_sleep` refreshes the heartbeat through the collector's pacing sleep, so a long paced job (NVD) stays healthy; 4 worker + 37 worker/jobs/collect tests pass, ruff+mypy clean | **Docker end-to-end verification pending**: observe the worker healthcheck stay green through a real ~15-min NVD sync. Then → Verified |
| WS11-14 | Dependency scan / SBOM / signed releases | M | P | 50 | Trivy in CI; SBOM + release signing not evident | Add SBOM generation + signed release artifacts |
| WS11-15 | v1.0.0 release (docs, versioning, tag) | H | NS | 0 | no release tag; README/docs in progress | Finalize docs, cut v1.0.0 after 11-10/11/13 land |

### WS12 — Advanced capabilities & future enhancements

| ID | Capability | P | S | % | Evidence | Remaining / verification |
|---|---|---|---|---|---|---|
| WS12-03 | Malware sandbox ingestion / isolated sample storage | L | NS | 0 | not implemented | Design isolated metadata-only ingestion; never execute on app hosts |
| WS12-04 | Detection-rule lifecycle (versioning/approval/rollback) | L | P | 50 | rules generated+validated w/ metadata; no approval/rollback workflow | Add rule review/approval + rollback + deploy audit |
| WS12-05 | Extra connectors (PhishTank, Censys, SecurityTrails, ICANN CZDS) | L | NS | 0 | not implemented (optional sources) | Add on demand behind connector contract + keys |
| WS12-06 | Dead-letter queue + replay UI | L | P | 50 | arq retries; no explicit DLQ + replay UI | Add DLQ + replay surface |

---

## 4. Critical & high-priority incomplete tasks

No **Critical** task is incomplete — every Critical capability is Verified. Incomplete **High**-priority tasks (all in WS11 + one in WS4):

| ID | Task | Status | Why it matters |
|---|---|---|---|
| WS11-13 | Worker NVD-sync stall fix | Implemented (Docker verify pending) | Fixed in code + regression tests 2026-10-26; needs one real NVD-sync run to confirm the healthcheck stays green |
| WS11-10 | Observability / OpenTelemetry | Not started | Required production telemetry (guide §19.1); needed to operate safely |
| WS11-11 | Backup / restore + tested recovery | Not started | Data-loss protection; a guide Phase-6 acceptance gate |
| WS11-15 | v1.0.0 release | Not started | Depends on 11-10/11/13 landing |
| WS4-02 | Formal scope/authorization record | Partial | Guide treats a persisted authorization record (approver, ticket, expiry) as a security control, not a UI checkbox |

---

## 5. Deferred / out-of-scope (excluded from the denominator)

These are deliberate decisions, not missing work. Reported separately per the instructions.

| Item | Guide expectation | Argus decision | Source |
|---|---|---|---|
| Multi-tenancy (`tenant_id` on every table, cross-tenant fail-closed tests) | Multi-tenant platform | **Single organization per deployment** | PLAN §3 |
| S3-compatible object storage | S3 for raw payloads/artifacts | Filesystem content-addressed store (`rawstore.py`) — functional equivalent for single host | ADR 0001 |
| Multi-tenant sharing groups / redaction | TLP-aware multi-tenant dissemination | Single-org; TLP enforced within one org | PLAN §3 |
| Graph database (Neo4j) | Optional, only if query patterns justify | Relational edge tables (`relationships`) suffice; guide §11/§18 agrees | ADR 0004 |
| OpenSearch | Optional at scale | PostgreSQL FTS + trigram (guide §18 endorses PG early) | migration 0015 |

If multi-tenancy is ever required, it becomes a Critical new workstream touching every table and query — treat as a major re-architecture, not a feature toggle.

---

## 6. Dependency bottlenecks

- **WS11-13 (worker stall)** gates confidence in all scheduled jobs and should precede telemetry work so new metrics measure a stable worker.
- **WS11-10 (observability)** is a prerequisite for meaningful SLOs and for validating **WS11-11 (backup)** and the **WS11-15 (release)** gate.
- **WS4-02 (scope record)** gates a stronger active-recon safety story but does not block TI work.
- Everything else is independent polish; no task is blocked by an external credential except **WS8-07** (needs a Claude key to *measure*, not to ship) and **WS9-06** (needs a real SIEM to *fully verify*).

---

## 7. Next recommended task (one at a time)

**WS11-13 is implemented** (code + regression tests, 2026-10-26) and needs only a Docker end-to-end confirmation (one real NVD sync with the healthcheck staying green) to reach Verified — do that whenever the Docker stack is next up.

**→ Next actionable: WS11-10 — Observability (OpenTelemetry).** It is the next High-priority item in dependency order (Group B) and now runs against a stable worker. See [`ARGUS_IMPLEMENTATION_ROADMAP.md`](ARGUS_IMPLEMENTATION_ROADMAP.md) Group B. Awaiting approval before starting.
