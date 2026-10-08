# MASTER PROMPT: World-Class Threat Intelligence Platform ("ThreatLens")

> **How to use:** Open an empty repo in Claude Code (or any agentic coding tool), save this file as `PROMPT.md`, and say:
> *"Read PROMPT.md fully, write PLAN.md, then execute Phase 0. Stop after each phase."*
> Rename `ThreatLens` to whatever you like.

---

## 0. ROLE AND MISSION

You are a combined **principal CTI analyst, detection engineer, and staff backend engineer**.

Build **ThreatLens**: a self-hosted Threat Intelligence Platform (TIP) that runs the **complete intelligence cycle**:

**Direction (PIRs) → Collection → Processing → Analysis → Dissemination → Feedback**

ThreatLens must turn noisy open-source feeds into **relevant, scored, explainable, shareable intelligence** that a SOC analyst can act on in under 60 seconds.

### What "world-class" means here (acceptance bar for the whole project)
1. **Relevant:** intelligence is prioritized against an organization profile and Priority Intelligence Requirements (PIRs), not just dumped.
2. **Explainable:** every score and verdict shows its evidence and calculation breakdown.
3. **Standards-based:** STIX 2.1 data model, TAXII 2.1 sharing, MISP interoperability, TLP 2.0 enforcement, MITRE ATT&CK mapping, Sigma for detections.
4. **Trustworthy:** source reliability grading (Admiralty scale), corroboration across independent sources, decay over time, false-positive suppression.
5. **Actionable:** exports to SIEM/EDR/firewall, auto-generated detections and hunt queries, alert enrichment API for SOC workflows.
6. **Measurable:** feed quality scorecards, platform metrics, test coverage, performance numbers.
7. **Secure and ethical:** the platform treats all collected content as hostile, and collection is legal and ToS-compliant.
8. **Production-grade:** containerized, tested, typed, observable, documented, CI-gated.

---

## 1. NON-NEGOTIABLE RULES

### Ethics and legality
- Collect only from **legally accessible, ToS-compliant** sources. Respect rate limits, robots.txt, attribution, and licenses. Store the **license and redistribution terms per source**, and block exports that violate them.
- **Out of scope:** scraping criminal marketplaces or forums, buying or using leaked credentials, interacting with threat actors, running malware, or scanning third-party infrastructure by default.
- Active enrichment (anything that touches the IOC's infrastructure) is **off by default**. It is on-demand only, rate-limited, and logged.
- Never fabricate intelligence, feeds, or results. Demo data must be clearly labeled `SYNTHETIC`.

### Security (treat the platform as a target)
- **All feed content is untrusted.** Sanitize it. Never render raw HTML. Defang IOCs in the UI (`hxxp://evil[.]com`) and make "copy refanged" an explicit action.
- Every outbound fetch goes through one hardened HTTP client with **SSRF protection**: block private, loopback, link-local, and cloud-metadata ranges; re-validate after every redirect; set size and time limits; use a restricted user agent.
- Never download or execute malware samples. Use hash lookups and metadata only.
- Secrets live in environment variables or a secret store only. Never commit secrets. Add `gitleaks` to CI.
- API: authentication (API keys + JWT), RBAC (`admin`, `analyst`, `viewer`), rate limiting, input validation, audit logging, parameterized queries only, secure headers, CORS allowlist.
- Write a **STRIDE threat model of ThreatLens itself** (`docs/THREAT_MODEL.md`) and map the API to OWASP ASVS and the OWASP API Top 10.

### Engineering
- Python 3.12+, full type hints (`mypy --strict` on core), `ruff`, `pytest`, `pre-commit`, conventional commits.
- Every connector and enricher is **pluggable, idempotent, retry-safe (exponential backoff + jitter), and degrades gracefully** when its API key is missing or its quota is exhausted.
- Tests use **recorded fixtures** (`respx`/VCR). No test may need the live internet or real keys.
- **Verify before implementing:** for every external source, check the *current* official docs for endpoint, auth, rate limit, license, and schema. Do not rely on memory. Record findings in `docs/SOURCES.md` with the date checked.

---

## 2. HOW YOU WORK

1. **Start:** inspect the repo, then write `PLAN.md` (architecture, assumptions, risk register, phase timeline). Then begin Phase 0.
2. **Decide and move:** when something is ambiguous, pick the best option, record it as an ADR in `docs/adr/`, and continue. **Stop and ask only for:** paid services, secrets you can't generate, destructive actions, or legal doubt.
3. **After every phase, STOP and deliver:**
   - What was built (5 lines max)
   - How to run and verify it (exact commands + expected output)
   - Test, lint, and type-check results (real output, never claimed)
   - `docs/learn/phase-N.md`: **Concept → Why it matters → How it works here → Hands-on exercise → Common mistakes**
   - Known limitations and the next phase
4. Keep `docs/PROGRESS.md` updated. Never mark a phase done with failing tests.
5. Prefer boring, proven tech over clever. Small, reviewable commits.

---

## 3. ARCHITECTURE AND STACK (defaults; change only via ADR)

| Layer | Choice |
|---|---|
| API | FastAPI + Pydantic v2, async (`httpx`) |
| DB | PostgreSQL 16 + SQLAlchemy 2 + Alembic (JSONB for raw/STIX payloads) |
| Queue / cache | Redis + `arq` (or Celery) for jobs; Redis for enrichment cache and rate-limit buckets |
| Scheduler | Per-connector schedules with jitter, checkpoints, ETag / If-Modified-Since |
| Search | PostgreSQL FTS + trigram first; OpenSearch optional later |
| Graph | `relationships` edge table + NetworkX for analysis; Neo4j only if justified by ADR |
| STIX / sharing | `stix2`, `taxii2-client`, `medallion` (TAXII 2.1 server), `pymisp` |
| Detections | `pySigma` + backends, YARA, Suricata rule templating |
| UI | Server-rendered (Jinja2 + HTMX + Chart.js) for solo maintainability; a React SPA is not required |
| Ops | Docker Compose, Prometheus metrics, structlog JSON logs, `/healthz` + `/readyz`, OpenTelemetry optional |
| CI | GitHub Actions: ruff, mypy, pytest + coverage, bandit, semgrep, pip-audit, gitleaks, Trivy (image), SBOM (CycloneDX) |

**Pipeline:**
`Connector → raw archive → parser → extractor/normalizer → allowlist/FP filter → dedup/merge → enrichment → scoring → correlation/graph → API/UI/exports/alerts`

---

## 4. DATA MODEL (minimum)

Use STIX 2.1 as the interchange model. Internally, store typed tables plus the original STIX JSON.

- `sources` (name, type, reliability A–F, license, redistribution_allowed, tlp_default, health, last_success, schema_version)
- `raw_documents` (source_id, fetched_at, hash, payload_ref, parse_status). Retain for reprocessing.
- `observables` (type, normalized_value, canonical_key UNIQUE, first_seen, last_seen, sightings_count, defanged_display)
- `indicators` (observable_id, pattern, valid_from/until, confidence, priority_score, score_breakdown JSONB, tlp, status: `new|active|expired|revoked|false_positive`, labels)
- `sightings` (indicator_id, source_id, seen_at, context JSONB)
- `entities`: `threat_actors`, `malware`, `campaigns`, `tools`, `vulnerabilities`, `attack_patterns` (ATT&CK), `reports`, `identities`
- `relationships` (src, rel_type, dst, confidence, source_id, first_seen/last_seen)
- `enrichments` (observable_id, enricher, result JSONB, fetched_at, ttl, cost)
- `org_profile`, `pirs`, `assets` (domains, IP ranges, brands, tech stack/CPE, vendors, sectors, geography)
- `cases`, `case_items`, `notes`, `verdicts` (analyst TP/FP feedback), `audit_log`
- `feed_metrics` (per source per day: items, new, duplicates, overlap, FP rate, latency)

Indexes and constraints: justify each in `docs/DATA_MODEL.md`. Include an ER diagram (Mermaid).

---

## 5. PHASE PLAN

### Phase 0: Foundation
- Repo layout, Docker Compose (api, worker, db, redis), config system, Alembic baseline, CI pipeline, pre-commit, logging, health endpoints.
- `org_profile.yaml` and `pirs.yaml` with a worked example (see §9). Loader plus validation.
- `docs/THREAT_MODEL.md`, `docs/SOURCES.md` skeleton, ADR 0001 (stack).
- **Accept:** `docker compose up` gives a healthy stack; CI green; `make test` passes.

### Phase 1: Collection and Processing core
- Connector framework (base class, registry, scheduler, checkpointing, hardened HTTP client, source health).
- IOC extractor for free text: IPv4/IPv6, domain, URL, email, MD5/SHA1/SHA256, CVE, file name, registry key. Validate with `ipaddress`, `tldextract`, checksums, and defang/refang handling.
- Normalization, bogon/private filtering, **allowlist engine** (Tranco top-N, CDN/cloud ranges, own assets, manual allowlist), dedup and merge by `canonical_key`.
- First connectors (verify each first): **CISA KEV, abuse.ch URLhaus, ThreatFox, Feodo Tracker, AlienVault OTX, Spamhaus DROP, Tor exit list, OpenPhish community**.
- **Accept:** 5+ live-capable connectors with fixtures; re-running ingestion creates zero duplicates; allowlisted domains never become active indicators; source-health page/endpoint works.

### Phase 2: Knowledge base
- Ingest **MITRE ATT&CK** (Enterprise, Mobile, ICS) from the official STIX data. Support version updates and diffing.
- Vulnerability intel: **NVD (API 2.0) + EPSS + CISA KEV + GitHub Advisories/OSV**. Normalize CVSS, CWE, CPE, and exploit/PoC signals.
- Relationship graph: indicator ↔ malware ↔ actor ↔ campaign ↔ technique ↔ CVE.
- **Accept:** query "show all techniques linked to malware X"; CVE records carry KEV and EPSS flags; graph traversal API returns paths with provenance.

### Phase 3: Enrichment engine
- Pluggable enrichers with TTL caching, quota tracking, and cost awareness: RDAP/WHOIS, DNS (A/AAAA/MX/NS/TXT), ASN and geo (MaxMind GeoLite2), reputation (AbuseIPDB, GreyNoise Community, VirusTotal, URLScan, MalwareBazaar), certificate transparency (crt.sh), Pulsedive (optional).
- Passive-first policy. Active enrichment requires an explicit flag, is rate-limited, and is audited.
- Endpoints: `GET /api/v1/lookup/{type}/{value}` and `POST /api/v1/enrich` (bulk, SOC-alert-friendly: returns verdict, score, evidence list, related entities, recommended action).
- **Accept:** single lookup returns in under 2 s on cache hit; quota exhaustion degrades to partial results with clear `skipped_reason`; every enrichment is stored with provenance.

### Phase 4: Scoring, trust, and feedback
Implement the model in §7. Requirements:
- Configurable in YAML, with a unit-tested scoring function.
- Store the full `score_breakdown` per indicator and show it in the UI/API.
- **TLP 2.0** enforcement on every read/export path (CLEAR, GREEN, AMBER, AMBER+STRICT, RED).
- Analyst TP/FP feedback adjusts source weights and per-indicator status. Log every adjustment.
- Daily expiry job (decay + `valid_until`).
- **Accept:** property-based tests (Hypothesis) show monotonic decay and bounded scores; an AMBER indicator is never returned to a viewer without clearance or sent to a non-permitted sink.

### Phase 5: Analyst experience
- Dashboard: ingestion health, top new high-priority IOCs, PIR matches, trending actors/malware/CVEs, ATT&CK heatmap, KEV-vs-our-stack panel.
- IOC page: summary verdict, score breakdown, timeline of sightings, enrichment cards, relationship graph (pivot), related reports, ATT&CK techniques, notes, TP/FP buttons.
- Search (value, tag, actor, CVE, technique), saved queries, bulk lookup (paste 500 IOCs → table + CSV).
- Cases/investigations with evidence items and export to Markdown/PDF.
- **Accept:** a first-time analyst can go from alert IOC to a documented verdict in under 60 s (record the walkthrough in `docs/DEMO.md`).

### Phase 6: Dissemination
- **STIX 2.1** bundle export and **TAXII 2.1** server (collections per TLP/confidence tier).
- **MISP**: push and pull (events/attributes mapping documented).
- Blocklist exports with confidence thresholds: plain text, CSV, JSON, and firewall External Dynamic List format. Respect license and TLP.
- SIEM/SOC integrations: **Wazuh** (CDB list generation + enrichment webhook), **Splunk HEC**, **Elastic/OpenSearch** bulk, **Microsoft Sentinel** threat-indicator upload.
- Alerting (Slack/Teams/Telegram/email): rule-based on PIR match, KEV + asset match, or score ≥ threshold. Deduplicated and rate-limited.
- **Accept:** exported STIX validates with the `stix2-validator`; a second ThreatLens or MISP instance can consume the TAXII feed; each integration has a documented, runnable demo.

### Phase 7: Detection engineering
- From indicators: generate **Sigma** rules (and compile via pySigma to SPL, KQL, Elastic, and Wazuh), **Suricata** rules (domains/IPs/JA3 where available), and **YARA** stubs from hash/string intelligence where licensed and appropriate.
- From TTPs: **hunt query templates** per technique for multiple SIEMs, each with data-source requirements and false-positive notes.
- **ATT&CK Navigator layer export** for any actor/malware/campaign/report, and **coverage-gap analysis** comparing the org's imported Sigma/detection inventory against the techniques most relevant to its PIRs.
- **Retro-hunt hook:** when a new high-priority IOC arrives, emit a query pack to run against historical logs.
- **Accept:** every generated rule passes syntax validation and includes metadata (author, date, references, ATT&CK tags, confidence, FP notes).

### Phase 8: Intelligence products and guarded AI assist
- Scheduled products: **daily threat brief, weekly CTI report, vulnerability priority list, executive one-pager** (HTML + PDF), generated from stored data with citations to source records.
- Brand/lookalike monitoring: CT logs + `dnstwist` permutations for the org's domains (passive checks only).
- **Optional AI module** (Claude API or local model), strictly guardrailed:
  - Summarize reports and extract TTPs/IOCs into **structured output**.
  - Every extracted IOC is **validated against the source text**. Anything not literally present is rejected.
  - Feed text is passed as **delimited untrusted data**. The model has **no tools and no side effects**. Output is a draft requiring analyst approval.
  - Log prompt, model, and output hash. Include a prompt-injection test suite (malicious feed text that tries to override instructions).
- **Accept:** briefs regenerate deterministically from data; AI extractions show ≥ the documented precision on a labeled test set of 30+ reports (create it, report the real numbers, and don't inflate them).

### Phase 9: Hardening and release
- Load test (target: ≥ 100 lookups/s cached on a laptop; document actual numbers). Query/index tuning with `EXPLAIN ANALYZE` evidence.
- Observability: Prometheus metrics (ingest lag, items/sec, enrich latency, quota burn, queue depth) and a Grafana dashboard JSON.
- Backup/restore script, data-retention policy, upgrade/migration test.
- Security review against `docs/THREAT_MODEL.md`: run ZAP baseline against the API, fix findings, document residual risk.
- Docs: README with architecture (Mermaid), quickstart, `docs/OPERATIONS.md`, `docs/INTEGRATIONS.md`, ADR index, a 5-minute demo script, and a CHANGELOG. Tag `v1.0.0`.
- **Accept:** fresh clone → working demo in under 10 minutes following the README only.

---

## 6. SOURCE CATALOG (starting list; verify each one's current terms first)

| Category | Sources |
|---|---|
| Malware/C2/IOC | abuse.ch (URLhaus, ThreatFox, MalwareBazaar, Feodo, SSLBL), AlienVault OTX, CIRCL OSINT feed (MISP), Pulsedive |
| Network reputation | Spamhaus DROP/EDROP, Blocklist.de, CINS Army, Tor exit list, GreyNoise Community, AbuseIPDB |
| Phishing | OpenPhish community, URLScan.io |
| Vulnerabilities | CISA KEV, NVD, FIRST EPSS, GitHub Advisories, OSV |
| Knowledge | MITRE ATT&CK (STIX), MITRE CAPEC (optional) |
| Advisories/reports (RSS/Atom) | CISA, CERT-In, Microsoft MSRC, Cisco Talos, Google/Mandiant, Unit 42, Check Point Research, ESET WeLiveSecurity, The DFIR Report |
| Ransomware tracking | ransomware.live (public API, verify terms) |
| Context | Tranco ranking (allowlist), MaxMind GeoLite2, crt.sh, RDAP |

Per-source record in `docs/SOURCES.md`: URL, auth, rate limit, license, update cadence, schema notes, reliability grade and rationale, date verified.

---

## 7. SCORING SPEC (v1; configurable, document the rationale, calibrate with feedback)

```
priority = clamp(0, 100,
    base_confidence
  × source_reliability_weight
  × decay(age_days, half_life[type])
  + corroboration_bonus
  + relevance_bonus
  − fp_penalty )
```

- `base_confidence`: from the feed (STIX 0–100) or a per-source default.
- `source_reliability_weight` (Admiralty source grade): A=1.00, B=0.85, C=0.70, D=0.50, E=0.30, F=0.20. Information credibility 1–6 is stored and can modify the weight.
- `decay`: `0.5 ** (age_days / half_life)`. Starting half-lives: IP 10 d, URL 7 d, domain 30 d, file hash 180 d. Tunable per type.
- `corroboration_bonus`: +8 per **additional independent** source (mirrors and re-publishers of the same upstream do not count), capped at +24.
- `relevance_bonus` (0–20): PIR match on sector, geography, tech stack/CPE, brand, vendor, or asset overlap.
- `fp_penalty`: allowlist hit, Tranco top-10k, shared CDN/cloud range, prior analyst FP, or a stale/dead sinkholed host.
- Vulnerabilities use a separate model: **KEV = critical floor**, EPSS percentile, CVSS, public exploit/PoC, internet exposure, asset/CPE match → a `patch_priority` of P1–P4 with the reasoning shown.
- Every score stores its full breakdown and the config version used.

---

## 8. QUALITY GATES

- Unit and integration tests; **≥ 85% coverage on core logic** (extractor, normalizer, dedup, scoring, TLP, SSRF guard).
- Property-based tests for the extractor, defang/refang round-trip, and scoring bounds.
- Contract tests for every connector against fixtures, plus a "schema drift" test that fails loudly when a feed changes format.
- Security tests: SSRF bypass attempts (DNS rebinding, redirects, decimal/octal IPs), XSS payloads in IOC fields, SQLi in search, TLP bypass attempts, and the AI prompt-injection suite.
- Feed scorecards (`feed_metrics`): uniqueness, overlap, timeliness, FP rate, and cost. Surface these in the UI and use them to justify keeping or dropping each feed.
- CI must pass on every PR. No phase closes with red CI.

---

## 9. EXAMPLE ORG PROFILE AND PIRs (use as a template; ask me to replace with real values)

```yaml
org:
  name: "Example Corp (SYNTHETIC)"
  sectors: [it_services, fintech]
  geography: [IN, US, SG]
  domains: [example.com, example.in]
  brands: ["Example Corp", "ExamplePay"]
  ip_ranges: ["203.0.113.0/24"]          # documentation range
  vendors: [microsoft, cisco, fortinet, palo_alto, vmware, atlassian]
  tech_stack:
    - { product: "Windows Server 2022", cpe: "cpe:2.3:o:microsoft:windows_server_2022:*" }
    - { product: "FortiGate",           cpe: "cpe:2.3:o:fortinet:fortios:*" }
    - { product: "Apache Tomcat",       cpe: "cpe:2.3:a:apache:tomcat:*" }
pirs:
  - id: PIR-1
    question: "Which ransomware groups are actively targeting our sectors and geographies, and what are their initial-access techniques?"
    watch: { sectors: [it_services, fintech], techniques: [T1190, T1078, T1566] }
  - id: PIR-2
    question: "Which newly exploited vulnerabilities affect products in our stack?"
    watch: { sources: [cisa_kev, epss], match: tech_stack }
  - id: PIR-3
    question: "Is our brand or domain being impersonated for phishing?"
    watch: { match: [domains, brands], sources: [ct_logs, openphish, urlscan] }
```

---

## 10. FINAL DELIVERABLES

1. Working repo at `v1.0.0` with all acceptance criteria demonstrably met.
2. `docs/`: ARCHITECTURE, DATA_MODEL, THREAT_MODEL, SOURCES, OPERATIONS, INTEGRATIONS, DEMO, ADRs, and `learn/phase-0..9.md`.
3. A **final report** containing: feature matrix vs. this prompt (done / partial / not done, each with an honest reason), real test/coverage/perf numbers, feed scorecards, known limitations, and a prioritized roadmap.
4. A **portfolio write-up** (`docs/PORTFOLIO.md`): problem, architecture diagram, design decisions and trade-offs, screenshots list to capture, and 5 resume-ready bullet points based **only on what was actually built and measured**.

Begin now: inspect the repo, write `PLAN.md`, then execute **Phase 0** and stop for review.
