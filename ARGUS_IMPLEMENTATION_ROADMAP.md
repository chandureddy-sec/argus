# Argus — Implementation Roadmap

Dependency-aware execution order for the **remaining** work, reconciled from
[`THREAT_INTELLIGENCE_AND_RECONNAISSANCE_BUILD_GUIDE.md`](../TEST%20FILE/THREAT_INTELLIGENCE_AND_RECONNAISSANCE_BUILD_GUIDE.md)
and the Argus phase log. Task IDs refer to
[`ARGUS_MASTER_IMPLEMENTATION_TRACKER.md`](ARGUS_MASTER_IMPLEMENTATION_TRACKER.md).

- **Reconciled:** 2026-10-26
- **Context:** The guide's build-order Phases 0–5 (foundations → passive recon → active recon → TI ingestion → enrichment/correlation) are **already Verified** in Argus. Only the guide's Phase 6 (operational maturity) and Phase 7 (advanced analytics) carry open items. So this roadmap is almost entirely **operational hardening + selected polish**, not foundational build.

---

## Guide build-order vs Argus status (mapping)

| Guide phase | Argus status | Notes |
|---|---|---|
| Phase 0 — safe foundations | ✅ Verified | WS1 complete; threat model, audit, migrations, CI |
| Phase 1 — entity/evidence + one passive workflow | ✅ Verified | WS1/WS3 |
| Phase 2 — passive recon MVP | ✅ Verified | WS3 |
| Phase 3 — active recon MVP | ✅ Verified (one gap) | WS4; **WS4-02 scope record** partial |
| Phase 4 — TI ingestion & IOC workbench | ✅ Verified | WS5/WS9 STIX/TAXII |
| Phase 5 — enrichment & correlation | ✅ Verified (one gap) | WS6; **WS6-06 attribution** partial |
| Phase 6 — attack-surface mgmt & operational maturity | 🟡 Partial | **WS11-10/11/12/14** + WS7-03 are the gap |
| Phase 7 — advanced analytics & collaboration | 🟡 Partial/Deferred | WS8-07/08, WS12 — mostly optional or deferred |

---

## Execution groups (dependency order)

### Group A — Reliability correctness (do first)
**Goal:** a trustworthy worker and scheduler before adding telemetry on top of it.
- **WS11-13** Worker NVD-sync stall fix. *(immediate next task — see below)*
- **Exit criteria:** worker emits heartbeats throughout a full NVD sync; healthcheck stays healthy; a regression test asserts heartbeat cadence during a long job.
- **Unblocks:** WS11-10 (telemetry measures a stable worker), WS11-15.

### Group B — Operational maturity (guide Phase 6)
**Goal:** meet the guide's operational-readiness acceptance gates.
- **WS11-10** Observability: OpenTelemetry traces + metrics across API, worker, connectors; expose the guide §19.1 minimum telemetry (request/latency/error, queue depth/age, per-source success + freshness, scan scope-blocks, DB pool/slow queries, backup status).
- **WS11-11** Backup/restore: scripted `pg_dump` + raw-store backup; a **restore test** that recovers entities, observations, artifacts and job state (guide Phase-6 gate).
- **WS11-14** Dependency scan/SBOM/signed releases: add SBOM generation + release signing (Trivy already present).
- **WS11-12** ZAP baseline DAST job + triage.
- **WS7-03** Change grouping + suppression windows + outage grace (prevents mass false "removed" alerts — guide Phase-6 gate).
- **Exit criteria:** telemetry visible; a restore test passes; a source-outage test produces no asset-removal flood; ZAP baseline triaged.
- **Unblocks:** WS11-15.

### Group C — Active-recon safety polish (guide Phase 3 residue)
- **WS4-02** Persisted scope/authorization record (approver identity, ticket ref, start/end, exclusions, emergency stop); enforce from the record in-worker, not only from a flag/scope-file.
- **WS4-11** Kill switch / emergency stop for in-flight active runs.
- **WS10-07** Active-run scope + target/ports/rate **preview** panel in the UI.
- **Exit criteria:** an active run cannot start without a valid authorization record; out-of-scope targets and redirects are blocked and audited against the record; a run can be stopped mid-flight; UI shows the live scope.

### Group D — Analytic depth (guide Phase 7, optional)
- **WS6-06** Attribution hypotheses (competing hypotheses, supporting/contradictory evidence, "unknown/insufficient").
- **WS8-07** Measure the guarded AI extractor with a Claude key (stays off by default).
- **WS8-08** Infrastructure clustering as evidence-backed hypotheses.
- **WS12-04** Detection-rule lifecycle (versioning/approval/rollback).
- **WS9-06** Validate ≥1 SIEM integration against a real instance.
- **Exit criteria:** each analytic claim links to evidence + uncertainty; detection content is approved/rollback-capable; one SIEM verified end-to-end.

### Group E — Release
- **WS11-15** Cut **v1.0.0**: finalize docs, bump version, tag, release notes — only after Groups A–B land.

### Deferred (not scheduled)
WS1-08 multi-tenancy, WS1-09 S3 object store, WS12-01 sharing groups, WS12-02 graph DB, WS12-03 malware sandbox, WS12-05 extra connectors, WS12-06 DLQ replay UI. See tracker §5.

---

## Milestones

| Milestone | Contains | Gate |
|---|---|---|
| M1 — Stable worker | Group A | Heartbeat holds through NVD sync |
| M2 — Operationally ready | Group B | Restore test passes; telemetry live; no alert-flood on outage |
| M3 — Active-recon hardened | Group C | Authorization record enforced; kill switch works |
| M4 — v1.0.0 | Group E (after M1–M2) | Tagged release with docs |
| M5 — Advanced analytics | Group D | Optional; post-1.0 |

---

## Immediate next task — WS11-13: worker NVD-sync stall

**What:** The arq worker stops emitting its heartbeat for the entire NVD sync (~15 min), so the Docker healthcheck flips the worker to *unhealthy* mid-job (PROGRESS 2026-10-23). The sync completes, but the container looks down and orchestration may restart it.

**Why first:** It is a concrete correctness/reliability regression with a known cause; every scheduled job's trustworthiness depends on it; and it must be fixed before telemetry (Group B) so new metrics measure a healthy baseline, and before cutting v1.0.0.

**Approach (for review — no code yet):**
1. Reproduce: run the NVD job in the Docker stack and watch heartbeat + healthcheck during the sync.
2. Root cause: confirm the NVD job holds the worker's event loop / doesn't yield to the heartbeat between paged fetches.
3. Fix options: (a) chunk the NVD sync into smaller scheduled units; and/or (b) refresh the heartbeat between API pages / await points; and/or (c) relax the healthcheck window to exceed the longest single job while still catching real stalls. Prefer (a)+(b) so the healthcheck stays tight.

**Acceptance criteria:**
- During a full NVD sync, the worker heartbeat updates at least once per healthcheck interval; the container never reports unhealthy solely due to this job.
- The NVD sync still completes with the same resulting CVE coverage.
- A regression test asserts heartbeat cadence across a simulated long-running job.

**Tests:** targeted unit/integration test for heartbeat during a long job; `go`/`pytest` suites stay green; Docker `compose up --wait` healthy with the worker running the job.

**Unblocks:** WS11-10 (observability on a stable worker), WS11-15 (release).

**Status:** awaiting your approval before any code change.
