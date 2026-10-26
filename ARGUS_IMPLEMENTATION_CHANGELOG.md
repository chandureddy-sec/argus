# Argus — Implementation Changelog

Historical record of reconciliation and implementation activity. Newest first.
Task IDs refer to [`ARGUS_MASTER_IMPLEMENTATION_TRACKER.md`](ARGUS_MASTER_IMPLEMENTATION_TRACKER.md).

---

## 2026-10-26 — WS11-13 worker NVD-sync stall fix

- **Changes made:** Added `worker.heartbeat_sleep(ctx)` — a pacing-sleep wrapper that refreshes the worker heartbeat (throttled to once per `HEARTBEAT_REFRESH_EVERY_S`=60 s, Redis errors logged not raised) — and wired it into the collector via `open_collector(s, sleep=…)` in `startup`, with `ctx["last_beat"]` seeded. Extracted `_beat()` and `HEARTBEAT_TTL_S`. A long paced job (the NVD sync paces 6.5 s/request for ~15 min) now keeps the heartbeat fresh even while the 5-min heartbeat cron is starved, so the worker healthcheck no longer flips to *unhealthy* mid-sync. The tight 600 s healthcheck window was left unchanged (it still catches a genuinely wedged worker).
- **Files modified:** `threatlens/src/threatlens/worker.py`, `threatlens/tests/test_worker.py`.
- **Tests executed + actual outcome:** `pytest tests/test_worker.py` → **4 passed**; `pytest tests/test_worker.py tests/test_jobs.py tests/test_collect.py` → **37 passed**; `ruff check` → clean; `ruff format --check` → clean; `mypy` → no issues. Full unit suite re-run: **694 passed, exit 0** (692 baseline + 2 new worker tests).
- **Status transition:** WS11-13 **In progress (25%) → Implemented (75%)**. Not marked Verified: the acceptance criterion "healthcheck stays green through a real ~15-min NVD sync" needs a Docker end-to-end run, not available this session.
- **Progress impact:** weighted 90.3% → **90.9%**; WS11 70% → 73%.
- **Decisions:** Chose the `sleep` injection seam (approach b) over chunking the NVD job (approach a) or relaxing the healthcheck window — it is minimal, uses an existing test seam, ties liveness to real job progress, and covers every paced job, not just NVD.
- **Remaining:** Docker verification of the healthcheck during a real NVD sync → then Verified.

---

## 2026-10-26 — Reconciliation & tracker creation (no code changes)

**Task:** Reconcile the external build guide with the Argus implementation; create the master tracker, roadmap and this changelog. Assessment only — **no application code modified.**

**Sources read:**
- `E:\TEST FILE\THREAT_INTELLIGENCE_AND_RECONNAISSANCE_BUILD_GUIDE.md` (1,376 lines, full).
- Argus: `README.md`, `docs/RECONX.md`, `threatlens/PLAN.md`, `threatlens/docs/PROGRESS.md`, 22 ADRs, `models.py`, migrations, `web/` page/component listing.

**Evidence gathered (run this session):**
- `go test ./...` → **all 37 test packages pass, exit 0.**
- `uv run pytest --ignore=tests/integration` → **692 passed, exit 0** (5m13s).
- Code inspection confirming design decisions and gaps:
  - `tenant_id` → **0 occurrences** (single-org, by design — PLAN §3).
  - No `boto3`/`minio`/S3 → raw store is filesystem content-addressed (`rawstore.py`).
  - No `opentelemetry` in deps or source → **observability not started.**
  - No backup/restore script in `threatlens/scripts/` → **backup not started.**
  - Recon scope gate is `--authorize`/`RECONX_AUTHORIZE` + optional scope **file** (`internal/cli/authorize.go`), not a persisted authorization record.
  - Data model: 40+ ORM tables, migrations 0001→0015.

**Files created:**
- `ARGUS_MASTER_IMPLEMENTATION_TRACKER.md`
- `ARGUS_IMPLEMENTATION_ROADMAP.md`
- `ARGUS_IMPLEMENTATION_CHANGELOG.md`

**Result / status transitions:**
- Normalized 99 included tasks across 12 workstreams + 4 deferred items.
- **Weighted progress 90.3 %**; **raw Verified 79.8 %** (79/99).
- All Critical tasks Verified. Remaining gap concentrated in WS11 (operational readiness): observability, backup/restore, worker NVD-stall bug, v1.0.0; plus partials WS4-02, WS6-06, WS7-03, WS8-07, WS9-06, WS10-07.

**Decisions / deviations recorded (from existing ADRs, not new):**
- Single-org (no multi-tenancy), filesystem raw store, PostgreSQL FTS over OpenSearch, relational edges over a graph DB — all excluded from the progress denominator as deliberate design.

**Next task selected:** **WS11-13 — worker NVD-sync stall fix** (dependency-first; unblocks observability and release). Awaiting approval before code changes.

**Blockers:** none for WS11-13. External-credential verification gaps (WS8-07 Claude key, WS9-06 real SIEM) affect measurement/verification only, not shipping.

---

<!-- Template for implementation entries (one per verified task):

## YYYY-MM-DD — <TASK-ID> <short title>
- **Changes made:** …
- **Files modified:** …
- **Tests executed + actual outcome:** …
- **Status transition:** <old> → <new> (evidence: …)
- **Decisions / blockers / deviations:** …
-->
