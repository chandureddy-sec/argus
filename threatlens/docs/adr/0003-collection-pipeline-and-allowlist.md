# ADR 0003 — Collection pipeline, deduplication and the allowlist

Date: 2026-10-09 · Status: accepted

## Context
Phase 1 turns public feeds into indicators. Four forces shape it:
* Feeds are **hostile input**. They are written by people who track
  adversaries, and they carry adversary-controlled strings: URLs, domains,
  free-text tags.
* Feeds **overlap and repeat**. The same IP turns up in several feeds, and the
  same feed republishes it every hour.
* Feeds **change format and terms** without notice, as BGPView's API did under ReconX.
* Feeds include **popular and shared infrastructure** (github.com, CDN edge
  IPs, our own domains). Blocking it would hurt us more than the threat would.

## Decision
1. **One hardened HTTP client** (`net/http.py`) for every outbound request:
   HTTPS-only by default; a connect-time SSRF guard on resolved addresses,
   re-checked on every redirect; size and time caps; retries with backoff,
   jitter and `Retry-After`; conditional GET (ETag / Last-Modified).
2. **Raw-first.** Every fetched body is archived, gzipped and content-addressed
   (`data/<source>/<sha256>.gz`), before it is parsed. A parser bug can be
   fixed and the stored documents reprocessed without fetching them again. An
   identical body is recognised by hash and not parsed twice (`unchanged`).
3. **Data model: observable → indicator → sightings.**
   * `observables`: one row per normalized value, unique by a canonical key.
   * `indicators`: one per observable; the platform's own assertion (status,
     confidence, TLP, STIX pattern).
   * `sightings`: one per (indicator, source). Re-ingesting updates
     `last_seen` and `times_reported` and adds no rows.
   * Inserts use `ON CONFLICT DO NOTHING` followed by a read, so two sources
     ingesting the same IP at once neither fail nor duplicate.
4. **Normalization rejects early**: bogon, private and reserved IPs; internal
   or bare-suffix domains; malformed hashes. Rejections are counted per reason
   on the run, never silently dropped.
5. **Allowlist with two effects**:
   * `suppress`: the indicator is stored with status `false_positive` and an
     `allowlist_reason`, but never goes active. Applies to our own assets,
     manual entries, and Tranco top-N registrable domains.
   * `flag`: the indicator stays active with a warning label. Applies to CDN
     edge ranges, and to URLs and emails *hosted on* a popular domain.
     Malware on github.com is still malware.
   * Tranco matches the private-aware registrable domain, so
     `user.github.io` is not hidden by `github.io`.
   * Any allowlist change re-evaluates every indicator, so adding or removing
     an entry is reversible.
   * A failed or empty refresh of a public list **keeps the previous entries**.
     A Tranco outage must not turn google.com into an active indicator.
6. **Per-source contract** (`SourceInfo`): licence and its URL, commercial and
   redistribution flags, attribution, the upstream producer (for
   corroboration), reliability grade, default confidence, interval, and a
   **minimum gap** that only an explicit `--force` can override.
   Missing keys mark the source `skipped`, not failing. Schema drift fails the
   run, marks the raw document `failed`, and degrades the source's health.
7. **Scheduling**: an arq cron tick queues one job per due source with job id
   `collect:<name>`. The API trigger uses the same id, so a source is never
   queued twice. `keep_result=0` makes sure a finished job doesn't block the
   next trigger.
8. **API auth arrives with the first data routes**: SHA-256-hashed API keys
   (256-bit random, shown once), ordered roles viewer < analyst < admin,
   per-key fixed-window rate limits (Redis), and an audit log for
   every state-changing call.

## Alternatives considered
* *Indicator per (value, source)*: simpler upserts, but every query then needs
  a GROUP BY, and corroboration has to be computed at read time.
* *Drop allowlisted values entirely*: smaller tables, but an analyst can't see
  that a feed reported google.com. That's the evidence that the feed is noisy,
  and Phase 4 feed scorecards need it.
* *Celery*: heavier than needed; arq is asyncio-native (ADR 0001).

## Consequences
* Storage grows with raw documents. Retention is a Phase 9 concern; today's
  footprint is small (≈1.5 MB for a full collection of all sources).
* SQLite works for tests and trials. The ingest of the 33 k-row URLhaus dump
  takes ≈80 s on SQLite, and Postgres is the deployment target.
* Licence flags are recorded now, so Phase 6 exports can enforce them
  without a migration.
