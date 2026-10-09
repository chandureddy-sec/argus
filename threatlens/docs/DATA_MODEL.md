# Data model

The schema comes from Alembic migrations (`migrations/versions/`). The
SQLAlchemy models are in `src/threatlens/models.py`. This page explains how the
tables fit together and why. See [ADR 0003](adr/0003-collection-pipeline-and-allowlist.md)
for the decisions.

```text
sources ─┬─< raw_documents
         ├─< connector_runs >── raw_documents
         └─< sightings >── indicators ──1:1── observables
allowlist_entries      api_keys      audit_log      app_meta
```

## Collection

| Table | One row per | Key columns | Notes |
|---|---|---|---|
| `sources` | connector | `name` (unique), licence fields, `upstream`, `reliability`, `interval_minutes`, `enabled`, `health`, `checkpoint`, `next_run_at` | Metadata is re-synced from code on every start. Runtime state (enabled, health, checkpoint) is kept. |
| `raw_documents` | distinct payload per source | `(source_id, sha256)` unique, `payload_ref`, `parse_status` | The body itself is stored gzipped under `TL_DATA_DIR`, not in the database. |
| `connector_runs` | collection attempt | `status`, `http_status`, `items_total/new/updated/rejected/allowlisted`, `error` | Raw material for health and Phase 4 feed scorecards. |

`status` values: `success`, `not_modified` (HTTP 304), `unchanged` (same
hash as a parsed document), `skipped` (missing key), `failed`.
`too_soon` and `disabled` are returned to the caller but not stored.

## Intelligence

| Table | One row per | Key columns | Notes |
|---|---|---|---|
| `observables` | normalized value | `type`, `value`, `canonical_key` (unique), `defanged`, `first_seen`, `last_seen` | `type` uses STIX names: `ipv4-addr`, `ipv6-addr`, `ipv4-net`, `ipv6-net`, `domain-name`, `url`, `email-addr`, `file-md5/sha1/sha256`, `vulnerability`, … |
| `indicators` | observable (1:1) | `status`, `confidence` 0–100, `tlp`, `labels`, `pattern` (STIX 2.1), `allowlist_reason`, `priority_score` + `score_breakdown` (Phase 4) | The platform's own assertion about the value. |
| `sightings` | (indicator, source) | `first_seen`, `last_seen`, `times_reported`, `confidence`, `labels`, `context`, `raw_document_id` | Re-ingesting updates this row and never adds one. That is what makes collection idempotent. |

Indicator `status`: `new`, `active`, `expired`, `revoked`, `false_positive`.
The allowlist sets `false_positive` together with `allowlist_reason`, and only
reverses statuses it set itself. An analyst's decision is never overwritten.

Canonical keys put case-insensitive parts in lower case (domains, URL
scheme and host, hashes) and keep case-sensitive parts as they are (URL paths).
IPs and networks are stored in compressed canonical form.

## Allowlist

| Table | Key columns | Notes |
|---|---|---|
| `allowlist_entries` | `(kind, value, origin)` unique; `kind` ∈ domain/cidr; `effect` ∈ suppress/flag; `origin` ∈ org_profile/manual/tranco/cloudflare/fastly | Automatic origins are replaced as a whole on refresh. Only `manual` entries can be edited through the API. |

## Access and audit

| Table | Key columns | Notes |
|---|---|---|
| `api_keys` | `name` (unique), `prefix` (first 10 chars, for identification), `key_hash` (SHA-256, unique), `role`, `expires_at`, `revoked_at`, `last_used_at` | The plaintext key is shown once and never stored. `last_used_at` is updated at most every 5 minutes. |
| `audit_log` | `at`, `actor`, `action`, `target`, `details` | Append-only. Actions so far: `api_key.create/revoke`, `source.run/enable/disable`, `allowlist.add/delete`. |

## Indexes worth knowing
* `observables (type, last_seen)`: the indicator list and type filter.
* `sightings (source_id, last_seen)`: the `?source=` filter and feed scorecards.
* `indicators (status, updated_at)`: active-set queries and exports.
* `connector_runs (source_id, started_at)`: the run history.
* The `pg_trgm` extension (baseline migration) is used for substring search
  on Postgres from Phase 5. Today `?q=` uses an escaped `LIKE`.
