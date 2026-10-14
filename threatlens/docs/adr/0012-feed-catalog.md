# ADR 0012: Feed catalog and custom feeds

Date: 2026-10-14 · Status: accepted

## Context
Step 3 of making ThreatLens work like the SOC platform the user knows: a feed catalog where an
admin switches sources on and off, pulls one now, syncs everything, sees where each feed comes
from and what it has contributed, and adds a feed of their own (URL, plain text / CSV / JSON,
indicator type, verdict, confidence, schedule, TLP, comment marker, value column, optional API
key and header) without writing a connector.

## Decisions

### 1. A custom feed is data, run by the ordinary pipeline
`custom_feeds` (migration 0010) holds how to fetch and read the feed; its `sources` row holds the
title, schedule, marking, reliability, health and run history like any built-in feed.
`connectors.custom.connector_for(spec)` turns the row into a normal `Connector` class, so a custom
feed gets everything a built-in one does: the hardened client (http(s) only, no private or
internal addresses, redirects re-checked, 20 MB cap), conditional GET, the raw archive,
normalization (bad, bogon and documentation values rejected and counted), the allowlist, dedup,
scoring and run history. `Collector.run` and `Collector.due` look custom names up in the database;
nothing is registered at import time.

* **Name**: `custom_<slug of the title>`, unique, never a built-in name.
* **Reading**: text = first token per line (space, comma, `;` or `|` separated), lines starting
  with the comment marker skipped and trailing comments cut; CSV = the delimiter is sniffed among
  `, ; tab |`, the value is the 0-based column; JSON = a list of strings, or objects with the value
  at a dotted path (lists on the way are walked). A document with content but no values is schema
  drift (the feed shows "failing" with "check the format and column/field").
* **Type**: "detect each value", or a family (IP / domain / URL / hash). With a family, a value of
  another kind is checked as that family and so rejected with a reason, never silently retyped.
* **Verdict**: "malicious" feeds produce malicious signals; "suspicious" ones get the source kind
  `custom-suspicious`, which scoring treats like the anonymizer lists (suspicion, never a
  malicious verdict on their own).
* **Trust**: the admin grades reliability A-F (default C); score = confidence x reliability
  weight x decay, as for every feed (ADR 0008). The original producer (default `custom:<host>`)
  keeps a mirror of a feed we already pull from counting twice when corroborating.
* **Pace**: every 15 minutes to 7 days; never faster than 5 minutes even on "Pull now".

### 2. Feed keys are encrypted, never shown again
Unlike passwords and feed-export tokens, a feed's API key must be sent onward, so it can't be
hashed. `threatlens.vault` encrypts it with Fernet under a key derived (HKDF-SHA256) from
`TL_SECRET_KEY`. Without `TL_SECRET_KEY` a key is refused rather than stored in clear. If the
secret changes, the feed's pulls are recorded as "skipped: enter it again". The key is never put
back in a page; an empty key field on edit keeps it, a checkbox removes it. Audit entries record
`secret_set`, never the value. URLs with credentials in them are refused (use the header fields).

### 3. Catalog actions
* **Switch on/off** (any source, lookup providers included): a switched-off feed keeps what it
  reported and stops pulling; switching on makes it due at once. Lookup providers re-read their
  switches every 30 s, so the worker and API pick changes up without a restart.
* **Pull now / Sync all feeds**: queue the worker job per source (fixed job id: a second press
  while queued is a no-op, reported as "already queued"). The source's own minimum gap still
  applies; a run that comes too soon is recorded as "too soon".
* **Remove** (custom feeds only; built-in ones can only be switched off): deletes the feed, its
  run history, raw-document rows and sightings; indicators that only it reported are revoked
  (unless an analyst gave a verdict) and everything it reported is re-scored.
* **Source page**: provenance (address, producer, grade, marking, how it is read), terms, health,
  the last 60 pulls (chart of new indicators per pull + table), and its contribution within the
  reader's TLP clearance: total, active/expired/not malicious, only-here vs corroborated, by type,
  top active indicators.

All changes need the admin role and a same-site POST (UI) or an admin API key
(`POST /api/v1/sources/sync`, `PATCH /api/v1/sources/{name}`, `POST|PUT|DELETE
/api/v1/sources/custom[/{name}]`); `GET /api/v1/sources/{name}/contribution` needs a viewer key.
Audited as `source.enable|disable|sync`, `custom_feed.create|update|delete`.

## Consequences
* Admins can add feeds whose terms ThreatLens hasn't checked. The form says so ("your own terms
  with the provider"); custom feeds are marked no-redistribution, so nothing they report is
  re-published beyond the blocklist an analyst approves.
* Internal feeds on private addresses can't be added (the SSRF guard applies to every fetch).
  Serve them on a public address with a key, or extend the guard deliberately.
* New dependency: `cryptography` (Fernet, HKDF).
