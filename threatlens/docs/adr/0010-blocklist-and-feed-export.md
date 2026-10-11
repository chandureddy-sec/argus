# ADR 0010: Blocklist, never-block guard and feed export

Date: 2026-10-11 · Status: accepted · Pulls part of Phase 6 (blocklist exports) forward

## Context
The user asked ThreatLens to work like the threat-intel module of the SOC platform they use at work:
verify an indicator, decide, and *act* on it, not only read about it. That module blocks IPs on
endpoint firewalls through its own agents. ThreatLens has no agents. The user chose (2026-10-11):
**"Block" puts a value on a managed blocklist that firewalls pull**, and allowed self-hosted
JavaScript in the UI for the interactive steps that follow (decided in the UI ADR for that step).

## Decisions

### 1. A block is a published list entry, in two modes
* `monitor`: recorded only, a dry run. Nothing pulls it.
* `enforce`: published at the feed export URL.

A new block is always `monitor`. Promoting it needs a **request and an approval by a different
admin** (four eyes). An admin may switch the rule off in Settings (a sole admin needs that); then
an admin's request enforces at once, and an analyst's still waits for an admin.

### 2. Every block expires; nothing is deleted
The duration depends on why the value is blocked:

| reason | when | default |
|---|---|---|
| `known_bad` | an active indicator the actor can read scores at least the known-bad score (60) | 30 days |
| `manual` | typed into the blocklist, not known bad | 30 days |
| `suspect` | anything else (an unknown value from a lookup, a low-scoring indicator) | 6 days |

Lifting ends a block early; extending pushes the expiry out. Rows stay for history and audit
(`block.create`, `block.request_enforce`, `block.enforce`, `block.decline`, `block.lift`,
`block.extend`). An indicator above the actor's clearance is treated as unknown, so blocking a
value reveals nothing about intelligence the actor may not read.

### 3. The never-block guard is checked twice
When a block is made **and** on every export (so a value made "ours" after it was enforced drops
out of the feed on the next pull). Refused:
* addresses that are not globally routable (private, loopback, link-local, CGNAT, multicast,
  documentation, reserved);
* ranges broader than /16 (IPv4) or /32 (IPv6), and ranges reaching a refused address;
* well-known public DNS resolvers;
* our own assets imported from ReconX (and, for a domain, any of our hosts under it);
* every allowlist entry: `org_profile` domains and ranges, `manual` entries, Tranco popular
  domains, Cloudflare and Fastly edge ranges.

A URL is refused only when its host is ours or non-global: a malicious URL on a popular site is
still blockable at URL level. "Never block" entries added in the UI are allowlist entries with
effect `flag`: indicators on them stay visible and labelled, so a compromise of our own host is
still noticed.

### 4. The feed export
`GET /feeds/{token}/{format}`, formats `ip.txt`, `domain.txt`, `url.txt` (bare values, one per
line: the External Dynamic List shape Palo Alto, Fortinet and Check Point read; URLs without a
scheme), `blocks.csv`, `blocks.json` and `stix.json` (a STIX 2.1 bundle of `indicator` objects with
the spec's TLP marking definitions; AMBER+STRICT maps to AMBER plus `x_threatlens_tlp`).

* **Token in the path**, because firewall EDL clients cannot send custom headers. Tokens are
  `tlf_` + 32 random bytes, shown once, stored as SHA-256, one per device so each can be revoked
  alone. A wrong, revoked or malformed token is a plain 404.
* The request log rewrites the path to `/feeds/<token>/…`; uvicorn's access log is off.
* Pulls are rate-limited per client address (60/min) and served `Cache-Control: no-store`.
* **TLP**: only blocks at or below the export limit (default TLP:AMBER+STRICT, a firewall being
  inside the organisation) are published. TLP:RED is never exported.
* **Licences**: publishing to our own firewalls is internal use, not redistribution, so feeds
  without redistribution rights (Spamhaus DROP) may back an enforced block. Sharing the list with
  another organisation (Phase 6 TAXII/MISP) must re-check `Source.redistribution`.

### 5. Policy is data, edited in the UI
`app_settings` holds one JSON document per key (`blocking`), validated on save (durations 1–365
days, score 0–100, export limit at most AMBER+STRICT) and audited as `settings.update` with a
before/after diff.

## Not done here (needs a SIEM or agents)
Auto-block from alerts, "keep blocking while attackers keep trying", per-endpoint enforcement and
"blocked on" status. They need sightings from the environment, which a later step can accept
over the API.

## Consequences
* Migration 0009 adds `blocks`, `app_settings`, `feed_tokens`.
* `/api/v1/blocks` (viewer reads, analyst blocks/requests/lifts, admin approves) lets other tools
  block programmatically; the UI gains Response → Blocklist and Platform → Settings, and a Block
  action on indicator pages and bulk-lookup results.
