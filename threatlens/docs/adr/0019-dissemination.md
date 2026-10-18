# ADR 0019: Dissemination — STIX/TAXII, exports, SIEM/TIP integrations, alerting

Date: 2026-10-18 · Status: accepted · Phase 6 · Extends ADR 0008 (TLP), 0010 (feed export), 0012 (feed catalog)

## Context
Phase 6 makes Argus share what it knows. The requirements are:
* STIX 2.1 bundles and a TAXII 2.1 server with collections per TLP and confidence tier;
* MISP push and pull;
* blocklist exports with confidence thresholds;
* Wazuh, Splunk, Elastic/OpenSearch and Microsoft Sentinel integrations;
* rule-based alerts to Slack, Teams, Telegram and email, deduplicated and rate-limited;
* respect for TLP and source licences on every path.

## Decisions
1. **One sharing rule set** (`share/select.py`). It is used by TAXII, exports and integrations
   alike. An indicator leaves only if all of these hold:
   * its TLP is at most the destination's cap, and **TLP:RED never leaves**;
   * at least one source that reported it allows redistribution
     (`sources.redistribution`, from docs/SOURCES.md), or no feed reported it (our analysts' own
     intelligence);
   * it is active and scores at least the destination's minimum;
   * it has a STIX pattern (CVEs do not).

   Analyst false positives are re-sent as revocations, so consumers drop them.
   Our own SIEM sightings (`environment` sources) are never shared as "sources".
2. **STIX 2.1 with the TLP 2.0 marking definitions** published by OASIS
   (cti-stix-common-objects, extension `extension-definition--60a3c5c5-…`; ids verified
   2026-10-18). Each bundle carries the definitions it references plus one producer
   `identity`.
   * Indicator ids are the deterministic `uuid5` ids set at ingestion, so a re-send updates the
     indicator instead of duplicating it. The validator warns that these are not UUIDv4 (a
     SHOULD, not a MUST), and we accept that.
   * Validation uses the official `stix2-validator`, pinned to **3.2.0**: the 3.3.1 wheel on
     PyPI ships without its JSON schemas.
   * The blocklist STIX export moved from TLP 1.0 ids to TLP 2.0 at the same time.
3. **A native, read-only TAXII 2.1 server** (`/taxii2/`) instead of medallion.
   * **Why not medallion.** Its backends are in-memory or MongoDB. Ours must read the live store
     under our RBAC, TLP clearance and licence rules, so collections are views over the store
     rather than copies.
   * **Collections:** CLEAR ≥60, CLEAR ≥30, GREEN ≥60, AMBER ≥60. A reader sees those at or
     below their clearance; others answer 404.
   * **Protocol support:** paging with an opaque `next` over (updated_at, id); `added_after`;
     `match[id|type|version|spec_version]`; `X-TAXII-Date-Added-First/Last` with microsecond
     precision, so resuming never repeats an object. Only the latest version of each object is
     kept.
   * **Auth:** an API key, also accepted as the password of HTTP Basic (what TAXII and MISP
     clients send).
4. **Consuming TAXII and MISP** uses the same custom-feed machinery as any feed (formats
   `taxii` and `misp`).
   * Indicators are read from simple STIX equality patterns, and producer markings are kept.
   * From MISP: published `to_ids` attributes through `attributes/restSearch`, with `tlp:` tags
     kept and a timestamp checkpoint.
   * This is how "another ThreatLens can consume the feed" is met and tested.
5. **Exports** (`/feeds/{token}/indicators/{fmt}`, feed-token protected like ADR 0010):
   * EDL text lists;
   * CSV (formula-safe) and JSON;
   * STIX;
   * Wazuh CDB lists (keys with a colon quoted; /8, /16 and /24 as dotted prefixes; other CIDRs
     listed up to a /22).
6. **Integrations** are rows in `integrations`, admin-only, with secrets sealed by the vault and
   never returned, logged or audited.
   * **Drivers and their APIs** (each verified against current vendor docs, docs/INTEGRATIONS.md):
     * Splunk: HEC.
     * Elastic/OpenSearch: `_bulk` with ECS `threat.indicator.*`, keyed by STIX id so re-sends
       update.
     * Sentinel: the STIX objects upload API (preview, ≤100 objects per request) with an Entra
       client-credentials token.
     * MISP: one event per TLP level per push.
     * Generic webhook.
   * **Pushes** follow a cursor, so nothing is sent twice and a failure resumes where it
     stopped. Each push is an `integration_runs` row.
   * **Internal networks.** SIEMs usually live in the LAN, so an admin can mark one integration
     or feed "internal network": RFC 1918, CGNAT and ULA addresses, plus plain http, for that
     destination only. Link-local (cloud metadata) is never reachable. Loopback needs
     `TL_ALLOW_LOOPBACK_DESTINATIONS` (development).
7. **SIEM sightings.**
   * `POST /api/v1/sightings` and a Wazuh integratord webhook (`integrations/wazuh/custom-argus`)
     record "seen in our environment" for values we already hold. Log lines never become
     indicators.
   * Scoring ignores `environment` sources: seeing a value is not a report that it is malicious.
     The threat journey and the `environment` alert rule read them.
8. **Alerting.**
   * **Rule kinds:** `score`, `pir` (relevance hits in the score breakdown), `kev_asset` (by CISA
     date added) and `environment`.
   * **Deduplication:** a unique (rule, dedup key) constraint means an alert is raised once.
   * **TLP:** delivery only to channels whose cap allows the alert's marking.
   * **Rate limit:** at most `TL_ALERT_MAX_PER_HOUR` messages per channel, with one digest for
     the rest.
   * **Start point:** a new rule starts from "now".
   * **Values:** people get defanged values; SIEMs get real ones.

## Consequences
* With the default feeds, most indicators stay home: URLhaus, OpenPhish, Spamhaus and OTX
  forbid or don't grant redistribution. The Integrations page shows how many are kept by marking
  and how many by licence. That is the point of the rule, not a defect.
* Sentinel could only be tested against recorded request shapes. The other drivers were run
  live against `scripts/sink.py`, which answers like each product. Wiring a real Splunk, Elastic,
  Sentinel or MISP needs that product.
* MISP push is not idempotent (a new event per run); the cursor prevents re-sending the same
  indicators.
