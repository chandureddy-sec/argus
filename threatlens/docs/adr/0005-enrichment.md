# ADR 0005: Enrichment engine

Date: 2026-10-10 · Status: accepted

## Context
Phase 3 adds enrichment: RDAP/WHOIS, DNS, ASN and geolocation, reputation (AbuseIPDB, GreyNoise,
VirusTotal, urlscan.io, MalwareBazaar), and certificate transparency (crt.sh). The spec requires TTL
caching, quota tracking, cost awareness, a passive-first policy (active enrichment explicit,
rate-limited, audited), `GET /lookup/{type}/{value}` plus a SOC-friendly bulk `POST /enrich`,
lookups under 2 s on a cache hit, partial results with a clear `skipped_reason` when a quota runs
out, and every enrichment stored with provenance. Each provider's docs and terms were checked on
2026-10-10 (docs/SOURCES.md).

## Decisions
1. **Enrichers are small classes with declared terms** (`EnricherInfo`): the observable types they
   handle, `mode` (passive/active), `third_party` (the value leaves the platform), `discloses` (the
   provider may make the lookup visible to others), key setting, quotas, TTL and negative TTL,
   licence flags, reliability grade, concurrency, and timeout. `query()` only fetches and reads.
   Policy, caching, quotas and storage live in one service, so every enricher gets the same rules.
2. **Passive vs active.** *Active* means a query can reach infrastructure the observable's owner
   controls. **DNS is active**: resolving a domain makes the resolver ask that domain's
   authoritative servers, which a malicious owner can watch. It is the only active enricher. It runs
   only with `active=true`, needs the analyst role, has a separate per-key limit
   (`TL_ENRICH_ACTIVE_PER_MIN`, default 30/min), and writes an `enrich.active` audit record for each
   call. Queries go over DNS-over-HTTPS through the one hardened HTTP client, not the host's
   resolver. RDAP, RIPEstat, reputation lookups and crt.sh are passive: they answer from their
   own data.
3. **TLP 2.0 is enforced before any third-party call.** CLEAR may go to every enricher. GREEN may
   go to providers that don't disclose lookups. VirusTotal is excluded because its docs say a
   looked-up IP "is scanned and added to the VirusTotal dataset". AMBER, AMBER+STRICT and RED never
   leave the platform. The effective TLP is the stricter of the request's and the stored
   indicator's, so a request can't loosen a stored marking. Cached answers are still shown, since
   showing them discloses nothing new.
4. **The database is the cache.** `enrichments` keeps one current row per (enricher, canonical key)
   with `expires_at`. That row is the provenance the spec asks for: the query asked (never a key),
   HTTP status, time, cost, requester, linked source row, and the upstream JSON capped at 256 KB. A
   separate Redis cache would add a second copy to keep in step without making hits measurably
   faster: a cache hit is two indexed reads, measured at about 50 ms through the API on the
   Docker stack. Redis holds what has to be shared and short-lived: quota counters and provider
   blocks. Errors and skips are not stored. "Not found" is stored with a shorter negative TTL.
5. **Quotas from two sides.** Our own fixed-window counters (minute/day/week, epoch-aligned, so
   daily windows reset at 00:00 UTC like AbuseIPDB) stop calls before a provider refuses them.
   Provider rate-limit headers at zero, or a 429, block the provider until the time it gave. A
   refused call costs nothing. Quotas come from docs, or from live headers where the docs are
   silent (GreyNoise keyless: 25/week, observed). Exhaustion gives `skipped_reason:
   quota_exhausted` with `resets_in_s`, and the lookup still returns everything else
   (`partial: true`).
6. **Cost awareness.** Enrichers that spend a provider quota are `metered`. A bulk request has a
   budget of metered calls (`budget`, default `TL_ENRICH_BUDGET` = 50). When it runs out the
   remaining metered enrichers are skipped (`budget_exhausted`). Free enrichers still run.
   `GET /enrichers` shows each quota and today's use.
7. **Interactive HTTP settings.** Lookups use their own `SafeHttp`, with the same SSRF guard: one
   quick retry, no waiting on a long `Retry-After` (that becomes quota exhaustion), and a
   per-enricher timeout (`TL_ENRICH_TIMEOUT_S`, 30 s for crt.sh). A failed refresh returns the
   previous answer marked `stale`, alongside the error.
8. **Geolocation via RIPEstat, not a local MaxMind database.** RIPEstat's `maxmind-geo-lite` data
   call serves GeoLite2 city data, so no MaxMind account, licence key or database updates are
   needed. RIPEstat (prefix-overview plus geo) is the one `auto` enricher: free, passive and
   unmetered, so the worker enriches new active IP indicators with it every 30 minutes
   (`TL_ENRICH_AUTO_PER_RUN`, default 100 per run). This fills the dashboard map. Paid or metered
   enrichers never run in the background.
9. **Interim verdict ("v0").** Phase 4 owns scoring, but a lookup must still say something a SOC
   can act on. The v0 rule: count each source's strongest finding once. Score = strongest
   malicious weight + 5 per further malicious source (max +15), or for suspicion alone, the
   strongest suspicious weight + 5 per further source (capped at 69). Then subtract half the
   strongest benign weight. An allowlist suppression makes the verdict benign. Thresholds are
   malicious ≥ 70 and suspicious ≥ 30. The verdict maps to `block` / `investigate` / `no_action` /
   `monitor`. The full breakdown is returned and the response says `score_model: v0-interim`.
10. **Roles.** Lookups and bulk enrichment need **analyst**, because they spend shared quotas and
    send values to third parties. Viewers can read the enricher catalogue. The UI shows stored
    answers to everyone; only analysts see the "Enrich now" button, which is passive only.
11. **Enrichers are `sources` rows** (`kind = enricher`, `interval_minutes = 0`), so licence and
    commercial/redistribution flags sit next to the feeds' and can be disabled with
    `threatlens sources disable <name>`. The collector only schedules names in its own
    registries, so enricher rows are never collected.

## Consequences
* Without keys, IPs get RDAP, RIPEstat, GreyNoise (25/week) and urlscan; domains get RDAP,
  urlscan, crt.sh, and DNS when asked. AbuseIPDB, VirusTotal and MalwareBazaar report
  `no_api_key` until keys are set.
* Several free tiers are non-commercial: AbuseIPDB free, the VirusTotal public API, and urlscan
  and RIPEstat without written permission. Their licence flags are off, and Phase 6 exports must
  not redistribute their data.
* Corroboration in v0 counts every source as independent. Phase 4 replaces this with
  upstream-aware independence and source reliability weights.
* A Pulsedive enricher (optional in the spec) is deferred. A local MaxMind database is not needed
  (decision 8).
