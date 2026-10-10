# Phase 3: Enrichment, carefully

## Concept
Enrichment answers the analyst's next question about an observable using *other people's data*:
who registered this domain and when (RDAP), which network announces this IP and where it is
(RIPEstat), whether others have seen it misbehave (AbuseIPDB, GreyNoise, VirusTotal, urlscan.io),
whether this hash is a known sample (MalwareBazaar), and what certificates were issued for the name
(crt.sh, Certificate Transparency). A *lookup* combines the platform's own knowledge (feeds, the
allowlist, the graph) with every applicable enricher into one verdict, with the evidence behind it
and a recommended action.

Two properties matter as much as the data:
* **Passive vs active.** Passive enrichment asks a third party what it already knows. Active
  enrichment can touch the observable's own infrastructure. A DNS lookup is active: the domain's
  authoritative name servers see the query.
* **Disclosure.** Every third-party lookup tells that party what you are interested in. Some
  providers keep or share what you ask (VirusTotal adds looked-up IPs to its dataset).

## Why it matters
* **Context turns an alert into a decision.** "198.51.100.7 contacted our server" means little;
  "an IP in a hosting ASN, reported by 17 AbuseIPDB users this week and a Feodo C2" means block it
  and hunt.
* **Lookups leak.** Querying an attacker's domain from your network, or pasting a sensitive internal
  hash into a public service, can tip off an adversary or breach a sharing agreement. TLP exists
  for exactly this: TLP:AMBER or RED intelligence must not end up in a public service's search
  history.
* **Free tiers are small and their terms are strict.** GreyNoise allows 25 keyless lookups a week;
  VirusTotal 4 a minute and 500 a day; several free tiers forbid commercial use. A platform that
  burns a quota on its first batch job, or quietly uses non-commercial data in a commercial
  product, fails in production.
* **Partial is normal.** Some provider is always slow, down or out of quota (crt.sh returned 502 for
  most of the day this phase was built). A lookup that fails when one provider fails is useless to
  a SOC.

## How it works here
* `enrich/base.py`: each enricher declares its terms in `EnricherInfo` (types, passive/active,
  third party, discloses, key, quotas, TTLs, licence, reliability) and implements one `query()`.
* `enrich/rdap.py`, `dns.py`, `ripestat.py`, `reputation.py`, `crtsh.py`: nine enrichers, each
  checked against the provider's current docs and a recorded live response where possible
  (docs/SOURCES.md, tests/fixtures/README.md).
* `enrich/service.py` decides, per enricher: use a fresh **cached** answer; or **skip** with a
  reason (`disabled`, `active_not_requested`, `tlp`, `no_api_key`, `budget_exhausted`,
  `quota_exhausted`); or **call** it under a timeout and concurrency limit, then store the answer
  with provenance in `enrichments`. A failed call returns the previous answer marked `stale`.
* `enrich/quota.py`: fixed-window counters in Redis, shared by the API, worker and CLI, plus
  provider blocks from rate-limit headers and 429s.
* `enrich/verdict.py`: the interim "v0" score. Each source's strongest finding counts once, then
  corroboration, then benign subtraction, then the allowlist. Every step is in `score_breakdown`.
* `api/enrich.py`: `GET /api/v1/lookup/{type}/{value}`, `POST /api/v1/enrich` (values and/or alert
  text, budgeted) and `GET /api/v1/enrichers` (policy, keys, quota use).
* Worker: every 30 minutes new active IP indicators get RIPEstat ASN and location (free, passive,
  unmetered), which fills the dashboard map. The UI indicator page shows stored enrichment and has
  an analyst-only "Enrich now" button.

## Hands-on exercise
With the stack up (`.\tl up`) and an analyst key (`.\tl key me analyst`):

1. `.\tl lookup 162.243.103.246`, then run it again. Compare the time and the statuses (`ok` vs
   `cached`). Where in Postgres is the answer stored, and what does its `query` column say?
2. `curl -H "X-API-Key: $KEY" "127.0.0.1:8000/api/v1/lookup/domain-name/example.com"`. Why was
   `dns` skipped? Repeat with `?active=true&enrichers=dns`, then find the `enrich.active` row in
   `audit_log`.
3. Repeat the first lookup with `?tlp=TLP:GREEN&refresh=true`, then `TLP:AMBER`. Which enrichers
   were skipped and why? Why is VirusTotal treated differently from AbuseIPDB at GREEN?
4. POST an alert to `/api/v1/enrich` with
   `{"text": "beacon to 162.243.103[.]246 and 10.0.0.5", "budget": 1}`. Why was `10.0.0.5`
   rejected, and what does `budget_exhausted` mean for the result?
5. Look up `71.6.199.23` (GreyNoise has 25 keyless lookups a week) and read `score_breakdown`.
   Would you block a Shodan scanner that is probing you? What would change your mind?

## Common mistakes
* Resolving or browsing to an indicator "just to check". That is active enrichment, and the owner
  sees you.
* Sending TLP:AMBER or RED values to public services, or using a service that records lookups for
  anything but TLP:CLEAR.
* Treating one engine's detection on VirusTotal, or a submitter's "phishing" tag on urlscan, as a
  verdict. Weight it, and look for corroboration.
* Caching errors (the outage becomes the answer for a day), or not caching "not found" (the same
  miss burns quota again and again).
* Counting quota only on your side. Another tool using the same key, or a provider resetting at a
  different time, makes your count wrong; trust the provider's headers.
* Letting a background job spend metered quotas. Analysts then find the daily VirusTotal allowance
  gone by 9 a.m.
* Ignoring licences: "free" often means non-commercial, and almost never means redistributable.
