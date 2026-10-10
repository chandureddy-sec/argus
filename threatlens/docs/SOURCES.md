# Sources

Every external source is checked against its **current official documentation**
before its connector or enricher is written, and checked again when it breaks.
A source is marked verified only once that check is done, with the date.
The machine-readable copy of each Phase 1 row is the connector's `SourceInfo`
(`src/threatlens/connectors/feeds.py`). It is synced into the `sources` table
and served at `GET /api/v1/sources`. If this page and the code disagree, the
code is what runs; fix whichever one is wrong.

Reliability uses the Admiralty source grade (A = completely reliable … F =
cannot be judged). `Upstream` names the original producer, so corroboration
doesn't count a mirror as an independent second source.

## Phase 1 feeds (built)

| Source | Type | Endpoint | Auth | Fetch limit (ours: interval / min gap) | Licence | Commercial | Redistribute | Reliability · conf. | Upstream | Verified |
|---|---|---|---|---|---|---|---|---|---|---|
| CISA KEV | vuln (CVE) | `cisa.gov/.../known_exploited_vulnerabilities.json` | none | 6 h / 1 h | CC0 1.0 | yes | yes | A · 100 | cisa | 2026-10-08 |
| abuse.ch URLhaus | malware URLs | `urlhaus.abuse.ch/downloads/csv_recent/` | none for the dump (Auth-Key optional) | 1 h / 5 min | abuse.ch terms (fair use; commercial needs subscription) | **no** | **no** | B · 80 | abusech | 2026-10-08 |
| abuse.ch ThreatFox | IOCs | `threatfox-api.abuse.ch/api/v1/` | **Auth-Key required** (`TL_ABUSECH_AUTH_KEY`, free) | 1 h / 15 min | abuse.ch terms | **no** | **no** | B · 75 | abusech | 2026-10-08 |
| abuse.ch Feodo Tracker | botnet C2 IPs | `feodotracker.abuse.ch/downloads/ipblocklist.json` | none | 30 min / 5 min | CC0 1.0 | yes | yes | B · 85 | abusech | 2026-10-08 |
| AlienVault OTX | pulses / IOCs | `otx.alienvault.com/api/v1/pulses/subscribed` | **API key required** (`TL_OTX_API_KEY`, free) | 1 h / 15 min | OTX terms of service | treated as **no** until confirmed | **no** | C · 50 | otx | 2026-10-08 (endpoint); terms open |
| Spamhaus DROP (v4 + v6) | criminal netblocks | `spamhaus.org/drop/drop_v4.json`, `drop_v6.json` | none | **24 h / 24 h** (page says both "once per hour" and "once per day"; we take the stricter) | DROP terms: free "regardless of size or business type", credit Spamhaus, keep date and © with the data | yes | **no** (terms grant no licence to the list) | A · 95 | spamhaus | 2026-10-09 |
| Tor exit list | Tor exit IPs | `check.torproject.org/torbulkexitlist` | none | 1 h / 30 min | no licence stated at the endpoint | yes | yes (assumed; see open points) | A · 30 | torproject | 2026-10-08 |
| OpenPhish community | phishing URLs | `raw.githubusercontent.com/openphish/public_feed/.../feed.txt` | none | 12 h / 1 h (feed updates every 12 h) | OpenPhish terms (community feed non-commercial) | **no** | **no** | B · 80 | openphish | 2026-10-08 |

Confidence is the default per-sighting value. Tor exit IPs get 30 because
being a Tor exit isn't malicious in itself. Phase 4 scoring builds on these values.

## Allowlist sources (built)

| Source | Use | Endpoint | Licence | Verified |
|---|---|---|---|---|
| Tranco top-N (default 10 000) | popular registrable domains → suppress; URLs on them → flag | `tranco-list.eu/top-1m.csv.zip` (daily, by 00:00 UTC) | No licence stated for the list. Its inputs include Cloudflare Radar (CC BY-NC 4.0), Majestic (CC BY 3.0) and CrUX (CC BY-SA 4.0). Used only internally to filter, never redistributed | 2026-10-09 |
| Cloudflare IP ranges | CDN ranges → flag | `cloudflare.com/ips-v4`, `ips-v6` | published for customers' firewall configuration | 2026-10-08 |
| Fastly public IP list | CDN ranges → flag | `api.fastly.com/public-ip-list` | published for customers' firewall configuration | 2026-10-08 |
| Org profile | own domains / ranges → suppress | `config/org_profile.yaml` | — | — |

## Phase 2 knowledge sources (built)

| Source | Type | Endpoint | Auth | Fetch limit (ours: interval / min gap) | Licence | Commercial | Redistribute | Reliability | Upstream | Verified |
|---|---|---|---|---|---|---|---|---|---|---|
| MITRE ATT&CK (Enterprise, Mobile, ICS) | knowledge | `raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json` → versioned bundles `<domain>/<domain>-<version>.json` (Enterprise 19.2 ≈ 54 MB) | none | 24 h / 1 h; a release is loaded once | ATT&CK Terms of Use: "royalty-free license … for research, development, and commercial purposes"; copies must reproduce MITRE's copyright and the licence | yes | yes, with notice | A | mitre | 2026-10-09 |
| NIST NVD API 2.0 | CVE details | `services.nvd.nist.gov/rest/json/cves/2.0` with `hasKev`, `virtualMatchString`, `cveId`, `lastModStartDate`/`EndDate` (≤ 120 days), `resultsPerPage` ≤ 2000 | optional key in the `apiKey` header (`TL_NVD_API_KEY`); an invalid key answers **404** | 2 h / 2 h; requests 6.5 s apart without a key, 0.7 s with one; ≤ `TL_NVD_MAX_REQUESTS` (60) per run | US government data (no copyright); NVD asks for the notice "This product uses the NVD API but is not endorsed or certified by the NVD." | yes | yes | A | nist | 2026-10-09 (API behaviour live; docs pages are JS-rendered, see open points) |
| FIRST EPSS | exploit probability | `epss.empiricalsecurity.com/epss_scores-current.csv.gz` (redirects to the dated file; ~2.7 MB, ~385 k rows; first line `#model_version:…,score_date:…`) | none | 6 h / 1 h, conditional GET; when unchanged, newly tracked CVEs are scored from the archived file | "published freely via CSV download and API with no registration"; "attribution is requested when EPSS data is used in publications or products" | yes | not addressed, so **no** | B | first | 2026-10-09 |
| OSV.dev (incl. GitHub Advisory Database) | OSS advisories | `api.osv.dev/v1/vulns/{CVE or GHSA id}` (CVE ids work; 404 when OSV has no record) | none | 24 h / 1 h; ≤ `TL_OSV_MAX_PER_RUN` (300) CVEs, 0.2 s apart; each CVE re-checked after 7 days | per upstream database: GHSA CC-BY 4.0, others CC0/CC-BY/MIT/Apache/CC-BY-SA; we keep only ids and package names | yes | **no** (mixed licences) | A | osv | 2026-10-09 |
| CISA KEV (knowledge use) | exploited CVEs | read from the Phase 1 `cisa_kev` connector's sightings; no extra download | — | — | CC0 1.0 | yes | yes | A | cisa | 2026-10-08 |

## Phase 3 enrichers (built)

Machine-readable copy: each enricher's `EnricherInfo` (`src/threatlens/enrich/`), synced into
`sources` (`kind = enricher`) and served at `GET /api/v1/enrichers`. Weights and policy: ADR 0005.

| Enricher | Types | Mode | Endpoint | Auth | Limits (ours) | Licence | Commercial | Redistribute | Rel. | Verified |
|---|---|---|---|---|---|---|---|---|---|---|
| RDAP | domain, IPv4/6 | passive | IANA bootstrap `data.iana.org/rdap/{dns,ipv4,ipv6,asn}.json` (cached 24 h) → the registry's RDAP server; domains by registrable domain | none | concurrency 4; TTL 7 d (miss 1 d) | registry terms (notices in each answer) | yes | **no** | A | 2026-10-10 (live) |
| DNS | domain | **active** | Cloudflare DoH JSON `cloudflare-dns.com/dns-query?name=&type=` (A, AAAA, MX, NS, TXT) | none | only with `active=true`; per-key 30/min; audited; TTL 1 h | Cloudflare 1.1.1.1 | yes | yes | A | 2026-10-10 (live) |
| RIPEstat | IPv4/6 | passive, **auto** | `stat.ripe.net/data/prefix-overview/` + `/maxmind-geo-lite/` with `sourceapp=threatlens` | none | RIPE: 8 concurrent per IP (we use 4); register `sourceapp` with stat@ripe.net if > ~1000/day; TTL 1 d | RIPEstat T&C; GeoLite2 by MaxMind | **no** (written permission needed) | **no** | A | 2026-10-10 (live; terms page read) |
| AbuseIPDB | IPv4/6 | passive | `api.abuseipdb.com/api/v2/check?ipAddress=&maxAgeInDays=90`, header `Key` | **key** `TL_ABUSEIPDB_API_KEY` | 1 000/day (Standard); `X-RateLimit-*` headers; 429 when out; TTL 24 h | AbuseIPDB ToS: free plans non-commercial | **no** | **no** | C | 2026-10-10 (docs; fixture synthetic) |
| GreyNoise Community | IPv4 | passive | `api.greynoise.io/v3/community/{ip}`; 404 + JSON = not observed | optional header `key` | **25/week without a key** (live `X-Ratelimit-Limit: 25`, reset 7 d); 50/week with a free account (docs, shared with the Visualizer); TTL 3 d | GreyNoise EULA: internal business or non-commercial use | internal only | **no** | B | 2026-10-10 (live) |
| VirusTotal | IP, domain, URL, hashes | passive, **discloses** | `www.virustotal.com/api/v3/{ip_addresses,domains,urls,files}/{id}`, header `x-apikey`; URL id = unpadded URL-safe base64 | **key** `TL_VIRUSTOTAL_API_KEY` | public API: 4/min, 500/day; TTL 24 h; never for TLP:GREEN+ (looked-up IPs are added to VT's dataset) | VT ToS: public API not for commercial products or business workflows | **no** | **no** | B | 2026-10-10 (docs; fixture synthetic) |
| urlscan.io | domain, URL, IP | passive (search only, never submits) | `urlscan.io/api/v1/search/?q=` (`page.domain`/`task.domain`, `page.url`/`task.url`, `page.ip`) | optional header `API-Key` | without a key 30/min per IP (live `X-Rate-Limit-*`); TTL 12 h | urlscan ToS: commercial use needs written permission | **no** | **no** | C | 2026-10-10 (live) |
| MalwareBazaar | MD5/SHA1/SHA256 | passive (metadata only) | `mb-api.abuse.ch/api/v1/` POST `query=get_info&hash=` | **Auth-Key** `TL_ABUSECH_AUTH_KEY` | fair use (no numbers published); concurrency 2; TTL 7 d (miss 1 d) | abuse.ch terms | **no** | **no** | B | 2026-10-10 (docs; fixture synthetic) |
| crt.sh | domain | passive | `crt.sh/?q={domain}&output=json` | none | concurrency 1, timeout 30 s; TTL 24 h | none published; CT data public by design | yes | **no** | A | 2026-10-10 (service down: 502 all day; format from earlier use, fixture synthetic) |

Not built: **Pulsedive** (optional in the spec); a local **MaxMind GeoLite2** database (RIPEstat
serves GeoLite2 data, so no MaxMind account is needed; ADR 0005).

## Open points
* **OTX terms**: confirm the commercial and redistribution position once there is a
  key to read the account terms with. Until then both flags are off.
* **Tor exit list**: no licence is published at the endpoint. Tor Project data
  is generally published openly. Confirm before Phase 6 exports include it.
* **Tranco** inherits a non-commercial input (Cloudflare Radar). We only use it
  as an internal filter. Revisit if the deployment is commercial and that use
  is in doubt.
* **Keyed enricher fixtures** (AbuseIPDB, VirusTotal, MalwareBazaar) are built from the
  documented fields. Record trimmed real answers once keys exist, and re-check the field names.
* **crt.sh** was unavailable during the whole Phase 3 check. Record a real answer and confirm the
  JSON fields when it is back.
* **Commercial deployments**: AbuseIPDB (free), VirusTotal (public API), urlscan and RIPEstat
  need a paid plan or written permission. Disable them with `threatlens sources disable <name>`
  until that is settled.
* **RIPEstat `sourceapp`**: register `threatlens` (or your own id) with stat@ripe.net if the
  deployment makes more than about 1 000 queries a day (`TL_RIPESTAT_SOURCEAPP`).
* **NVD API 2.0 rate limits and notice**: the developer pages render client-side and
  couldn't be read (2026-10-09). The pacing (6.5 s without a key, 0.7 s with one) and
  the notice text come from earlier knowledge of the documented limits (5 and 50
  requests per rolling 30 s). NVD's news page confirms that throttled requests now get
  **429** (May 2025). Re-check the developer pages in a browser.
* **EPSS redistribution** isn't addressed by FIRST; kept off.
* **ransomware.live** API access and terms (spec §6).

## Corrections log
* 2026-10-09 **Spamhaus DROP**: the Phase 0 note said "non-commercial only".
  The current product page says the list is free for any business type, so
  commercial use is allowed. The connector's `redistribution` flag was wrong
  (the terms grant no licence to the list) and is now off. The fetch interval
  went from 12 h to 24 h to honour the stricter "once per day" wording.
