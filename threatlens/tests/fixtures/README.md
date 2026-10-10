# Test fixtures

Connector contract tests parse these files; no test touches the network.

| File | Origin | Why |
|---|---|---|
| `cisa_kev.json` | **Real**, trimmed to 3 entries (catalog 2026.10.04) | CC0 — redistribution allowed |
| `feodo.json` | **Real**, first 3 entries | CC0 |
| `spamhaus_drop.ndjson` | **SYNTHETIC** records in the real v4/v6 format, metadata lines included (replaced 2026-10-09) | DROP terms grant no licence to redistribute the list |
| `tor_exits.txt` | **Real**, first 3 lines | public list |
| `urlhaus.csv` | **SYNTHETIC** values in the real format (header copied from the live dump) | abuse.ch terms restrict redistribution |
| `threatfox.json` | **SYNTHETIC**, built from the documented response fields | API needs an Auth-Key we don't have yet; redistribution restricted |
| `otx.json` | **SYNTHETIC**, built from the OTX SDK's documented pulse structure | API needs a key; not yet verified against a live response |
| `openphish.txt` | **SYNTHETIC** | community feed is non-commercial and not for redistribution |

Synthetic values use IANA/ICANN-owned names and addresses (`*.example.*`,
`93.184.216.34`, `192.0.43.10`, `192.0.32.0/20`) or documentation ranges (`2001:db8::/32`) so no real third party is implicated. When a
key becomes available, replace the synthetic ThreatFox/OTX fixtures with
trimmed real responses and note the date here.

## Knowledge base (`kb/`)

| File | Origin | Why |
|---|---|---|
| `enterprise-attack-19.1.json`, `-19.2.json` | **Real** ATT&CK 19.1 / 19.2 objects: Emotet, its techniques, groups using it, one mitigation, one campaign, a revoked pair, a CVE-mentioning relationship, a group new in 19.2; collection contents trimmed to match | ATT&CK Terms of Use permit copies that carry MITRE's copyright designation and licence: see `kb/ATTACK-NOTICE.txt` |
| `attack_index.json` | **Real** `index.json`, two versions per domain | same |
| `nvd_pool.json` | **Real** NVD API 2.0 records (CVE-2024-3400, -2021-44228, -2020-1472, two FortiOS CVEs, one CVSS-v4-only CVE), ≤12 CPE matches per node and ≤12 references each | US government data |
| `epss_scores.csv.gz` | **Real** EPSS file header plus the rows for those CVEs and the first five rows | FIRST publishes EPSS freely; attribution: FIRST.org |
| `osv_CVE-2021-44228.json`, `osv_GHSA-jfh8-c2jp-5v3q.json` | **Real** OSV records, trimmed (affected/references) | GHSA: CC-BY 4.0 (GitHub) |

All recorded 2026-10-09.

## Enrichment (`enrich/`)

Recorded 2026-10-10 from the live, keyless endpoints, unless marked SYNTHETIC.

| File | Origin | Why |
|---|---|---|
| `iana_{dns,ipv4,ipv6,asn}.json` | **Real** IANA RDAP bootstrap files, trimmed to the services the tests use | IANA registry data |
| `rdap_domain_github.json`, `rdap_domain_404.json` | **Real** Verisign RDAP answers (github.com; a non-existent .com: 404 with an empty body) | public registry record |
| `rdap_ip_arin.json` | **Real** ARIN RDAP answer for 162.243.103.246 (a Feodo Tracker C2 in `feodo.json`) | public RIR record |
| `ripestat_prefix.json`, `ripestat_geo.json` | **Real** RIPEstat `prefix-overview` / `maxmind-geo-lite` for the same IP | small excerpt for testing only; RIPEstat terms bar redistribution of the data set |
| `greynoise_benign.json`, `greynoise_404.json` | **Real** GreyNoise Community answers (71.6.199.23 = Shodan scanner; 8.8.8.8 not observed) | — |
| `doh_github_{A,AAAA,MX,NS,TXT}.json`, `doh_nx_A.json` | **Real** Cloudflare DoH JSON answers | DNS answers |
| `urlscan_search.json`, `urlscan_empty.json` | **Real** anonymous urlscan search (`page.domain:"github.com"`, 3 results; a miss) | public scans |
| `abuseipdb_check.json` | **SYNTHETIC** values in the documented `check` fields | needs a key |
| `virustotal_ip.json`, `virustotal_file.json`, `virustotal_404.json` | **SYNTHETIC** values in the documented object attributes (file = EICAR test file) | needs a key |
| `malwarebazaar_hit.json`, `malwarebazaar_miss.json` | **SYNTHETIC** values in the documented `get_info` fields (EICAR hashes) | needs an abuse.ch key |
| `crtsh.json` | **SYNTHETIC** rows (example.com) in crt.sh's JSON format | crt.sh returned 502 all day on 2026-10-10 |
