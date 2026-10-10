# ReconX 🔍

[![Build & Cross-Compile](https://github.com/reconx/reconx/actions/workflows/build.yml/badge.svg)](https://github.com/reconx/reconx/actions/workflows/build.yml)
[![Go Version](https://img.shields.io/badge/go-1.22%2B-blue.svg)](https://golang.org)
[![Platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20darwin-lightgrey.svg)](https://github.com/reconx/reconx)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> Cross-Platform Passive Reconnaissance & External Attack-Surface Intelligence CLI for Windows and Kali Linux.

ReconX aggregates, normalizes, deduplicates, and confidence-scores publicly available OSINT data across multiple passive providers without sending intrusive probes or triggering security alerts on target systems.

---

## 🚀 Key Features

* **Zero-Runtime Dependency Binary:** Compiled with pure Go (`CGO_ENABLED=0`) into a single portable binary (`reconx.exe` for Windows, `reconx` for Kali Linux).
* **Passive by Default:** Gathers intelligence strictly from public records (DNS, CT logs, RDAP, WHOIS, Threat Feeds). Active probing is strictly gated behind `--active`.
* **Universal Target Parser:** Automatically detects and classifies Domain, IPv4, IPv6, CIDR blocks, and Organizations from raw text or URLs.
* **Modular Provider Architecture:** Plug-and-play provider interface. Adding a new OSINT source requires writing a single isolated file.
* **Correlated Asset Intelligence:** Links Domain ➔ Subdomain ➔ IP ➔ ASN ➔ Organization with source attribution and confidence scoring.
* **Pipeline-Friendly CLI:** Built on Cobra with `--silent` flag for seamless piping into tools like `httpx` or `nuclei` on Kali.

---

## 📦 Installation & Build

### Prerequisites
* Go 1.22 or higher

### Build from Source

```bash
# Clone repository
git clone https://github.com/reconx/reconx.git
cd reconx

# Download dependencies
go mod tidy

# Build for current OS
go build -ldflags="-s -w" -o reconx ./cmd/reconx
```

### Cross-Compilation (Compile for Kali from Windows or vice-versa)

```bash
# Build for Kali Linux (64-bit ELF)
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/reconx-linux-amd64 ./cmd/reconx

# Build for Windows (64-bit EXE)
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/reconx-windows-amd64.exe ./cmd/reconx
```

---

## 💻 Usage & Commands

```bash
# Universal passive scan
reconx scan --domain example.com --passive --output ./results

# Domain subdomain enumeration
reconx subdomains --domain example.com

# DNS records query (A, AAAA, MX, NS, TXT, SOA, CAA)
reconx dns --domain example.com

# Certificate Transparency & TLS certificates
reconx certificates --domain example.com

# Passive IP / ASN intelligence
reconx ip --target 8.8.8.8

# Historical endpoint discovery (Wayback Machine CDX)
reconx history --domain example.com

# Exporting results to JSON and HTML
reconx scan --domain example.com --json results.json --html report.html
```

### Active Recon (requires authorization)

The `probe`, `portscan`, and `webmap` commands send traffic **directly to the
target** and are refused unless you confirm you are authorized to test it:

```bash
# Confirm authorization explicitly
reconx probe --target example.com --authorize

# Or via environment variable (useful in CI / engagement shells)
RECONX_AUTHORIZE=1 reconx webmap --target example.com

# Restrict to an engagement scope file (one host/domain/CIDR per line);
# out-of-scope targets are refused even with --authorize
reconx portscan --target 10.0.0.5 --authorize --scope engagement-scope.txt
```

Active header analysis covers CSP, HSTS, X-Frame-Options, X-Content-Type-Options,
Referrer-Policy, Permissions-Policy, the cross-origin isolation headers
(**COOP**, **COEP**, **CORP**), version-disclosing `Server` / `X-Powered-By`
headers, and permissive CORS (`*`, `null`, `*` with credentials).

### API keys

Three passive sources work better (or at all) with a key. Store them once
instead of exporting them in every shell:

```bash
reconx keys                 # which keys are set (values masked)
reconx keys set github      # prompts for the token without echoing it
reconx keys test            # checks each key with its service (no target contacted)
reconx keys unset urlscan
```

Keys are saved to `%AppData%\reconx\keys.json` (Windows) or
`~/.config/reconx/keys.json` (Linux/macOS) with owner-only permissions
(override the path with `RECONX_KEYS_FILE`). An environment variable that is
already set always wins over the stored key. The dashboard's **Settings** page
does the same.

### Raw response archive

`reconx scan example.com --archive-raw` (or the dashboard checkbox) saves every
raw HTTP response the passive sources return to
`reports/raw/<scan name>/`, with a `manifest.json` listing URL, status, size and
SHA-256 for each. Request headers are never written and key-like URL
parameters are redacted. DNS lookups are not HTTP and are not archived.

### Monitoring & alerts

Monitors re-run a **passive** scan on a schedule, save it to `reports/` like any
scan, compare it with the previous scan of the target, and raise alerts:

```bash
reconx monitor add example.com --every 1d \
  --webhook https://hooks.slack.com/services/… --min-severity medium
reconx monitor                   # list monitors and their last run
reconx monitor run example.com   # run one now
reconx monitor run               # run whatever is due, then exit (Task Scheduler / cron)
reconx monitor daemon            # foreground scheduler
reconx monitor alerts            # recent alerts
reconx monitor test-webhook example.com
reconx monitor rules             # the alert rules
```

Alert rules: new / removed subdomains, DNS changes, new certificates,
certificates crossing 14/7 days to expiry, provider/ASN changes, new open
ports or CVE IDs from Shodan on the target's own IPs (KEV → high), new
potential dangling DNS, weakened SPF/DMARC, and hosts or IPs that ThreatLens
newly flags (when it is configured). The first run saves a baseline.
Alerts are logged to `reports/monitor/alerts.jsonl`. Slack, Discord and Teams
webhook URLs get chat-formatted messages; any other URL receives JSON
(`{"text": …, "alert": {…}}`). Monitors run while `reconx serve` is open
(disable with `--no-monitor`) or under `reconx monitor daemon`; the dashboard's
**Monitoring** page manages them.

### Threat intel from ThreatLens

ReconX can ask a [ThreatLens](threatlens/) server (this repository's threat-intelligence
platform) about every host and IP a scan finds:

```bash
export RECONX_THREATLENS_URL=http://127.0.0.1:8000
reconx keys set threatlens            # an analyst key: in threatlens/, run  tl key reconx analyst
reconx scan example.com --threatlens                      # verdicts for hosts and IPs (TLP:GREEN)
reconx scan example.com --threatlens --threatlens-assets  # also import as YOUR OWN assets
```

Each host and IP gets a verdict (malicious / suspicious / benign / unknown), a score, the
evidence and a recommended action. They are shown in the terminal (flagged ones), the JSON,
HTML and Markdown reports, and the dashboard's **Threat Intel** tab. `--threatlens-tlp
TLP:AMBER` keeps the values on the ThreatLens server (no third-party lookups).
`--threatlens-assets` is only for targets you own: ThreatLens then lists your hosts that a feed
reports, treats lookups of them as "investigate, don't block", and adds the software Shodan saw on
them to your tech stack. Monitors include the check automatically when ThreatLens is configured
(rule `threat_intel_flagged`). Design: `threatlens/docs/adr/0006-reconx-link.md`.

### Dashboard visualisations

Each scan's detail view has a **Graph** tab (domain → hosts → CNAMEs → IPs →
ASNs → likely providers, plus nameservers and mail servers; drag, Ctrl+scroll
to zoom, click to focus) and a **Map** tab (IP geolocation, coloured by
Shodan exposure). The graph exports as GraphML (Gephi, yEd) or JSON; HTML and
Markdown reports include the map and location table. The world outline is
embedded (Natural Earth via world-atlas), so nothing is loaded from a CDN.

---

## 📡 Data Sources & Modules

**Passive** sources only query public third-party services and public DNS
resolvers; nothing is sent to the target's own infrastructure. They run on
every `scan`. **Active** modules contact the target directly and run only
with `--active --authorize`.

Every source degrades gracefully: a timeout, 404, rate limit or malformed
response is recorded in the report's *Sources* table and the scan continues.

### Passive — subdomain discovery (`internal/providers/`)

Results from all of these merge into one deduplicated subdomain list, with
per-source evidence and confidence.

| Source | What it adds | Auth |
| :--- | :--- | :--- |
| crt.sh | Subdomains and certificates from Certificate Transparency logs | none |
| AlienVault OTX | Subdomains and historical DNS (passive DNS) | none |
| HackerTarget | Subdomains from its host-search database | none |
| Anubis (jldc.me) | Subdomains from the Anubis dataset | none |
| Wayback Machine | Hostnames from archived URLs | none |
| urlscan.io | Subdomains, plus the newest archived page capture per host: title, Server header, HTTP status, IP/ASN, TLS issuer, screenshot URL (linked, never downloaded) | none · optional `RECONX_URLSCAN_API_KEY` |
| Cert Spotter (SSLMate) | Subdomains from a second Certificate Transparency monitor (currently valid certificates), with first/last issuance dates | none · optional `RECONX_CERTSPOTTER_API_KEY` |
| GitHub code search | Hostnames mentioned in public code, with links to the files. Weak evidence (may be stale or an example). | **requires** `RECONX_GITHUB_TOKEN`; skipped with a notice if unset |

### Passive — enrichment

| Source | What it adds | Auth |
| :--- | :--- | :--- |
| RDAP (rdap.org) | Domain registration data | none |
| Public DNS (1.1.1.1, 8.8.8.8, 9.9.9.9) | Current DNS, DNSSEC, CAA, SPF/DMARC/DKIM, MTA-STS, TLS-RPT, PTR | none |
| ip-api.com | IP geolocation, ASN, ISP, reverse DNS | none |
| Team Cymru (DNS) | Announced prefix, RIR, allocation date | none |
| RIPEstat | Origin ASN, holder, prefix, RIR and upstream ASNs, cross-checked against Team Cymru. Disagreements are reported with both values, never silently resolved. (Replaces BGPView, whose API was shut down.) | none |
| Shodan InternetDB | Per IP: open ports, CPEs, hostnames, tags and CVE IDs from Shodan's last crawl. IPs not in Shodan's index are skipped. | none |
| Shodan CVEDB | Per CVE from InternetDB: CVSS, EPSS score/percentile, CISA KEV and ransomware use. CVE lists are ordered KEV first, then by EPSS; KEV-listed CVEs raise host interest. | none |

CVE IDs from Shodan are matched from observed software versions. ReconX
reports them as **unverified indicators**, not confirmed vulnerabilities.

### Active — direct to target (`internal/modules/`, requires `--active --authorize`)

`httprobe`, `tls`, `headers`, `techdetect`, `crawler`, `jsanalysis`,
`apicapture` (headless browser, `--browser`), `portscan` (`--ports`) and
`nmap` (`--nmap`, needs the nmap binary).

### Environment variables

| Variable | Used by | Effect if unset |
| :--- | :--- | :--- |
| `RECONX_URLSCAN_API_KEY` | urlscan.io | Anonymous search (recent scans only, 30 searches/min, no technology detection). With a free account key: higher limits and Wappalyzer technologies for the 10 newest hosts. |
| `RECONX_CERTSPOTTER_API_KEY` | Cert Spotter | Anonymous quota: 10 subdomain queries/hour, so at most 2 result pages per scan; a 429 is reported and the scan continues. A key raises this to 10 pages. |
| `RECONX_GITHUB_TOKEN` | GitHub code search | Source is **skipped** (shown as `skipped`, not an error). GitHub requires a token for code search; any personal access token works, no scopes needed for public code. Limit: 9 searches/min, so ReconX reads at most 3 pages (300 files) per scan. |
| `RECONX_AUTHORIZE=1` | Active modules | Active commands require `--authorize`. |
| `RECONX_KEYS_FILE` | `reconx keys` | Key file defaults to the user config directory. |

The three API keys can also be stored with `reconx keys set <name>` (see *API keys* above).

---

## 🏗️ Project Architecture

```text
reconx/
├── cmd/reconx/main.go          # Application entrypoint
├── internal/
│   ├── cli/                    # Cobra commands + shared scan pipeline & auth gate
│   ├── target/                 # Target parsing & classification
│   ├── orchestrator/           # Concurrency fan-out, rate limiting & provider status
│   ├── providers/              # Provider interface & passive OSINT implementations
│   ├── normalize/              # Normalization, dedup & confidence scoring
│   ├── correlate/              # Attack-surface + infrastructure graph (GraphML export)
│   ├── intel/                  # Passive intel: certs, DNS posture, Cymru, Shodan InternetDB/CVEDB, scoring
│   ├── enrich/                 # IP enrichment: ip-api geo/ASN, RIPEstat routing
│   ├── dns/                    # DNS record resolver
│   ├── whois/                  # RDAP / WHOIS client
│   ├── modules/                # Active recon modules (probe, portscan, crawler, tls, ...)
│   ├── storage/                # SQLite storage (modernc.org/sqlite)
│   ├── report/                 # JSON / HTML / Markdown export, geo map
│   ├── monitor/                # Scheduled passive scans, alert rules, webhooks
│   ├── archive/                # Raw HTTP response archive for passive sources
│   ├── keystore/               # Stored API keys (reconx keys)
│   └── ui/                     # Terminal tables & formatting
├── pkg/models/                 # Shared data contracts (Target, Asset, Graph, Report)
├── configs/config.yaml.example # Configuration file template
└── .github/workflows/          # Cross-platform CI/CD
```

Unit tests live alongside the code they cover (`*_test.go`).

---

## ⚖️ Legal & Ethical Notice

ReconX is intended strictly for authorized security assessments, defensive attack surface management, and legitimate penetration testing. Passive collection queries public databases; active features must only be used with written authorization.
