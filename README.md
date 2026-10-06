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
│   ├── correlate/              # Attack-surface graph correlation
│   ├── enrich/                 # Bulk DNS resolution & ASN / cloud enrichment
│   ├── dns/                    # DNS record resolver
│   ├── whois/                  # RDAP / WHOIS client
│   ├── modules/                # Active recon modules (probe, portscan, crawler, tls, ...)
│   ├── storage/                # SQLite storage (modernc.org/sqlite)
│   ├── report/                 # JSON / HTML / Markdown export
│   └── ui/                     # Terminal tables & formatting
├── pkg/models/                 # Shared data contracts (Target, Asset, Graph, Report)
├── configs/config.yaml.example # Configuration file template
└── .github/workflows/          # Cross-platform CI/CD
```

Unit tests live alongside the code they cover (`*_test.go`).

---

## ⚖️ Legal & Ethical Notice

ReconX is intended strictly for authorized security assessments, defensive attack surface management, and legitimate penetration testing. Passive collection queries public databases; active features must only be used with written authorization.
