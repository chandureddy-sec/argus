# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Primary user: a **solo security practitioner or consultant** who runs
reconnaissance and threat-intelligence work from a single self-hosted Argus
instance — for their own organization or on behalf of clients. They are
technical (comfortable with Docker, a CLI, API keys, SIEM/firewall formats),
work hands-on across both attack-surface and threat-intel tasks, and need one
person to cover ground that larger teams split across tools and roles.

The role model (viewer / analyst / admin) still exists and larger in-house SOC
teams can use it, but the product's center of gravity is the single expert
operator, not a staffed SOC.

## Product Purpose

Argus answers the two questions a security operator faces daily, in one place:

1. **What do we expose on the internet?** Maps domains, hosts, IPs, open
   services and software from public sources; optional authorized active checks.
2. **Is this indicator bad, and what do we do about it?** Collects open
   threat-intel feeds, scores every IP / domain / URL / hash / CVE 0–100 with the
   reasons shown, verifies a value against ~a dozen providers, and turns the
   verdict into an action: a case, a firewall block, or "not malicious".

Success is a solo operator completing the full loop — discover exposure →
assess an indicator → decide → act (case / block / export) — without stitching
together separate EASM and TIP products or losing the evidence trail.

## Positioning

**Attack-surface management (EASM) and threat intelligence (TIP) unified in one
self-hosted application, behind one sign-in.** A neighboring product typically
does one half; Argus runs both over a shared evidence model so a recon finding
and a threat-intel verdict live in the same system, cross-reference each other,
and export together. Reinforced by (but not reducible to) explainable scoring,
full provenance, and a passive-first safety model.

## Operating Context

- Self-hosted via Docker Compose on the operator's own machine or server; one
  organization per deployment.
- API bound to `127.0.0.1:8000`; web UI served at `/app`; a TLS reverse proxy is
  expected before any network exposure.
- Accessed through a browser behind one sign-in with 2FA; also driven by the
  `threatlens` CLI (`tl` launcher on Windows, `start.sh`/`stop.sh` on Linux/macOS)
  and consumed by external tools via `/api/v1` (API key) and `/feeds/...` (token).
- Core analyst loop spans Attack surface (scans, compare, monitors), Threat intel
  (verify, bulk check, indicators, vulnerabilities, ATT&CK, detections,
  lookalikes, report assistant), and Response (cases, blocklist, alerts).
- Organization identity is configured, not assumed: `config/org_profile.yaml`
  ships blank; the operator adds domains, ranges, brands and tech stack.

## Capabilities and Constraints

- Web UI of ~32 pages across Home, Attack surface, Threat intel, Response and
  Platform areas; light and dark themes.
- Out-of-the-box feeds (URLhaus, ThreatFox, Feodo, OpenPhish, Spamhaus DROP, Tor,
  OTX, CISA KEV, NVD, EPSS, OSV, MITRE ATT&CK) and lookup providers (AbuseIPDB,
  GreyNoise, VirusTotal, MalwareBazaar, urlscan, RDAP, RIPEstat, crt.sh, DNS).
  Sources needing a (usually free) API key report "skipped" until a key is added
  — a visible, expected state, not an error.
- Interop: STIX 2.1, TAXII 2.1, EDL/CSV/JSON blocklist exports, Sigma/Suricata/
  YARA/Wazuh detections, and SIEM sinks (Splunk, Elastic, Sentinel, MISP) — all
  license- and TLP-aware.
- Explainability is a product requirement: every 0–100 score shows its breakdown
  and policy version; indicators carry provenance, a feed-to-action threat
  journey, pivots, timelines and stored enrichment; reports are cited and
  reproducible.
- The AI report assistant is **off by default**; its drafts are checked item by
  item against the source and require an analyst's approval before use.
- Single-organization by design (no multi-tenancy); raw artifacts use a
  filesystem content-addressed store (no S3); relational edge tables rather than a
  graph database — deliberate decisions for a single-host deployment, not gaps.

## Brand Commitments

Binding — future work preserves these and does not restyle them away:

- Product name **Argus**, part of a shared mark family in [`brand/`](brand/).
- **Official accent: muted olive.** The olive interface token (`#8f9a5b` in dark,
  `#5f6a34` in light) is the one Argus brand and UI accent. Pink (`#ff4fa3`) was
  explicitly rejected and retired as a brand colour on 2026-11-04; it is no longer
  a mandatory or permitted brand colour.
- Logo system: 64×64 rounded-square dark frame (`#0e0b1d`), an olive **signal**
  dot (`#8f9a5b`) at the top-right as "the finding", and a per-product gradient
  glyph. New marks start from `brand/template.svg`.
- Typography: **Inter** for text (700 / `-0.01em` for wordmarks), **JetBrains
  Mono** for values (IPs, hashes, domains). Both SIL OFL and self-hosted.
- Light and dark themes are both first-class.

## Evidence on Hand

- Real product: a working self-hosted platform (Go ReconX engine, Python
  ThreatLens API/worker, React web UI) with live feed collection and provider
  lookups. README and architecture docs are accurate to the build.
- Brand assets exist in [`brand/`](brand/) (`reconx.svg`, `threatlens.svg`,
  `template.svg`, `preview.html`).
- Demos and tests run against a **synthetic "Example Corp"** profile in
  `threatlens/tests/fixtures/`, never real `config/`.
- **No real customers, users, testimonials, benchmarks, logos, pricing or
  deployment claims exist** (pre-product, zero users). Future work must not
  fabricate any of these; use the synthetic "Example Corp" data for illustration.

## Product Principles

1. **One operator, whole loop.** Design for a single expert covering both EASM
   and TIP end to end; never assume a staffed, role-split SOC.
2. **Evidence over assertion.** Every verdict, score and report shows its reasons
   and provenance and can be reproduced; nothing is a black box.
3. **Safe by default.** Passive first; active and destructive actions (scanning,
   blocking) are gated, confirmed, audited, and reversible — safe to run against
   your own organization.
4. **Honest states.** "Skipped (needs a key)", partial results, empty states and
   quotas are shown plainly rather than hidden or faked.
5. **Self-hosted and sovereign.** The operator's data and the whole stack stay on
   their own infrastructure; internal addresses never leave it.

## Accessibility & Inclusion

No formal standard has been established as a product requirement yet. Light and
dark themes are both supported; values are set in a monospace face for
legibility. (Open: confirm a target such as WCAG 2.1 AA if the product moves
toward real-team adoption.)
