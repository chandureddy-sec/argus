# ADR 0002 — Monorepo with ReconX, and the ReconX ↔ ThreatLens link

Date: 2026-10-08 · Status: accepted

## Context
The spec assumes an empty repository. ThreatLens is being built next to
ReconX, a Go attack-surface scanner in the same repo. ReconX already knows
the organization's real hosts, IPs and observed technologies (CPEs from
Shodan and urlscan) — exactly the "assets" and "tech stack" the spec's org
profile asks a human to type in.

## Decision
* ThreatLens lives in `threatlens/` with its own `pyproject.toml`, lockfile,
  Dockerfile and CI workflow (`.github/workflows/threatlens.yml`, path-filtered).
  The Go workflow ignores `threatlens/**`.
* A dedicated **Phase 3b** links the tools once ThreatLens has an enrichment
  API:
  * ReconX gains `--threatlens <url>` (key stored with `reconx keys`) and sends
    a scan's hosts, IPs and CPEs to `POST /api/v1/enrich`; verdicts appear in a
    Threat Intel tab, and a monitor rule alerts on newly flagged assets.
  * ThreatLens can import ReconX scan JSON to populate `assets` and an
    *observed* tech stack, so PIR-2 ("vulnerabilities in our stack") matches
    what is deployed.
* The contract between them is the HTTP API only (JSON schemas versioned under
  `/api/v1`); neither imports the other's code.

## Consequences
* Each side can be released and run alone.
* One `git log` covers both; commits stay scoped to one side where possible.
* CI time is not wasted: each workflow runs only for its own paths.
