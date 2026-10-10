# ADR 0006: ReconX ↔ ThreatLens link (Phase 3b)

Date: 2026-10-10 · Status: accepted · Builds on ADR 0002 and ADR 0005

## Context
ADR 0002 planned a link once ThreatLens had an enrichment API. ReconX should send a scan's hosts
and IPs for verdicts, show them, and alert when assets become flagged. ThreatLens should import
ReconX scans as the organization's assets and observed tech stack. The contract is the HTTP API
only, and neither side imports the other's code.

## Decisions
1. **ReconX → `POST /api/v1/enrich`.** `reconx scan --threatlens[=<url>]` sends the target, every
   host that currently resolves, and every IP. It sends batches of 100 (ThreatLens's default
   bulk limit) with at most 500 values per scan. The URL comes from the flag or
   `RECONX_THREATLENS_URL`. The analyst key comes from `RECONX_THREATLENS_API_KEY` or the ReconX
   key store (`reconx keys set threatlens`), and `reconx keys test` checks it against
   `/api/v1/enrichers`. Config errors fail the scan *before* it starts. ThreatLens errors during
   the scan never fail it: they are recorded on the report (`threat_intel.status`/`error`).
2. **Default TLP:GREEN.** A scan of your own estate is not public, but it can be looked up by
   services that don't publish lookups. VirusTotal is therefore held back by ThreatLens's TLP
   rule (ADR 0005). `--threatlens-tlp TLP:AMBER` keeps every value on the ThreatLens server.
3. **Where verdicts appear.** On `ScanReport.threat_intel` (JSON), as a "Threat Intel" section in
   the HTML and Markdown reports, as a dashboard tab (with a scan-form option that is enabled
   when the server has ThreatLens configured), and in the terminal (flagged assets only).
   Evidence links in HTML are sanitized by `html/template`; the dashboard allows only http(s)
   links.
4. **Monitor rule `threat_intel_flagged`.** When ThreatLens is configured, every scheduled
   monitor run includes the check. The rule alerts on assets that are newly malicious (high) or
   suspicious (medium) compared with the previous run. An asset already flagged alerts again only
   when it escalates from suspicious to malicious.
5. **Assets are imported only on purpose.** `--threatlens-assets` (or `threatlens
   import-reconx`) posts the whole scan to `POST /api/v1/assets/import/reconx`. A separate flag
   keeps a scan of someone else's target from becoming "ours". Imports need the analyst role, are
   audited (`assets.import`), and are idempotent by file SHA-256. An older scan never overwrites
   newer facts.
6. **What counts as our asset:** the scanned target, hosts that resolve, and **only the IPs those
   hosts resolve to**, minus shared CDN edges. ReconX's IP list also contains the domain's name
   and mail servers. A live import of a real scan (2026-10-10) had 17 IPs, of which 16 were
   Cloudflare/Google name-server and edge addresses. A feed listing one of those says nothing
   about our servers, and their software isn't our stack. Each excluded address is reported with
   its reason. Private addresses are refused as everywhere else. A public hostname that resolves
   to a private address is still kept as a host.
7. **Assets are watched, not allowlisted.** A feed listing one of our hosts is the strongest
   signal ThreatLens can give (compromise, abuse, or a shared IP), so hiding it would be wrong.
   Instead lookups add an "own asset" evidence line, and a `block` recommendation becomes
   `investigate`, because blocking your own server cuts off your own service. `GET /api/v1/assets`
   and the UI Assets page list feed-matched assets first. Org-profile domains and ranges keep
   their ADR 0003 allowlist behaviour. That is a deliberate statement by the profile author,
   whereas imported assets are observations.
8. **Observed tech stack.** CPEs Shodan InternetDB reports for our IPs (CPE 2.2 URIs, normalized
   to CPE 2.3) become `asset_products`. PIR-2 matching (UI "in our stack", `stack=true`) uses the
   profile stack plus everything observed. The NVD mirror adds observed **application** CPEs only:
   a single `linux_kernel` CPE would pull thousands of CVEs into the budgeted NVD sync.

## Consequences
* A bulk scan spends metered provider quota. One 19-value scan used 27 metered calls, most of
  GreyNoise's 25-per-week keyless allowance, which ThreatLens then skips as `quota_exhausted`.
  Deployments that scan often should set a GreyNoise key or disable it
  (`threatlens sources disable greynoise`).
* Imported assets carry an analyst-level trust decision. Importing third-party infrastructure
  would turn "block" into "investigate" for it, which is why the import is opt-in, analyst-only
  and audited.
* Assets are not yet removed when a later scan no longer sees them. `last_seen` shows staleness;
  pruning belongs with the Phase 4 expiry work.
