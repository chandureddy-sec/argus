# Phase 3b: Joining the attack surface to threat intelligence

## Concept
ReconX answers "what do we expose?": hosts, IPs and the software on them, from passive sources.
ThreatLens answers "what is known to be bad, and what affects us?". The join between the two is
where both become more useful:

* **Outside-in**: each of our hosts and IPs gets a verdict. "Is any of our infrastructure listed
  by a threat feed?" is one of the highest-value questions a small team can ask regularly.
* **Inside-out**: what we actually run (observed CPEs) becomes part of the tech stack, so
  "vulnerabilities in our stack" reflects what is deployed, not only what someone typed into a
  profile.

## Why it matters
* **A feed listing your own IP is an incident lead, not noise.** It usually means a compromised
  server (C2, phishing kit, open proxy), abuse of a shared address, or a recycled IP someone else
  used for crime. Each needs a different response, and none of them is "block it".
* **Asset inventories drift.** Hand-maintained lists miss the forgotten staging host. A scan sees
  what resolves today.
* **Not every IP in a scan is yours.** Name servers, mail providers and CDN edges show up in any
  passive scan. Treating them as yours creates false alarms ("our IP is malicious!" when it is a
  Cloudflare edge shared with a phishing site). It also pollutes your tech stack with other
  people's software.

## How it works here
* ReconX `scan --threatlens` sends the target, live hosts and IPs to `POST /api/v1/enrich`, in
  batches with a TLP (GREEN by default). It stores the verdicts on the report, shows them in the
  HTML/Markdown reports and a dashboard tab, and the `threat_intel_flagged` monitor rule alerts
  on new ones.
* `--threatlens-assets` (or `threatlens import-reconx file.json`) sends the whole report to
  `POST /api/v1/assets/import/reconx`. `assets.py` keeps the target, resolving hosts and the IPs
  they resolve to (minus CDN edges and private addresses), plus Shodan's CPEs normalized to CPE
  2.3. Imports are idempotent (file SHA-256), audited, and an older scan never overwrites newer
  facts.
* Lookups of an own asset say so, and turn `block` into `investigate`. `GET /api/v1/assets` and
  the Assets page list feed-matched assets first. `GET /api/v1/assets/products` shows each
  observed product with its known and KEV CVEs.
* PIR-2 and the NVD scope use the profile's stack plus the observed applications.

## Hands-on exercise
With the ThreatLens stack up and an analyst key in `RECONX_THREATLENS_API_KEY`:

1. `reconx scan <your-domain> --threatlens` (with `RECONX_THREATLENS_URL=http://127.0.0.1:8000`).
   Open the HTML report's Threat Intel section. Why is every value "partial", and which
   enrichers were skipped for which reason?
2. Run it again with `--threatlens-tlp TLP:AMBER`. What changed in the evidence, and why might you
   want that for an incident?
3. Add `--threatlens-assets`, then open `/ui/assets`. How many of the scan's IPs were imported,
   and why were the others left out? (`GET /api/v1/assets/imports`.)
4. Look up one of your own IPs: `GET /api/v1/lookup/ipv4-addr/<ip>`. Find the `asset` field and
   the "Own asset" evidence line. If a feed listed it, what would `recommended_action` be?
5. Set up a ReconX monitor for the domain. Which rule would tell you, the next morning, that
   ThreatLens newly considers one of your hosts malicious?

## Common mistakes
* Importing scans of third parties (customers, pentest targets) as your own assets. Their
  malicious infrastructure would then be recommended for "investigate" instead of "block".
* Counting name-server, mail-provider and CDN addresses as your servers.
* Blocking your own IP because a feed lists it. Investigate first: compromise, abuse or a
  recycled address?
* Pulling NVD data for every observed CPE, OS kernels included, and exhausting the sync budget
  on CVEs that don't apply to an internet-facing service.
* Re-running a bulk lookup of a large estate many times a day on free provider tiers. A weekly
  GreyNoise allowance is gone in one scan.
