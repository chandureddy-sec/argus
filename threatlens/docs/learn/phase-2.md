# Phase 2: Knowledge, not just indicators

## Concept
An indicator on its own ("203.0.113.7 is bad") answers *what*. Analysts need *who*, *how* and
*so what*: which malware family, which group uses it, which techniques they run, which
vulnerabilities they exploit, and whether those affect us. Phase 2 adds three knowledge layers and a
graph that joins them:

* **Behaviour**: MITRE ATT&CK, a curated, cited catalogue of tactics, techniques, groups, software,
  campaigns and mitigations, published as STIX 2.1.
* **Vulnerabilities**: a CVE seen through four lenses. NVD says *what it is* (CVSS, CWE, affected
  CPEs). CISA KEV says *it is being exploited*. EPSS says *how likely exploitation is in the next 30
  days*. OSV/GHSA says *which open-source packages are affected*.
* **Relationships**: typed, sourced edges between indicators, malware, actors, campaigns, techniques
  and CVEs, so any question becomes a graph walk.

## Why it matters
* **CVSS measures severity, not risk.** Most CVEs with a CVSS of 9.8 are never exploited, and some
  exploited ones score 7.x. KEV (exploitation observed) and EPSS (exploitation likely) reorder a
  patch queue far better than CVSS alone. Phase 4 combines them into a P1–P4 `patch_priority`.
* **Techniques outlive indicators.** An IP rotates in days; "uses WMI for execution (T1047)" holds
  for years. Detections built on techniques (Phase 7) keep working after the IOCs expire.
* **Provenance is the product.** "Emotet → T1047" is worth acting on when you can see *who* says so
  (MITRE, with citations) and *how* (an ATT&CK relationship, a feed field, a sentence mentioning a
  CVE). A graph without provenance is rumour with arrows.
* **Versions change meaning.** ATT&CK revokes and merges techniques, deprecates software and adds
  groups twice a year. A detection mapped to a revoked technique is silently stale unless something
  tells you what changed.

## How it works here
* `kb/attack.py` reads MITRE's `index.json`, loads releases newer than the stored one, and upserts
  every object into `entities` and every relationship into `relationships`. It records the release,
  and for later releases only the **meaningful** changes. Between Enterprise 19.1 and 19.2 about
  7 400 objects (mostly relationships) changed timestamps, but only 17 entities changed content, 6
  were added and 237 relationships were added.
* `kb/nvd.py` mirrors the *relevant* CVEs: KEV, the org's tech stack (`virtualMatchString` with the
  CPE prefixes from `org_profile.yaml`), and any CVE the platform has seen. It is kept current from
  NVD's change feed, paced to the keyless rate limit, with a per-run request budget.
* `kb/vulns.py` parses NVD records (the best CVSS of every version, CWEs, vulnerable CPE → vendor and
  product, references tagged *Exploit*, CISA's SSVC "exploitation" decision), copies KEV facts from
  the Phase 1 KEV connector, and computes **exploit signals**, each with its source.
* `kb/epss.py` downloads one daily CSV and updates the CVEs already tracked. `kb/osv.py` asks OSV for
  each CVE's GHSA aliases and affected packages.
* `kb/link.py` runs after each feed collection. It resolves names like "QakBot" or "Cobalt Strike" to
  ATT&CK entities through normalized aliases (or creates a local entity), and writes
  `indicator --indicates--> malware` edges with the feed field as evidence.
* `kb/graph.py` resolves what a person types (`S0367`, `emotet`, `CVE-2024-3400`, an IP) to a node.
  Its `paths()` runs a bidirectional BFS that returns only shortest paths, each edge with its source,
  origin and evidence.

## Hands-on exercise
With a scratch SQLite database (see Phase 1's exercise for the environment variables):

1. `uv run threatlens collect mitre_attack`. Then
   `curl -H "X-API-Key: $KEY" localhost:8000/api/v1/entities/Emotet/techniques`.
   Pick one technique and open the `evidence.provenance.references` URL. What does the citation say?
2. `uv run threatlens attack-load --version 19.1 --force` loads an older release over the current one.
   Then load 19.2 again (`attack-load --version 19.2 --force`) and list the changes:
   `GET /api/v1/attack/releases/enterprise-attack/19.2/changes`. Why does a downgrade need `--force`?
3. `uv run threatlens collect cisa_kev nvd epss` (NVD takes a few minutes without a key). Compare
   `GET /api/v1/vulnerabilities?kev=true&sort=cvss` with `…&sort=epss`. Find a KEV CVE with a CVSS
   below 8: why is it still urgent?
4. `GET /api/v1/vulnerabilities/CVE-2024-3400`. Read `exploit_signals`: which source supports each one?
5. `uv run threatlens collect feodo`, then ask for a path from a Feodo IP to a technique:
   `GET /api/v1/graph/paths?from=<ip>&to=T1047`. Which edge came from a feed and which from MITRE?
   What would change if the feed had named the malware differently ("Heodo")?

## Common mistakes
* Sorting vulnerabilities by CVSS alone.
* Treating "a report mentions CVE-X" as "group Y exploits CVE-X". Keep the quote and the weaker
  relationship type.
* Mirroring all of NVD without a reason, then fighting rate limits. Scope to what you defend and
  what you've seen.
* Re-downloading ATT&CK and overwriting it without recording what changed. Revoked techniques
  quietly break detection mappings.
* Matching malware names exactly. Feeds say "QakBot", "Qbot" and "qak-bot"; normalize, and prefer
  the curated entity.
* Following hub nodes without a budget in a graph search. One popular technique links to hundreds of
  software entries.
