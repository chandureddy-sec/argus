# ADR 0004: Knowledge base and relationship graph

Date: 2026-10-09 · Status: accepted

## Context
Phase 2 adds the context that makes indicators meaningful: MITRE ATT&CK, vulnerability intelligence
(NVD, EPSS, CISA KEV, OSV/GitHub advisories), and a graph linking indicators, malware, actors,
campaigns, techniques and CVEs. The spec defaults to an edge table plus NetworkX, and allows Neo4j
"only if justified". It also asks for typed entity tables, ATT&CK version diffing, KEV and EPSS flags
on CVEs, and traversal with provenance.

## Decisions
1. **One `entities` table, typed by STIX type, with the original object in `stix`.**
   ATT&CK has more than 12 object types, and new ones arrive (the 19.x bundles carry detection
   strategies and analytics). A table per type would mean a migration for every new type. Common
   columns (name, external id, aliases, domains, tactics, revoked/deprecated) are real columns. The
   rest stays in the stored STIX object.
2. **Malware and actors named by feeds become entities too** (`origin=feed`), when ATT&CK has no
   match. Names are resolved by a normalized alias key (`QakBot` = `Qbot` = `qak-bot`). ATT&CK
   entities win over local ones, and non-revoked ones win over revoked ones.
3. **Polymorphic edges.** `relationships.src_ref` and `dst_ref` are STIX ids of entities,
   vulnerabilities or indicators, with no foreign keys. Every edge kind fits one table and one
   traversal query. Every edge records:
   * `origin`: `attack` (an ATT&CK relationship object), `attack-mention` (a CVE named in ATT&CK
     text), `feed` (a feed field), or `identity` (the indicator *is* the CVE);
   * `source_id`, `confidence`, `provenance` (the evidence: relationship id and citations, the feed
     field and value, or a quote), `first_seen`/`last_seen`.
4. **Deterministic STIX ids** (uuid5 under a fixed namespace) for everything ThreatLens creates:
   indicators, CVEs, local entities, derived edges. Re-ingesting never duplicates, and Phase 6 STIX
   exports are stable. Pre-Phase-2 indicators get their id from a backfill on the next collection run,
   not in the migration (no `uuid-ossp` extension needed).
5. **Postgres for storage, Python for traversal.** Paths use a bidirectional BFS that expands the
   smaller frontier one level per query, stops at the first meeting level (shortest paths), and has a
   visited-node budget for hub techniques (Ingress Tool Transfer has 520 `uses` edges in Enterprise 19.2). No NetworkX
   dependency is needed yet. Neo4j isn't justified at this scale (≈50 k edges for ATT&CK plus feeds).
6. **CVE mentions are recorded as `related-to`, never `exploits`.** ATT&CK text such as "Wizard
   Spider has exploited CVE-2020-1472" is evidence, but turning prose into a typed claim would
   overstate what was parsed. The quote travels with the edge.
7. **ATT&CK versioning.** Releases are loaded from the versioned files listed in MITRE's `index.json`.
   The first load of a domain is a *baseline* and lists no changes. Later releases record
   **meaningful** changes only (name, description, aliases, version, revoked/deprecated, tactics,
   platforms, domains). Between Enterprise 19.1 and 19.2, about 7 400 objects (mostly relationships)
   got a new `modified` timestamp, but only 17 entities changed content (all `x_mitre_domains`), 6
   were added and 237 relationships were added. The timestamp-only ones are counted as "touched" and
   not listed. Loading an older
   release needs `--force`.
8. **Vulnerability scope** (`TL_NVD_SCOPE=relevant` by default): KEV CVEs, CVEs matching the
   org's tech-stack CPEs, and every CVE the platform has seen (feeds, ATT&CK text). They're kept
   current from NVD's change feed. `all` builds a full mirror. CVE rows can exist as **stubs** before
   NVD answers. Each source writes only its own columns (NVD: CVSS/CWE/CPE/refs; KEV connector: KEV
   facts; EPSS: probability; OSV: advisories and packages), so a refresh never erases another source's
   data.
9. **KEV is read from the Phase 1 connector's sightings**, not downloaded twice. NVD's own
   `cisaExploitAdd` fields confirm it.
10. **Exploit signals are computed when read**, from KEV, CISA's SSVC "exploitation" decision point,
    and NVD references tagged *Exploit*. Each signal names its source. Phase 4 turns them into a
    `patch_priority`.

## Consequences
* One generic traversal serves every "show X linked to Y" question. The cost is that the database
  can't enforce edge endpoints, so dangling refs are possible: the API drops edges whose other node
  can't be resolved.
* Feed-named local entities can duplicate an ATT&CK entity that ATT&CK adds later. New links go to
  ATT&CK, but old edges keep pointing at the local entity until a merge step exists (Phase 4 backlog).
* The full Enterprise bundle is about 54 MB of JSON and is parsed in memory (a few hundred MB of RAM
  during a load, once per release).
