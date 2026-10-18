# ADR 0020: Detection engineering

Date: 2026-10-18 · Status: accepted · Phase 7

## Context
Phase 7 turns intelligence into detections:
* Sigma rules from indicators, compiled for Splunk, KQL, Elastic and Wazuh;
* Suricata and YARA rules;
* hunt queries per ATT&CK technique, with data sources and false-positive notes;
* ATT&CK Navigator layers;
* coverage gaps against the organisation's own rule inventory;
* a retro-hunt hook for new high-priority indicators.

Every generated rule must pass syntax validation and carry metadata: author, date, references,
ATT&CK tags, confidence and false-positive notes.

## Decisions
1. **Rules are grouped by purpose, not one per indicator.** Labels pick the purpose, and each
   purpose carries its ATT&CK tactic/technique and false-positive notes:
   * C2 → T1071.001
   * malware delivery → T1105
   * phishing → T1566.002
   * anonymiser → T1090.003
   * known-bad file → T1204.002

   Values are chunked at 500 per rule to stay within SIEM query limits.
2. **Sigma first, then compiled with pySigma** (1.5.x, the version the current Splunk, Kusto
   and Elasticsearch backends support):
   * log sources: `network_connection`, `firewall`, `dns_query` (domain and subdomains), `proxy`,
     and `process_creation` with Sysmon `Hashes`;
   * output: Splunk SPL, KQL (Sentinel / Defender) and Elastic Lucene.

   pySigma's validators run on every rule, with exceptions:
   * `custom_attributes` (our `x_argus_*` fields);
   * the repository-wide duplicate checks;
   * `tlpv1_tag` (we tag TLP 2.0);
   * **`attacktag`, which downloads MITRE data at run time.** All outbound traffic goes through
     the guarded client and tests never touch the internet, so ATT&CK tags are checked offline
     against the ATT&CK v20 tactic list (v18 split Defense Evasion into Stealth and Defense
     Impairment).
3. **Wazuh is native, not pySigma.** No pySigma backend for Wazuh exists. Argus writes Wazuh
   rules over its CDB list exports (ADR 0019) and checks the XML: unique custom ids
   100000–120000, a description and a list per rule.
4. **Suricata rules** cover IP (and CIDR), DNS `dns.query`, TLS `tls.sni` and HTTP
   `http.host`/`http.uri`.
   * **sids:** stable (hashed into 9,100,000–9,999,998) and probed past collisions within a
     generation.
   * **Validation, two levels:**
     * `suricataparser` plus our own checks: msg, sid, rev, classtype and metadata; msg text
       without `;`, `"` or `\`; unique sids.
     * **The real engine:** CI runs `suricata -T` (jasonish/suricata:7.0) on every rule shape.
   * **What the engine caught:** an unescaped `;` and `"` in a URL's msg, and `nocase` on
     `http.host` (Suricata 7 lowercases that buffer and rejects the combination).
   * **Not generated: JA3.** No feed in the catalogue supplies JA3 fingerprints.
5. **YARA rules use `import "hash"`** for file hashes. They are compiled with yara-python, and a
   test shows the rule matches the right content and not other content. These rules read whole
   files, so they suit retro-scans, not inline scanning. No string-based YARA is generated: no
   feed supplies licensed strings.
6. **The hunt library** (`detect/hunts.yml`):
   * 14 hand-written Sigma hunts for common techniques;
   * each with ATT&CK tags, data-source requirements and false positives;
   * compiled to all three backends at first use.

   They are for hunting, not paging.
7. **Navigator layers** (format 4.5, ATT&CK version from the loaded release) for any malware,
   tool, actor or campaign, from ATT&CK and feed `uses` relationships.
8. **Coverage** compares an imported Sigma inventory with *relevant* techniques:
   * **Inventory:** `.yml`, `.yaml` or a zip; techniques come from `attack.tNNNN` tags, and
     re-imports update by rule id.
   * **Relevance:** watched by a PIR (weight 5) or used by malware and actors our current
     indicators point at (1 per family).
   * **Coverage rule:** a sub-technique rule covers its parent.
   * **Output:** gaps, plus gap and coverage Navigator layers.
9. **Retro-hunts.** Every 15 minutes, indicators that newly reach 80 get a pack:
   * their Sigma rules and conversions, with a 30-day lookback;
   * stored in `retro_hunts`, marked with the strictest TLP of the indicators, and shown within
     the reader's clearance.

## Consequences
* Generated rules contain indicator values, so they are TLP-marked like the intelligence they
  came from: a Sigma `tlp.*` tag, YARA metadata, Suricata metadata and the pack README. Only
  indicators within the requester's clearance are used.
* The inventory import trusts YAML structure only (`yaml.safe_load`, size and count limits);
  rules are stored, never executed.
* Licences: rules are for our own detection, which the source terms allow. Sharing the packs
  outside follows the same rules as Phase 6 exports.
* pySigma depends on `diskcache` (PYSEC-2026-2447, pickle in its cache directory, no fixed
  release yet). Argus never uses that cache: only the ATT&CK and D3FEND data loaders do, and the
  validators that call them are disabled. CI ignores this one advisory with that justification.
  Re-check when diskcache ships a fix.
