# Phase 7: Detection engineering

## Concept
Intelligence becomes useful in a SOC when it turns into **detections**: rules that run on logs
and traffic. Two very different kinds exist:

* **Indicator-based (atomic) detections**, such as "connection to 203.0.113.7" or "DNS query
  for evil.example". They are precise and cheap, but short-lived, because attackers change
  infrastructure. They work best generated automatically and retired by decay (Phase 4).
* **Behaviour-based (TTP) detections**, such as "Word spawning PowerShell" or "LSASS memory
  read". They are durable and survive infrastructure changes, but are noisier and need tuning.
  The ATT&CK technique is their unit.

**Sigma** is the vendor-neutral rule format. You write it once and compile it to Splunk, KQL or
Elastic with **pySigma**. **Suricata** inspects network traffic; **YARA** inspects files.

## Why it matters
* An indicator list sitting in a TIP detects nothing. A rule in the SIEM does.
* **Coverage tells you where you are blind.** Mapping your rules to ATT&CK, and comparing them
  with the techniques used by the adversaries you actually face, turns "we have 400 rules" into
  "we can't see T1190 at all".
* **Retro-hunting closes the time gap.** An indicator published today was often active last
  week. Searching history when it arrives finds compromises that real-time rules missed.

## How it works here
* **Detections → Rules from intel:**
  * **Input:** indicators at or above a score, within your clearance, grouped by purpose (C2,
    malware delivery, phishing, anonymiser, file).
  * **Output:**
    * Sigma (+ SPL / KQL / Lucene);
    * Suricata (IP, DNS, TLS SNI, HTTP);
    * YARA (hash module);
    * Wazuh (over the CDB exports).
  * **Metadata on every rule:** author, date, references, ATT&CK tags, TLP, confidence and false
    positives.
  * **Validation:** pySigma, suricataparser and our checks, yara-python and an XML parse. CI also
    runs the **real Suricata engine** (`suricata -T`) on every rule shape.
  * A zip pack is available too.
* **Hunts:** 14 Sigma hunts (PowerShell cradles, Office → shell, WMI, scheduled tasks, Run keys,
  rundll32, mshta, LOLBin downloads, script beacons, LSASS access, shadow-copy deletion, RDP,
  web shells, password spraying). Each shows its data sources and false positives, in every
  query language.
* **Coverage:**
  * **Import:** your Sigma repository (files or a zip).
  * **Relevance:** techniques watched by PIRs or used by the malware your indicators point at.
  * **Result:** the gaps, with Navigator layers to load into the ATT&CK Navigator.
* **Navigator layer** button on every malware, tool, actor and campaign page.
* **Retro-hunts:** a pack every 15 minutes for indicators that newly reach 80, to search the last
  30 days.

## Hands-on exercise
1. Detections → Rules from intel → Generate at score 60. Open the Sigma rule and switch to KQL.
   Which Sysmon event does `network_connection` map to? (Event ID 3.)
2. Download the zip pack. Run `docker run --rm -v %CD%:/r jasonish/suricata:7.0 -T -S
   /r/suricata/<file>.rules`. Does it load?
3. Hand-write a Suricata rule with `msg:"a;b"` and test it. What does Suricata say?
4. Import a few rules from the public SigmaHQ repository (rules/windows/process_creation) on the
   Coverage tab. Which relevant techniques are still gaps? Open the hunt for one of them.
5. Open QakBot (S0650) and download its Navigator layer. Load it at
   https://mitre-attack.github.io/attack-navigator/.

## Common mistakes
* **One rule per indicator.** 30,000 rules overwhelm any SIEM. Group them, and chunk the values.
* **Trusting a parser to stand in for the engine.** `suricataparser` accepted rules Suricata 7
  rejects: an unescaped `;` in msg, and `nocase` with `http.host`. Validate with the real engine
  where you can.
* **Hashing ids into a small range without handling collisions.** With 1,210 indicators in a
  900,000 range, a duplicate sid is more likely than not (birthday problem).
* **Validators that phone home.** pySigma's ATT&CK tag validator downloads MITRE data. On an
  air-gapped or SSRF-guarded platform, check tags offline.
* **Treating coverage as a percentage to maximise.** Weight by relevance: a gap on a technique
  your adversaries use matters more than ten techniques nobody uses against you.
* **Forgetting that rules carry intelligence.** A rule containing AMBER indicators is AMBER.
