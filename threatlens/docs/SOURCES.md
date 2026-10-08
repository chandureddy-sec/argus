# Sources

Every external source is verified against its **current official
documentation** before a connector or enricher is written, and re-verified when
it breaks. Nothing below is marked verified until that check is done and
dated. (Phase 0 creates this register; verification happens in the phase that
builds each connector.)

Reliability uses the Admiralty source grade (A = completely reliable … F =
cannot be judged). `Upstream` names the original producer, so corroboration
doesn't count a mirror as an independent second source.

| Source | Type | Phase | Endpoint | Auth | Rate limit | Licence / redistribution | Cadence | Reliability | Upstream | Verified |
|---|---|---|---|---|---|---|---|---|---|---|
| CISA KEV | vuln | 1 | | | | | | | CISA | not yet |
| abuse.ch URLhaus | malware URLs | 1 | | | | | | | abuse.ch | not yet |
| abuse.ch ThreatFox | IOCs | 1 | | | | | | | abuse.ch | not yet |
| abuse.ch Feodo Tracker | botnet C2 | 1 | | | | | | | abuse.ch | not yet |
| AlienVault OTX | pulses/IOCs | 1 | | | | | | | community | not yet |
| Spamhaus DROP/EDROP | netblocks | 1 | | | | | | | Spamhaus | not yet |
| Tor exit list | IPs | 1 | | | | | | | Tor Project | not yet |
| OpenPhish community | phishing URLs | 1 | | | | | | | OpenPhish | not yet |
| MITRE ATT&CK (STIX) | knowledge | 2 | | | | | | | MITRE | not yet |
| NVD API 2.0 | vuln | 2 | | | | | | | NIST | not yet |
| FIRST EPSS | vuln | 2 | | | | | | | FIRST | not yet |
| OSV / GitHub Advisories | vuln | 2 | | | | | | | various | not yet |
| AbuseIPDB | reputation | 3 | | | | | | | community | not yet |
| GreyNoise Community | reputation | 3 | | | | | | | GreyNoise | not yet |
| VirusTotal | reputation | 3 | | | | | | | VirusTotal | not yet |
| urlscan.io | reputation | 3 | | | | | | | urlscan | not yet |
| MalwareBazaar | hashes | 3 | | | | | | | abuse.ch | not yet |
| crt.sh | CT logs | 3 | | | | | | | CT logs | not yet |
| RDAP | registration | 3 | | | | | | | registries | not yet |
| Tranco | allowlist | 1 | | | | | | | Tranco | not yet |

## Points to confirm during verification
These come from prior knowledge and must be checked, not assumed:
* **VirusTotal** public API terms restrict use in commercial products/services.
* **abuse.ch** APIs (URLhaus, ThreatFox, MalwareBazaar) may now require a free Auth-Key.
* **Spamhaus DROP** is free for non-commercial use; commercial use needs a licence.
* **MaxMind GeoLite2** requires an account and licence key, with its own EULA.
* **NVD API 2.0** rate limits differ with and without an API key.
* **OpenPhish community** feed terms and update cadence.
* **ransomware.live** API access and terms (spec §6).
