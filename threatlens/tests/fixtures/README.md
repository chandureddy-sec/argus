# Test fixtures

Connector contract tests parse these files; no test touches the network.

| File | Origin | Why |
|---|---|---|
| `cisa_kev.json` | **Real**, trimmed to 3 entries (catalog 2026.10.04) | CC0 — redistribution allowed |
| `feodo.json` | **Real**, first 3 entries | CC0 |
| `spamhaus_drop.ndjson` | **Real**, first records of v4 and v6 plus their metadata lines | DROP terms allow redistribution with attribution; the copyright line is kept |
| `tor_exits.txt` | **Real**, first 3 lines | public list |
| `urlhaus.csv` | **SYNTHETIC** values in the real format (header copied from the live dump) | abuse.ch terms restrict redistribution |
| `threatfox.json` | **SYNTHETIC**, built from the documented response fields | API needs an Auth-Key we don't have yet; redistribution restricted |
| `otx.json` | **SYNTHETIC**, built from the OTX SDK's documented pulse structure | API needs a key; not yet verified against a live response |
| `openphish.txt` | **SYNTHETIC** | community feed is non-commercial and not for redistribution |

Synthetic values use IANA/ICANN-owned names and addresses (`*.example.*`,
`93.184.216.34`, `192.0.43.10`) so no real third party is implicated. When a
key becomes available, replace the synthetic ThreatFox/OTX fixtures with
trimmed real responses and note the date here.
