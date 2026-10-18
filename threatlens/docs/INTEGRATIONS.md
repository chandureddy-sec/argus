# Integrations

How Argus shares intelligence (ADR 0019).

* **The sharing rules.** Every path below applies them:
  * nothing above the destination's TLP cap, and TLP:RED never;
  * nothing from a source whose licence forbids redistribution;
  * only indicators at or above the destination's minimum score.
* **Where it's configured.** Platform → **Integrations** (admin). Exports and TAXII need no
  setup beyond an API key or feed token.
* **Verification.** API details were checked against each vendor's current documentation on
  2026-10-18; links are below.

## Try any integration without the product: the sink

`scripts/sink.py` answers like Splunk HEC, Elastic, MISP and a webhook, and logs what it
receives (auth schemes only, never the secret):

```powershell
uv run python scripts/sink.py 8099 sink.jsonl          # terminal 1
$env:TL_ALLOW_LOOPBACK_DESTINATIONS = "true"           # terminal 2: let integrations reach 127.0.0.1
uv run uvicorn threatlens.api.app:create_app --factory --port 8010
```

Add an integration with URL `http://127.0.0.1:8099` and **internal network** ticked, then press
**Test** and **Push now**.

Live run, 2026-10-18 (Feodo, Tor exits and CISA KEV collected that day; minimum score 30):

| Destination | Test | Push | Second push |
|---|---|---|---|
| Splunk HEC → sink | "HEC accepted a test event" | 1,210 indicators, success | 0 (cursor) |
| Elastic → sink | "cluster answered" | 1,210, success | 0 |
| MISP → sink | "MISP answered" | 1,210 (one event per TLP), success | 0 |
| Webhook → sink | test message sent | 1,210, success | 0 |
| Slack → sink | test message sent | alerts only | — |

## TAXII 2.1 (any TAXII client, MISP, another Argus)

* **Discovery:** `https://<argus>/taxii2/`.
* **API root:** `/taxii2/api/`.
* **Collections:**
  * TLP:CLEAR ≥60
  * TLP:CLEAR ≥30
  * TLP:GREEN ≥60
  * TLP:AMBER ≥60 (needs an AMBER-cleared key)
* **Authentication:** an API key as `X-API-Key`, `Authorization: Bearer`, or the **password** of
  HTTP Basic (any user name).

```python
from taxii2client.v21 import Server          # pip install taxii2-client (OASIS)
server = Server("https://argus.example.org/taxii2/", user="taxii", password="tl_...")
col = next(c for c in server.default.collections if c.title.startswith("TLP:CLEAR, high"))
envelope = col.get_objects(limit=500)        # follow envelope["next"] while envelope["more"]
```

Live run against a local instance: the official client listed 4 collections and pulled 1,214
objects in 7 pages in 0.17 s. The objects were indicators, malware, relationships, identity and
TLP 2.0 marking definitions, and they pass `stix2-validator` (STIX 2.1).

**Another Argus** consumes it as a feed: Feed catalog → Add feed, format **TAXII 2.1
collection**, the collection URL, auth header `X-API-Key` and the key. Only new objects are
pulled after the first run, and producer markings are kept. `tests/test_share.py` runs exactly
this against a live app.

## MISP

* **Pull** (MISP → Argus):
  * Feed catalog → Add feed, format **MISP**, URL `https://misp/attributes/restSearch`, with
    the automation key (header `Authorization`).
  * The first pull reads published `to_ids` attributes of the last 30 days; later pulls read
    only changes.
  * `tlp:` tags set the marking. Composite types keep their indicator half (`ip-dst|port`,
    `filename|sha256`).
  * **Internal network** for a MISP in the LAN.
* **Push** (Argus → MISP):
  * Integration kind **MISP**, base URL and automation key.
  * Each push makes one event per TLP level (tagged `tlp:clear`, `tlp:green`, …), with
    `to_ids` attributes `ip-dst`, `domain`, `url`, `md5`, `sha1`, `sha256` and `email-src`.
  * Distribution defaults to 0 (your organisation only); publishing is off unless ticked.
* **API:** `POST /attributes/restSearch`, `POST /events/add`, `GET /servers/getVersion`, auth
  header `Authorization: <key>` (MISP OpenAPI spec).

## Splunk (HTTP Event Collector)

Integration kind **Splunk HEC**: base URL (e.g. `https://splunk:8088`), HEC token, and an
optional index and sourcetype (default `argus:indicator`).

* **Request.** `POST /services/collector/event` with `Authorization: Splunk <token>`, events
  concatenated in one body (Splunk "Format events for HTTP Event Collector").
* **Each event:** value, type, score, verdict (`revoked` for analyst false positives), TLP,
  labels, licensed sources, first/last seen, valid until, STIX id.
* **Search:**
  `index=threatintel sourcetype=argus:indicator verdict=malicious | lookup … | stats …`

## Elastic / OpenSearch

* **Setup:** integration kind **Elastic / OpenSearch**, cluster URL, an encoded API key (or a
  user and password), and an index (default `argus-indicators`).
* **Request:** `POST /_bulk` (NDJSON); documents are ECS threat-intel shaped.
* **Document fields:**
  * `event.kind: enrichment`, `event.category: threat`, `event.type: indicator`;
  * `threat.indicator.type`, `.ip`, `.url.full`, `.file.hash.*`, `.confidence`
    (High/Medium), `.marking.tlp` (CLEAR…AMBER+STRICT, `tlp_version` 2.0), `.first_seen`,
    `.last_seen`, `.provider`;
  * `threat.feed.name`.
* **Ids:** documents are keyed by the STIX id, so re-sends update instead of duplicating.
  Elastic's indicator-match rules can use the index directly.

## Microsoft Sentinel (STIX objects upload API)

* **Setup:** integration kind **Sentinel**, with the Entra tenant id, app (client) id, client
  secret and Log Analytics workspace id. The app needs the **Microsoft Sentinel Contributor**
  role on the workspace.
* **Token:** `POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` (client
  credentials, scope `https://management.azure.com/.default`).
* **Upload:**
  `POST https://api.ti.sentinel.azure.com/workspaces/{id}/threat-intelligence-stix-objects:upload?api-version=2024-02-01-preview`.
* **Body:** `{"sourcesystem": "<org identity>", "stixobjects": [...]}`, at most 100 objects per
  request (identity + 99 indicators).
* **Limits:** Microsoft's preview terms apply; 100 requests per minute.
* **Tested:** against recorded request shapes only (`tests/test_share.py`). A live run needs an
  Azure workspace.

## Wazuh

**Lists:** point Wazuh at a CDB export and match alerts against it:

```bash
curl -fsS https://argus/feeds/<token>/indicators/wazuh-ip.cdb -o /var/ossec/etc/lists/argus-ip
# ossec.conf <ruleset>: <list>etc/lists/argus-ip</list>
# rule:  <list field="dstip" lookup="address_match_key">etc/lists/argus-ip</list>
systemctl restart wazuh-manager      # lists are built when the analysis engine starts
```

* **Alert webhook** (sightings + enrichment): copy `integrations/wazuh/custom-argus` to
  `/var/ossec/integrations/` and add an `<integration>` block. The script's header has the
  exact block; use an **analyst** API key.
* **What happens per alert:**
  * Argus records a "seen in our environment" sighting for every value it already holds;
  * the answer (verdict, score, action) is written to `integrations.log`;
  * the `environment` alert rule can notify the SOC.
* **Live run:** the script ran on Windows against a local instance, exit 0, and the sighting
  appeared in the indicator's threat journey.

## Any SIEM: the sightings API

```bash
curl -X POST https://argus/api/v1/sightings -H "X-API-Key: tl_..." -H "Content-Type: application/json" \
  -d '{"system": "splunk", "values": ["185.220.101.34", "beacon to evil[.]example"], "context": {"host": "ws-12"}}'
```

* Values may be raw text: indicators are extracted from it.
* Only values Argus already holds are recorded; log lines never become intelligence.
* The answer lists each match with its verdict and recommended action (`block`, `investigate` or
  `monitor`), within the key's TLP clearance.

## Alerts: Slack, Teams, Telegram, email, webhook

* **Channels** are integrations of these kinds:
  * **Slack** incoming webhook URL;
  * **Teams** Workflows webhook URL (an Adaptive Card is posted);
  * **Telegram** bot token + chat id (`sendMessage`);
  * **email** over SMTP with STARTTLS;
  * **webhook**.
* **Rules** live under Response → **Alerts** (admin):
  * high-priority indicator (score ≥ N);
  * matches our priorities (PIR or asset relevance);
  * exploited CVE in our stack (CISA KEV);
  * seen in our environment.
* **Guarantees:**
  * each alert is sent once;
  * only to channels whose TLP cap allows it;
  * at most `TL_ALERT_MAX_PER_HOUR` (default 20) per channel per hour, the rest summarised in one
    message;
  * values are defanged.
* **Live run:** the "seen in our environment" rule raised one alert for a SIEM sighting of the
  live Feodo C2 and delivered it to the Slack sink. A second evaluation raised nothing.

## Exports (firewalls, scripts)

`/feeds/<token>/indicators/<format>?min_score=60`; create the token under Settings → Feed export.

* **Formats:**
  * `ip.txt`, `domain.txt`, `url.txt` (no scheme), `sha256.txt`: Palo Alto / FortiGate External
    Dynamic Lists;
  * `indicators.csv` (formula-safe), `indicators.json`;
  * `stix.json`;
  * `wazuh-ip.cdb`, `wazuh-domain.cdb`, `wazuh-url.cdb`.
* **Blocklist only:** the enforced blocklist (four-eyes approved) stays at
  `/feeds/<token>/{ip,domain,url}.txt` (ADR 0010).
