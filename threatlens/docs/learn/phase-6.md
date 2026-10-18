# Phase 6: Dissemination

## Concept
Intelligence that stays inside the platform protects nobody. Dissemination gets the right
intelligence to the right place, in a form the receiver can use without retyping it:
* to firewalls, as blocklists;
* to SIEMs, for matching against logs;
* to partners, as STIX over TAXII;
* to MISP communities;
* to people, as alerts.

Two standards carry most of it:
* **STIX 2.1** is the data model. An `indicator` holds a *pattern*
  (`[ipv4-addr:value = '1.2.3.4']`), validity dates, confidence, a TLP marking and its producer.
  `relationship`s link it to the `malware` it indicates.
* **TAXII 2.1** is the transport: HTTPS + JSON, with collections a client pages through using
  `added_after` and `next`.

## Why it matters
* **Sharing rules are promises.** Sharing has two directions of risk:
  * share too little and the SOC never benefits;
  * share too much and you break a promise. A TLP:AMBER report from a partner, or a feed whose
    licence forbids redistribution, must not end up in someone else's MISP. One leak and the
    community stops sharing with you.
* **Formats matter as much as content.** A firewall wants a bare list, a SIEM wants fields it can
  join on, and a person wants a short, defanged message.
* **Alerts are expensive.** An alert storm teaches people to ignore the channel. Deduplication
  and rate limits are part of the feature, not polish.

## How it works here
* **One rule set** (`share/select.py`) decides what may leave, for every path:
  * at most the destination's TLP, and never RED;
  * a source that allows redistribution (or our own analysts);
  * at least the minimum score.

  The Integrations page previews how many indicators qualify and why the rest stay home.
* **STIX** (`share/stix.py`):
  * TLP 2.0 marking definitions with their official ids; deterministic indicator ids, so
    re-sends update;
  * revocations for analyst false positives;
  * malware and `indicates` relationships when their source may be shared.
* **TAXII** (`/taxii2/`) is read-only and computed live from the store. It has collections per
  TLP and confidence tier, paging and filters, and API-key auth via HTTP Basic (what clients
  send).
* **Integrations** (`share/sinks.py`, `share/integrations.py`): Splunk HEC, Elastic bulk (ECS),
  Sentinel's STIX upload API, MISP events and webhooks.
  * Each push follows a cursor, so nothing is sent twice.
  * Secrets are sealed; runs are recorded.
  * "Internal network" opens private ranges for one destination, never cloud metadata.
* **Exports** (`/feeds/<token>/indicators/<fmt>`): EDL lists, CSV, JSON, STIX and Wazuh CDB.
* **Sightings** from our SIEM (`/api/v1/sightings`, the Wazuh webhook) record "seen in our
  environment" without changing scores.
* **Alerts** (`share/alerts.py`):
  * rules `score`, `pir`, `kev_asset` and `environment`;
  * a unique dedup key per rule; a TLP cap per channel; an hourly limit with a digest.

## Hands-on exercise
1. Start `scripts/sink.py` and a demo instance with `TL_ALLOW_LOOPBACK_DESTINATIONS=true`.
2. Integrations → Add → Splunk HEC → `http://127.0.0.1:8099`, internal network ticked. Press
   **Test**, then **Push now**, then **Push now** again. Why does the second push send 0?
3. Change the integration's minimum score. Why does the next push send everything again?
4. With `taxii2-client`, list the collections using a GREEN-cleared key, then an AMBER-cleared
   one. What changes?
5. Post a sighting for a known C2 IP to `/api/v1/sightings`. Open its indicator: what does the
   threat journey say? Did the score change, and why not?
6. Run `uv run python -m stix2validator <file>` on `stix.json` from the export URL.

## Common mistakes
* **One rule per path.** If TAXII, exports and SIEM pushes each check TLP their own way, one of
  them will eventually get it wrong. Keep one function.
* **Forgetting licences.** "It's public on the internet" is not a licence. Spamhaus DROP, for
  example, allows commercial use but not redistribution.
* **Random ids on re-send.** The receiver then holds two copies of everything. Use stable ids.
* **Treating a SIEM hit as evidence of maliciousness.** It is evidence that the value reached
  *you*. Score on feed reports; alert on the hit.
* **Sending secrets or real values to chat.** Defang for people. Keep tokens out of logs and
  error messages: a Telegram bot token travels in the URL path, so redact it.
* **Paging on low-precision timestamps.** If `date_added` is truncated to milliseconds,
  `added_after` returns the last object again. Use microseconds, or an opaque cursor.
