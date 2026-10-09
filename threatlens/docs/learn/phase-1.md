# Phase 1 — Collecting threat data without poisoning yourself

## Concept
"Collection" is the intelligence-cycle step after Direction (the PIRs from
Phase 0). For a TIP it means pulling indicator feeds on a schedule and turning
them into a deduplicated store of normalized observables, with every row
traceable to the source and the exact document it came from.

Three properties separate a usable collection layer from a feed aggregator:
1. **Safe**: feed content is attacker-influenced, and the platform's own
   fetcher must not be turned against internal networks (SSRF).
2. **Idempotent**: re-running a feed changes timestamps, not row counts.
3. **Discriminating**: popular, shared and own infrastructure doesn't
   become a block-list entry just because a feed mentioned it.

## Why it matters
* **SSRF**: a TIP fetches URLs it didn't choose: feed endpoints, redirects,
  and later enrichment targets. If a redirect can point it at
  `169.254.169.254` (cloud metadata) or `10.0.0.5:6379` (Redis), an attacker
  who controls a feed or a DNS record gets inside your network. Checking the
  URL string isn't enough. DNS can resolve a harmless-looking name to a
  private address, and it can resolve differently the second time (rebinding).
  So the check happens on the **resolved address at connect time**, on every hop.
* **Normalization before dedup**: `HXXP://Evil[.]COM/`, `http://evil.com/` and
  `http://evil.com` are the same indicator. Without one canonical form you
  get three rows, triple-counted "corroboration", and three alerts.
* **Bogon rejection**: feeds routinely contain `127.0.0.1`, `10.x` and
  documentation ranges. Blocking them is useless at best. A feed listing
  `8.8.8.8` or `github.com` is a false positive that can take down production.
* **Provenance**: when an indicator causes a block, the first question is
  "who said so, and when?" Raw-document archiving plus per-source sightings
  answer that, and let you reprocess history after fixing a parser bug.
* **Licences are data**: abuse.ch, OpenPhish and others forbid commercial
  use or redistribution on their free tiers. Recording that per source
  now lets exports enforce it later.

## How it works here
* `net/guard.py` + `net/http.py`: `SafeHttp`, the only outbound client. A
  custom transport resolves names itself and refuses private, loopback,
  link-local, CGNAT and metadata addresses (both IPv4 and IPv6, including
  mapped and 6to4 forms) **at connect time**. Redirects are followed by hand
  and re-checked. Bodies are capped while streaming. Retries back off with
  jitter and honour `Retry-After`. Conditional GET uses stored ETags.
* `ioc/`: `extract()` finds candidates in free text, refangs `hxxp` and
  `[.]`, then `normalize()` validates and canonicalizes each one. It returns
  either an `Observable` or a `Rejected` with a reason.
* `connectors/`: one class per feed with a `SourceInfo` contract (licence,
  reliability, upstream, interval, minimum gap) and a `parse()` that raises
  `SchemaDriftError` when the format changes, instead of silently returning nothing.
* `collect.py`: `Collector.run()` fetches, archives the raw body, parses,
  normalizes, merges duplicates within the document, applies the allowlist,
  upserts in batches of 500, then records the run and the source's health.
* `allowlist.py`: suppresses own assets, manual entries and Tranco top-N.
  It only *flags* CDN ranges and URLs hosted on popular domains.
* `jobs.py`, `worker.py`, `cli.py`: the same collector runs from an arq cron
  tick, an admin API trigger, or `threatlens collect`.
* `auth.py`: hashed API keys, viewer < analyst < admin, per-key rate limits,
  and an audit log for every state-changing call.

## Hands-on exercise
Use a scratch SQLite database so nothing touches the real stack (PowerShell
syntax; in bash use `export`):

```powershell
$env:TL_DATABASE_URL = "sqlite+aiosqlite:///./scratch.db"
$env:TL_DATA_DIR = "./scratch-data"
$env:TL_LOG_JSON = "false"
uv run threatlens init-db
```

1. `uv run threatlens allowlist-refresh`, then `uv run threatlens collect cisa_kev feodo`.
   Run the same command again. Why is the status `too_soon`? Add `--force`:
   why is it now `not_modified` or `unchanged` with `new = 0`?
2. `uv run threatlens sources`. Which sources say `(non-commercial)`? Find the
   clause in each licence page that justifies the flag.
3. `echo "beacon to hxxp://evil-c2[.]net/a and 10.0.0.1" | uv run threatlens extract --rejected`.
   Why was `10.0.0.1` rejected, and why is that safer than keeping it?
4. Create an admin key (`uv run threatlens keys create me --role admin`),
   start the API (`uv run threatlens api`) and `POST /api/v1/allowlist` a
   CIDR for one Feodo IP. Read `GET /api/v1/indicators/{id}` before and after.
   Then delete the entry and watch the indicator come back.
5. In `tests/test_http.py`, read `test_redirect_to_metadata_is_refused`.
   Explain why checking the URL before the request would not have caught it.

## Common mistakes
* Validating URLs as strings instead of checking the address actually connected to.
* Following redirects automatically with the HTTP library's default policy.
* Deduplicating on the raw string (`Evil.com` ≠ `evil.com`).
* Treating a parser that returns zero items as "the feed is empty". It is
  usually schema drift, and it should fail loudly.
* Hiding allowlisted values instead of labelling them. You lose the
  evidence that a feed is noisy.
* Ignoring a feed's stated fetch limit. Spamhaus, for one, firewalls clients
  that download too often.
* Storing API keys in plaintext, or comparing them with a slow password hash
  on every request. With 256 bits of entropy, SHA-256 is the right tool.
