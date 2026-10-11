# ADR 0011: Live Verify and Bulk check; self-hosted JavaScript

Date: 2026-10-11 · Status: accepted · Amends the "no JavaScript" rule of the analyst UI

## Context
Step 2 of making ThreatLens work like the SOC platform the user knows: one box that runs a full
investigation of a value and shows it **as it happens**, and a bulk check whose rows arrive while
it runs, with a detail pane and actions on the results. Providers answer in 0.1–10 s; waiting for
the slowest before showing anything made a lookup feel broken. The user asked for it to work "real
time" and allowed self-hosted JavaScript (2026-10-11).

## Decisions

### 1. JavaScript: one self-hosted file, progressive enhancement
* CSP adds `script-src 'self'; connect-src 'self'`. Everything else stays (`default-src 'none'`,
  no inline styles or scripts, no third-party origins, `form-action 'self'`).
* `static/app.js` is plain JavaScript: no framework, no build step, no `eval`. It reads streams,
  places **server-rendered** HTML by element id, and handles selection, filtering and in-page
  actions. It never builds markup from data.
* Every page still works without it: Verify waits for all providers and renders the result; Bulk
  check posts and renders all rows; actions post forms and show a result page.

### 2. One rendering path
The page and the stream render the same Jinja macros (`_verify.html`, `_bulk.html`). The stream
sends `{"ops": [{"op": "replace"|"append", "id", "html"}], "progress"?, "done"?, "error"?}`, one
JSON object per line (`application/x-ndjson`, `Cache-Control: no-store`). Using `fetch` streaming
instead of EventSource also allows POST (bulk check with files).

### 3. The lookup streams; the old call is the same code
`EnrichmentService.lookup_stream` yields `start` (local knowledge and the providers about to be
asked), then one `enricher` result per provider as it completes (`asyncio.as_completed`), then
`done` (the full lookup). `lookup()` consumes the stream, so there is one implementation. If the
reader goes away, the providers still running are cancelled.

### 4. Acting on a verdict
* **Block** reuses `/ui/blocklist` (ADR 0010); with `Accept: application/json` it answers in place.
* **Flag malicious / Not malicious** (`/ui/verify/flag`) is the TP/FP feedback of ADR 0008. Flagging
  a value we have never seen records it as an **analyst-submitted** indicator (label
  `analyst-submitted`, confidence 80, no feed sighting, audited `indicator.submit`) scored from the
  analyst signal. "Not malicious" on an unknown value is refused (nothing claims it is bad), as is
  any flag on a value whose indicator is above the analyst's clearance.
* **Auto-block malicious** in Bulk check blocks malicious results in *monitor* mode as they arrive,
  through the same guard and audit as any block.

### 5. Disclosure stays governed by TLP
Second-opinion links (VirusTotal, AbuseIPDB, Shodan, GreyNoise, Censys, urlscan, crt.sh,
MalwareBazaar) are a disclosure when clicked, so they follow the enricher sinks: portals that
publish searches only at TLP:CLEAR, the rest up to TLP:GREEN, none above. Links open with
`rel="noopener noreferrer"`. Values shown or posted by the pages are defanged (the server refangs);
refusal messages in JSON are defanged too.

### 6. Limits
Verify 60 lookups/min and Bulk check 20/min per account; bulk ≤ 500 values, ≤ 10 files of ≤ 5 MB
each (binary files are skipped with a note); 8 lookups in parallel sharing one metered-call budget.

## Consequences
* Tests assert the only `<script>` on any page is our `app.js` (`tests/uihelp.py`).
* Rows of a bulk check arrive in completion order and are re-sorted worst-first when it finishes.
* A slow provider no longer delays the others; the verdict appears when the last one answers or
  times out (its card then shows the previous answer, marked "older answer").
