# ADR 0015: Threat-intel pages in Argus; the API accepts the session

Date: 2026-10-14 · Status: accepted · Builds on ADR 0013 (Argus) and 0011 (live verify)

## Context
Step 3 of merging ReconX and ThreatLens into Argus: Verify, Bulk check, Indicators, Cases,
Blocklist, Feed catalog, Assets and Settings rebuilt as Argus pages. The REST API (`/api/v1`)
already does almost all of it, but only with API keys; the classic UI used server-rendered
HTML for the live streams and form posts for settings.

## Decisions
1. **`/api/v1` accepts an API key or the signed-in session.** Same roles, same TLP clearance,
   same rate limits (bucket per user). A session may change state only from a same-site page:
   `auth.same_origin` (Sec-Fetch-Site, falling back to Origin) is now shared by the classic UI
   and the API. API keys are unchanged.
2. **One small Argus module (`argus_api.py`) for what had no JSON form**: Verify and Bulk check
   streams as NDJSON events (start / provider / done; start / row / done) carrying the classic
   cards' plain-language headlines and fields (`threatlens.verify`), flagging, block counts,
   decline and extend, the blocking policy, feed tokens (shown once, `no-store`), the
   never-block list, and a custom feed's edit form (never its key).
3. **Defang on the server**: every string in the Verify and Bulk payloads is defanged before it
   leaves; live values appear only in the second-opinion links, which the marking allows. A
   test found the canonical key (`type|value`) leaking a live value, so it is no longer sent.
   The pages also defang free text (feed context) and refang only on an explicit Copy.
4. **Pages** (`web/src/pages`): Indicators (filters in the URL) and indicator detail (score
   breakdown or patch priority for CVEs, reports with context, notes, feedback, block, add to
   case); Verify (cards fill in as providers answer; `providers=false` in the URL keeps it
   local); Bulk check (paste or upload, rows stream in, pick and block or flag); Blocklist
   (counts, views, request/approve/decline/lift/extend, block form); Cases and case detail
   (evidence, notes, write-up, close/reopen, Markdown report); Feed catalog, feed page and
   add/edit form; Assets (inventory, software, imports); Settings (policy, export tokens,
   never-block). Vulnerabilities, ATT&CK and Search still open the classic screens.

## Consequences
* Anything the API can do, a signed-in browser can do within the same roles; CSRF is covered
  by the same-site rule plus the SameSite=Strict cookie.
* The classic `/ui` pages keep working until step 4 retires them.
