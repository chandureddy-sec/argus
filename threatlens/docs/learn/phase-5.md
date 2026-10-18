# Phase 5: Analyst experience

## Concept
A threat-intelligence platform is judged at the moment a SOC analyst pastes an alert's IP or
domain into it. Everything earlier (collection, enrichment, scoring) only pays off if, in under a
minute, the analyst can answer three questions:

1. **Is it bad?** A verdict with the score and *why*.
2. **What is it part of?** Malware, actor, campaign, CVEs, ATT&CK techniques: the *pivot*.
3. **What do I do, and how do I record it?** Block, flag, open a case, write it down.

The phase builds the screens around that loop:
* the landscape (dashboard);
* the indicator page;
* search and saved views;
* bulk check;
* cases with Markdown and PDF reports.

## Why it matters
* An indicator without context forces the analyst to open five other tabs (VirusTotal, WHOIS,
  ATT&CK, the SIEM). Each tab costs minutes and leaks the indicator to third parties.
* A verdict nobody wrote down is lost at the next shift change. A case with evidence snapshots
  is the audit trail: what we knew, when, and who decided.
* Analysts repeat the same searches every day ("everything tagged qakbot", "new KEV in our
  stack"). Saved views turn them into one click.

## How it works here
* **Landscape** (`/app/landscape`, `GET /app/api/landscape`) shows:
  * a triage queue: the top new high-priority indicators, with the action to take;
  * PIR matches;
  * trending malware and techniques, and the ATT&CK tactic heat;
  * newly exploited CVEs, and the subset in our own stack (KEV vs. our stack);
  * patch priorities, geography;
  * feed health, i.e. ingestion success rates.
* **Indicator page** (`/app/indicators/:id`):
  * a verdict pill and the 0–100 score, with the full score breakdown;
  * actions: Block, Add to case, Confirm malicious, Not malicious (TP/FP feedback that also
    adjusts source weights, Phase 4);
  * analyst notes;
  * every source's report with its context;
  * `GET /app/api/indicators/{id}/related`, which adds:
    * **Pivot**: graph neighbours grouped by type. Each link names the source that asserted it
      and opens that entity's page.
    * **ATT&CK techniques**: the indicator's own, plus those its malware or actor `uses`
      (one hop further, labelled "via …").
    * **Timeline**: when each source first and last reported it, and when providers answered.
    * **Enrichment**: the *stored* answer of each provider, with no new lookup. Reading the page
      never sends the indicator anywhere; "Verify now" does, under the TLP rules of Phase 3.
* **Search** (`/app/search`): one box for everything.
  * An exact hit (an IP, CVE id, ATT&CK id, malware name or alias) opens its page.
  * Anything else lists the matching indicators, entities, CVEs and cases; `tag:` searches
    labels.
* **Saved views** (`/app/api/searches`) store a path inside Argus per account, from either the
  Search page or the filtered Indicators list. `cases.check_query` refuses anything that could
  leave Argus: other hosts, `//`, backslashes, `/api`, `/login`. Views saved by the old `/ui`
  pages still open (`cases.app_path`).
* **Bulk check** (`/app/bulk`) takes up to 500 values or an uploaded file. It streams one row per
  value, then lets you filter, select and block, flag or open a case, and export CSV (cells that
  could run as spreadsheet formulas get a leading `'`).
* **Cases** collect evidence *snapshots*: what Argus said about an item when it was added.
  `export.md` and `export.pdf` produce the report. The PDF (`threatlens/pdf.py`, fpdf2 with the
  bundled Inter font):
  * prints the TLP marking on every page;
  * writes feed text as plain text only, with control and bidi characters removed;
  * breaks long tokens and caps each table cell, so no hostile value can break the layout.

## Hands-on exercise
1. Bring up the stack (`.\tl up --build`), sign in, and open **Search**. Paste an IP from the
   landscape's triage queue.
2. On the indicator page, read the score breakdown. Which part contributes most: source grade,
   decay or corroboration?
3. In **Pivot**, open the malware family, then come back. Hover a technique chip: is it the
   indicator's own, or "via" the malware?
4. Press **Verify now**, then return. The Enrichment section now shows the stored answers and
   the Timeline an "answered a lookup" entry.
5. **Add to case** → open the case → write a conclusion → download the **PDF**. Check that the
   marking is on every page.
6. On **Indicators**, filter to `status=active`, sort by priority, and press **Save this view**.

## Common mistakes
* **Looking things up on page load.** It is tempting to enrich every indicator page
  automatically, but that spends quotas and discloses AMBER intel to third parties. Argus shows
  stored answers and asks providers only on an explicit Verify.
* **Saving arbitrary URLs as "views".** That is an open redirect. Store app-relative paths and
  validate them on the server, not just in the browser.
* **Rendering feed text as HTML or Markdown in reports.** A feed title can contain `<script>`, a
  formula (`=HYPERLINK(…)`) or right-to-left override characters. Write it as plain text,
  escape it for the format, and strip control characters.
* **A pivot without provenance.** "Linked to Emotet" is useless if you can't see who said so.
  Every edge here carries its source and how it was derived.
