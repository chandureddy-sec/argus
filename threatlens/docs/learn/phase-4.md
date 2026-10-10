# Phase 4: Scoring, trust, TLP and feedback

## Concept
A feed says "this IP is bad". Phase 4 turns that claim into a **priority**: how much to care about
it *now*, for *this* organization, and why. Four ideas do the work:

* **Trust (Admiralty grading).** Intelligence services grade every report twice:
  * how reliable the *source* has been (A "completely reliable" to F "cannot be judged");
  * how credible this *piece of information* is (1 "confirmed" to 6 "cannot be judged").

  A grade-B feed's report is worth less than a grade-A one, and a "probably true" (2) item more
  than a "doubtful" (4) one.
* **Decay.** Indicators go stale at different speeds. An IP is re-assigned in days, a phishing URL
  dies in a week, a file hash stays that file forever. Each type gets a half-life: IP 10 days,
  URL 7, domain 30, hash 180.
* **Corroboration and relevance.** Two *independent* sources agreeing is evidence; the same list
  mirrored twice is not. A threat aimed at your stack, brand or assets matters more than the
  same threat elsewhere.
* **TLP 2.0 (Traffic Light Protocol).** Sharers mark intelligence CLEAR, GREEN, AMBER,
  AMBER+STRICT or RED. The receiver promises not to pass it on further than the marking allows,
  and that includes looking it up on a third-party service.

## Why it matters
* An unscored list of 40,000 indicators is unusable. Blocking all of it breaks things, and
  reading all of it is impossible. Priority is what turns collection into a to-do list.
* Without decay, a list only grows: last spring's C2 server, now a hosting customer's website,
  stays "malicious" forever. False positives destroy trust in the platform.
* Without explanations, analysts can't challenge a score, and nobody can tune the model.
* Breaking TLP breaks the sharing relationship. One leaked AMBER report can get you dropped
  from the community that gave it to you.

## How it works here
* `config/scoring.yaml` holds every number. `threatlens.scoring.model.score` is a pure function
  of *signals*:
  * feed sightings;
  * stored enrichment findings;
  * an analyst's "true positive".

  It computes:

      priority = clamp(0, 100, base + corroboration + relevance − penalty)
      base     = strongest report: confidence × reliability × credibility × feedback × decay(age)

  Every term, signal and config version is stored in `indicators.score_breakdown`. The indicator
  page shows it as a formula such as `70.75 + 0 + 10 − 0 = 80.75`.
* Feeds that report a host as offline (URLhaus, Feodo) make its report age from `last_online`.
  In the first live run 5,262 URLhaus URLs and 4 of 5 Feodo C2s expired for that reason.
* Collection runs score what they touched. The daily job (`threatlens rescore`) re-derives
  source weights, recomputes CVE patch priorities (P1–P4, KEV is a floor) and re-scores
  everything. Indicators below 10 become `expired`, and come back if a feed lists them again.
* Analyst feedback:
  * **False positive** sets the score to 0 permanently.
  * **True positive** adds a grade-A report.
  * Every verdict re-derives the reporting feeds' weights from all verdicts; each change is in
    the audit log.
* TLP: every key and user has a clearance (viewer GREEN, analyst AMBER+STRICT, admin RED by
  default). Anything above it doesn't exist for that reader: API, UI, graph, lookups, assets.
  Providers are *sinks* with a maximum level, and nothing AMBER or RED ever leaves.

## Hands-on exercise
1. `.\tl rescore`. Note how many indicators expired, then open `/ui` → *Indicator stats →
   Priority*. Which feed has the most expired indicators, and why?
2. Open the highest-priority IP (`/ui/indicators?sort=priority&type=ipv4-addr`). Recompute its
   score by hand from the *Score* panel: confidence × weight × decay, plus each term.
3. Look up `162.243.103.246` (Phase 3 said "block"). Why is it "monitor" now? Which evidence line
   tells you?
4. Mark an indicator *False positive* with a note, then open `/ui/sources`. What happened to
   that feed's weight factor, and why so little? (Work out `factor(0, 1)` from the formula in
   `config/scoring.yaml`.)
5. Create a viewer key with `--clearance TLP:CLEAR`, set one indicator's TLP to AMBER (SQL), and
   try to find it through `/api/v1/indicators`, `/api/v1/graph/node`, and a lookup with an
   analyst key that has `--clearance TLP:GREEN`.
6. Edit `corroboration.per_source` in `config/scoring.yaml` and run `.\tl rescore` again. What
   does the `config` field in a breakdown show now?

## Common mistakes
* Counting mirrors as corroboration (URLhaus + ThreatFox are one upstream: abuse.ch).
* Letting relevance create a score on its own. "It mentions our brand" with no malicious report
  is a monitoring signal, not a block.
* Decaying benign evidence. "This is a Shodan scanner" doesn't become less true with time, and
  decaying it would make scores *rise* with age.
* Adjusting source weights incrementally (`weight -= 0.01` per FP). The weight then depends on
  the order of clicks and drifts; derive it from all verdicts each time.
* Filtering TLP in the UI only. The API, the graph's path search, aggregate counts and lookup
  scores are all read paths too, and a verdict computed from hidden evidence leaks it.
* Failing open: an unknown marking must be treated as RED, an unknown clearance as CLEAR.
