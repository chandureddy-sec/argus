# ADR 0008: Scoring, trust, TLP enforcement, feedback and expiry (Phase 4)

Date: 2026-10-11 · Status: accepted · Replaces the interim verdict of ADR 0005

## Context
PROMPT §5 (Phase 4) and §7 specify a priority score, Admiralty-based source trust, TLP 2.0
enforcement on every read and export path, analyst TP/FP feedback that adjusts source weights,
and a daily expiry job. Phase 3 shipped an interim verdict (`v0-interim`) that treated every source
as independent and never decayed.

## Decisions

### 1. One scoring function for stored indicators and live lookups
`threatlens.scoring.model.score` is pure (no I/O), and is fed *signals*:
* every feed sighting;
* every malicious, suspicious or benign finding of a stored enrichment;
* an analyst "true positive".

Each signal contributes `confidence × reliability weight × credibility × feedback factor ×
decay(age)`. Then:

    priority = clamp(0, 100, base + corroboration + relevance − penalty)

* **base**: the strongest malicious or suspicious contribution.
* **corroboration**: +8 per further *independent upstream* still worth `min_signal` (15), capped
  at +24. URLhaus and ThreatFox are both abuse.ch, so together they count once.
* **relevance** (0–20) is added only while base ≥ `min_signal`. Relevance makes a real report
  more urgent; it never invents one. The hits are:
  * own asset (+20);
  * brand or domain impersonation (+15);
  * linked to malware or tools using a technique a PIR watches, or the report names one (+10);
  * the report names a watched sector or country (+5 each).
* **penalty**: half the strongest benign finding (not decayed, because it describes what the
  value is now); +15 for a shared CDN edge; +10 for a popular (Tranco) domain; +15 when RDAP
  says the domain is no longer registered.
* **Suspicious-only** evidence is capped at 59: it never reaches "malicious" on its own.
* An allowlist suppression or an analyst false positive gives 0 and `benign`.
* **Thresholds**: malicious ≥ 60 → block; suspicious ≥ 30 → investigate; benign with at least 25
  of penalty → no action; else unknown → monitor. The Phase 3 threshold was 70. At 60, a fresh
  single listing by a grade-B feed (URLhaus 80 × 0.85 = 68; Feodo 85 × 0.85 = 72) blocks, which
  is what a SOC expects of an active malware URL or C2.

Lookups (`/lookup`, `/enrich`, ReconX) use the same function. The API keeps `score` as an
integer, which ReconX's Go client reads, and adds `priority` as a float. `score_breakdown` is
now an object.

### 2. Monotonic by construction (property-tested)
Only base and the corroboration count change with time, and both only fall: every signal's
contribution decays at the same per-type half-life, and the benign penalty does not decay.
Hypothesis tests check, over random signals, relevance and penalties:
* scores stay within 0–100;
* a score never rises as time passes;
* adding an independent report never lowers it;
* decay is monotonic.

### 3. Admiralty grades
* Each source keeps its reliability grade A–F, weighted A 1.00, B 0.85, C 0.70, D 0.50, E 0.30,
  F 0.20.
* Each source now also has an information-credibility grade (1–6), which multiplies the weight:
  1–2 → 1.0, 3 → 0.9, 4 → 0.75, 5 → 0.5, 6 (cannot be judged) → 1.0.
* Per-source grades and their reasons are in `docs/SOURCES.md`.

### 4. Feed facts that change the age
URLhaus (`url_status`) and Feodo Tracker (`status`) say when a listed host went offline. A
signal's age then counts from `last_online` instead of the last fetch. This matters because
URLhaus keeps URLs in its 30-day "recent" file long after they died. In the first live run this
expired 5,262 URLhaus URLs and 4 of 5 Feodo C2s (offline since March).

### 5. Configuration
* `config/scoring.yaml` (`TL_SCORING_PATH`) is validated strictly, and every number above lives
  there.
* Every breakdown stores `config: "<version>/<sha256 of the file, 8 hex>"`, so an edit without a
  version bump is still traceable.
* The configuration is reloaded when the file changes.

### 6. Expiry
* Each score stores `valid_until`: the time when the strongest report decays below
  `expiry.below` (10).
* The daily job (02:47, also `threatlens rescore`) runs in this order:
  1. re-derive source weights;
  2. recompute patch priorities;
  3. re-score every indicator.
* An `active` indicator scoring below 10 becomes `expired`. An expired one that scores above it
  again, because a feed listed it again, returns to `active`. `false_positive` and `revoked` are
  never changed by scoring.
* Collection runs score the indicators they touched immediately.
* CVE indicators take the patch-priority score and never expire. KEV is a non-decaying floor
  (PLAN).

### 7. Vulnerabilities: patch priority P1–P4
* Points:

  | Signal | Points |
  |---|---|
  | KEV | 40 |
  | ransomware use | +10 |
  | SSVC active exploitation (when not in KEV) | 30 |
  | public exploit or PoC | 15 |
  | EPSS percentile ≥ 0.95 / 0.80 / 0.50 | 25 / 15 / 5 |
  | CVSS ≥ 9 / 7 / 4 | 20 / 10 / 5 |
  | affects our stack (profile or ReconX-observed CPE) | 25 |
  | seen on our internet-facing assets | 15 |

* Tiers: P1 ≥ 80, P2 ≥ 55, P3 ≥ 30, else P4.
* Floors: KEV is at least P2, and KEV in our stack is P1.
* Recomputed after KEV, NVD, EPSS and OSV syncs, and daily.

### 8. Feedback adjusts source weights, and is never drift-prone
* `POST /api/v1/indicators/{id}/feedback` (analyst) or the UI buttons append to `verdicts` and
  mirror the latest verdict on the indicator.
  * **fp** → `false_positive`, score 0. The allowlist and feeds never re-activate it.
    `Collector._apply_verdict` now leaves analyst-decided statuses alone.
  * **tp** → an analyst signal (grade A, credibility 1, confidence 90), which also re-activates
    a false positive.
  * **reset** → the feeds and allowlist decide again.
* Source factor = `clamp(0.5, 1.1, ((tp + 20 × 0.9) / (tp + fp + 20)) / 0.9)`.
  * It is recomputed from all latest verdicts every time, never nudged incrementally.
  * Each change is audited (`source.weight`, with from/to/tp/fp/config).
  * The changed sources' indicators are re-scored in the background.

### 9. TLP 2.0 everywhere (`threatlens.tlp`)
* **Clearance.** Every API key and user has one: the most restricted level it may read.
  * By default it follows the role: viewer GREEN, analyst AMBER+STRICT, admin RED.
  * It can be set with `--clearance` (`keys create`, `users create`, `users clearance`).
* **Hidden means absent.** An item above the reader's clearance does not exist for them:
  * 404 on detail;
  * left out of lists, counts, the map and the dashboard;
  * left out of graph nodes, neighbours and paths;
  * left out of asset flags and lookups. Its sightings don't count in the score, so the verdict
    can't leak it either.
* **Unknown values fail closed.** An unknown item marking counts as RED, and an unknown clearance
  reads CLEAR only.
* **Sinks** are declared with a maximum level: `enricher:third_party` GREEN,
  `enricher:disclosing` CLEAR. `sink_allows` is the only test. A hidden indicator's marking still
  keeps its value away from third parties, even when the caller can't see it.
* `clearance` is a required argument of every graph and lookup call, so the type checker lists
  any read path that forgets it.
* Phase 6 exports will register their own sinks.

## Consequences
* The verdict for 162.243.103.246 changed from Phase 3's "malicious/block" to "unknown/monitor".
  Feodo still lists it, but reports it offline since 2026-03-07. This is intended; the live check
  in PROGRESS shows the before and after.
* Tor exit nodes score ≈ 30 (grade A, confidence 30), on the edge between "suspicious" and
  "monitor". That is deliberate: a Tor exit is context, not maliciousness.
* Geography relevance only matches ISO country codes in feed context. OTX pulses carry
  `targeted_countries` (now stored), but likely as country names, and mapping names to codes
  needs a country list. Sector relevance matches OTX `industries` and tags by slug (`fintech`).
  Neither has been seen live yet, because there is no OTX key.
* Feedback tallies count feed sightings, not enrichment findings. Enrichers are not re-weighted
  by feedback yet.
* Sinkhole detection (one of the spec's FP penalties) is not implemented. The only liveness
  penalties are RDAP "no longer registered" and the feed-reported offline date.
