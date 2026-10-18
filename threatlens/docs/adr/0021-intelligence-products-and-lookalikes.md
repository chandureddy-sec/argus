# ADR 0021: Intelligence products and lookalike-domain monitoring

Date: 2026-10-18 · Status: accepted · Phase 8

## Context
Phase 8 turns stored intelligence into products people read:
* a daily threat brief;
* a weekly CTI report;
* a vulnerability priority list;
* an executive one-pager.

Each comes as HTML and PDF, built from stored data, with citations to the source records. The
acceptance test: **a product regenerates deterministically from the data**.

Phase 8 also adds brand protection: domains imitating ours, found from Certificate Transparency
(CT) logs and dnstwist permutations, with passive checks only.

## Decisions

### Products
1. **A product is a pure function of the database and an `as_of` time.**
   * `products/build.py` reads stored rows only. It never reads "now" and never calls an
     upstream.
   * The period comes from `as_of`:
     * daily and vulnerability products cover the previous UTC day;
     * weekly and executive products cover the previous Monday-to-Monday week.
   * Lists are sorted with tie-breakers, so equal data gives equal JSON.
   * The SHA-256 of the canonical JSON (sorted keys, no whitespace) is stored with the product.
   * `POST /products/{id}/verify` rebuilds the product and compares fingerprints. A match proves
     determinism. A mismatch means the data changed since generation (a new indicator, a
     re-score), and the UI says so.
2. **Every statement cites its records.** Each item carries:
   * a `ref`: `indicator #id`, a CVE id, `case #id`, `lookalike #id`, an ATT&CK id or a source
     name;
   * a `link` to its Argus page.

   The HTML links every reference; the PDF prints them. The executive one-pager's risks list
   the records behind each sentence.
3. **TLP.**
   * **Content cap:** `TL_PRODUCTS_MAX_TLP`, default TLP:GREEN, so a product can go to the
     whole organisation.
   * **Marking:** the strictest marking among the items actually included. It is printed at
     the top and bottom of the HTML and on every PDF page.
   * **Reading:** a reader needs that clearance. List, get, HTML and PDF all filter by
     clearance.
   * **Never included:** TLP:RED.
4. **One renderer per format from one structure.**
   * **HTML:** Jinja2 with autoescape on (`products/product.html`). Self-contained: inline CSS,
     no scripts. Served with `Content-Security-Policy: default-src 'none'; style-src
     'unsafe-inline'`, so even a template bug can't run script.
   * **PDF:** the existing fpdf2 layer (`threatlens/pdf.py`, Inter font, marking in the
     footer).
   * **Values are defanged** in both, because products are for people.
5. **Scheduling.**
   * The worker runs `build_products` daily at 06:05 UTC, after the night's collection,
     scoring and KEV pull. It builds every kind whose latest closed period has no stored
     product yet:
     * daily kinds every day;
     * weekly kinds on Monday, or on the first run after it if the worker was down.
   * `(kind, period_end)` is unique: regenerating replaces the stored product.
   * Analysts can generate a product on demand (`POST /products/generate`, `as_of` not in the
     future).
6. **Indicator counts exclude CVE observables.** CVEs have their own KEV section, and counting
   them inflated "new indicators" by 1,748 in the live check.

### Lookalikes
7. **Candidates come from two passive sources only. Nothing is resolved or contacted.**
   * **dnstwist permutations** of each org domain:
     * homoglyphs, typos, bitsquatting and transpositions;
     * TLD swaps over a fixed list of about 30 phisher-favoured TLDs and large ccTLDs.
   * **CT logs:** one crt.sh query per brand keyword (`%keyword%`, keywords of four or more
     letters, shared by domains with the same keyword). A logged name is a candidate when its
     registered domain is a permutation, or contains the keyword and isn't ours
     (combosquatting, e.g. `example-secure-login.net`).
   * **Our feeds:** domain indicators that *are* a permutation (exact match), and domain or URL
     indicators that contain the keyword. The first live run showed why the exact match is
     needed: a keyword search can never find homoglyphs (`exarnple.com` does not contain
     `example`).

   dnstwist's DNS, WHOIS and GeoIP features are not used: they are active and would touch the
   lookalike's infrastructure.
8. **Analysts review every candidate.** The status starts as `new`:
   * **confirm** (optionally *and block*: a blocklist entry in monitor mode, through the normal
     never-block guard);
   * **benign** (ours, a partner's, harmless).

   Evidence is kept: the earliest certificate date, or the indicator id.
9. **New candidates feed the `lookalike` alert rule kind** (migration 0014 widens the check
   constraint) **and the daily and weekly products.**
   * **Marking:** TLP:CLEAR. They are public CT data about our own brand.
   * **Lifetime:** they stop alerting once reviewed.
10. **The scan degrades rather than fails.** A crt.sh error (it often answers 502 under load)
    is recorded in the run's `errors` and in the audit log, and the feed half still runs. The
    first live scan hit exactly that; the retry answered in 1.8 s.

## Consequences
* The products are reproducible evidence. A fingerprint printed in the PDF can be checked
  against the database later.
* Reproducible does not mean frozen. Scores decay and indicators expire, so `verify` on an old
  product will often report "data changed". That is the honest answer, and the stored product
  keeps what was said at the time.
* Lookalike coverage is only as good as the CT log and the permutation set. A lookalike with
  no certificate that isn't in our feeds stays invisible to passive monitoring.
