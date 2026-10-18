# ADR 0018: Interactive views — threat map, drill-downs, calendar, threat journey

Date: 2026-10-18 · Status: accepted · Completes the SecIncyte-parity plan (step 4 of 4); extends ADR 0015/0016

## Context
The last step of the SecIncyte parity plan was interactivity:
* a zoom/pan map whose locations list their IPs on hover;
* charts and a calendar you can click through to the data behind them;
* a "threat journey" per indicator, from the feed that reported it to the action taken.

Argus already had the data (stored RIPEstat locations, sightings, verdicts, blocks, cases) but no
view that connected it.

## Decisions
1. **Threat map** (`GET /app/api/threatmap?mode=landscape|acted`, `ThreatMap.tsx` on the
   Landscape page).
   * **Data.** Only *stored* RIPEstat answers are used; the map never triggers a lookup.
     * IPs are grouped into ~0.5° cells (one dot per city). At most 3,000 located IPs are drawn,
       highest score first, with 60 listed per dot.
     * `acted` shows only IPs we blocked (live block) or an analyst confirmed malicious.
   * **Rendering.** Plain SVG on the bundled Natural Earth land outline (`web/public/maps`, the
     same file ReconX embeds).
     * Zoom with the wheel or +/−, up to 12×, around the cursor; pan by dragging.
     * Dots keep their on-screen size while zooming.
     * Hover lists every IP at a location; a click pins the list so its links can be used.
   * **Side list.** A filterable list (IP, city, country, network), narrowed to all IPs,
     blocked/flagged or seen, and sorted by latest or score.
   * **Why not a map library.** Leaflet or MapLibre would need tile servers (an outbound request
     per view, which conflicts with the self-hosted CSP) or large bundles. 1,000×500
     equirectangular SVG is enough at country/city scale.
2. **Drill-downs.**
   * Each chart point now carries the range it covers: `from`/`to` on `/app/api/activity`, and
     `date` on `/app/api/collection`.
   * Clicking an area-chart point, a bar or a type ring opens Indicators filtered to that slice.
     For this, `GET /api/v1/indicators` gained `added_from` / `added_until`.
   * The Indicators page shows active drill filters as removable chips.
3. **Activity calendar** (`GET /app/api/calendar?month=YYYY-MM`).
   * A Sunday-first month grid. Shading is new indicators per day; dots mark malicious ones,
     cases opened and blocks placed.
   * A day opens the indicators added that day. There is no navigation past the current month.
4. **Threat journey.** Computed with the indicator's other context (`/related` → `journey`) as
   seven ordered stages, each `done`, `none` or `warn` with a time and plain lines:
   * Reported (feeds and their grades)
   * Ingested
   * Scored (score, verdict, validity)
   * Enriched
   * Seen in our environment
   * Analyst decision
   * Action (live block, cases)

   It appears as a card on the indicator page and in a side drawer opened by clicking a row in
   Indicators ("click any row for its threat journey").
5. **"Seen in our environment"** counts sightings from sources of kind `environment`. Argus has
   no SIEM of its own, so the stage stays empty until the Phase 6 SIEM integrations record
   sightings (e.g. the Wazuh alert webhook). An own-asset match is shown there too. When an
   environment sighting exists the stage is `warn`, because the indicator has reached us.

## Consequences
* Nothing new is sent upstream: every view reads stored rows under the reader's TLP clearance,
  and values stay defanged in the JSON.
* The map shows only IPs that RIPEstat located. The worker's `enrich_backlog` geo-locates new IP
  indicators over time; the card says how many are still without a location.
* Not built (they need SecIncyte's own SIEM or endpoints): the 3-D attack-surface view, endpoint
  firewall rules, NetFlow correlation.
