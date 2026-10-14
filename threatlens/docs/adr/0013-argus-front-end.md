# ADR 0013: Argus, one front end for ReconX and ThreatLens

Date: 2026-10-14 · Status: accepted · Amends ADR 0011 for the new UI

## Context
The user asked to merge ReconX and ThreatLens into one product ("one piece, same UI, world
class"). They chose: one app, with ReconX's Go engine as an internal service; a new name,
**Argus**; and a new design they specified in detail (dark navy, a single blue accent, Inter,
React + Tailwind + Recharts).

## Decisions
1. **Engines stay, the screen changes.** ThreatLens (FastAPI, Postgres, feeds, scoring,
   enrichment, blocklist, cases, accounts) and ReconX (Go scanner) keep their code. Argus is a
   new front end in `web/` that both feed. The classic `/ui` pages stay until each is rebuilt.
2. **Stack**: React 18 + TypeScript, Vite, Tailwind CSS 3, Recharts 3, lucide icons; versions
   pinned. Design tokens are CSS variables (`web/src/index.css`); charts read the same tokens.
   This supersedes ADR 0011's "plain JavaScript, no framework, pages work without JS" for the
   Argus UI only: a single-page app needs JavaScript. Sign-out stays a plain form POST.
3. **Served by the API at `/app`.** The image builds `web/` in a Node stage (compose passes it
   as the `webapp-src` build context) and copies `dist/` to `/app/webapp`
   (`TL_WEB_DIST`). The page needs a session; static files (hashed bundles, fonts) carry no
   data and are public, the bundles cached as immutable. Unknown paths serve the page (client
   routes); missing files are 404s; paths can't leave the dist folder. `/` now redirects to
   `/app/`; sign-in accepts `next=/app/...`.
4. **Security headers unchanged in spirit**: `default-src 'none'; script-src 'self';
   style-src 'self'; connect-src 'self'`, no CDN, self-hosted fonts. React sets styles through
   the CSSOM, which `style-src 'self'` allows.
5. **`/app/api/*` uses the session cookie, not API keys**, and applies TLP clearance to every
   count, series and row. Read-only for now; state changes will need the same same-origin
   check as the classic UI.
6. **Real figures only.** KPIs: active indicators, scored malicious, assets monitored, feeds
   healthy. Detections: new indicators per period split by today's verdict, with the change
   against the previous period (shown only when there is one). Indicators by type, feed pulls
   per weekday (becomes scan activity when the ReconX engine joins), and the latest indicators
   with server-side filtering and paging, always defanged.

## Consequences
* Node is needed to build the image (not to run it).
* Until each page is rebuilt, the Argus sidebar links to the classic `/ui` screen; ReconX
  pages are marked "soon" until the engine runs in the stack (step 2).
