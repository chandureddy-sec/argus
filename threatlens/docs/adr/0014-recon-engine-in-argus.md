# ADR 0014: The ReconX engine inside Argus

Date: 2026-10-14 · Status: accepted · Builds on ADR 0006 (ReconX link) and 0013 (Argus)

## Context
Step 2 of merging ReconX and ThreatLens into Argus: run scans, watch them live, read the
results, compare scans and manage monitors from the Argus UI, with scan results feeding
ThreatLens's assets directly. ReconX's own web server has scans, live progress (SSE), saving,
compare, graph/map data and monitors, but **no user accounts**: one random token per process,
readable by anyone who can reach it, guards its POSTs.

## Decisions
1. **ReconX runs as an internal engine** (`deploy/reconx.Dockerfile`, compose service
   `reconx`): a static Go binary (pure-Go SQLite) on Debian slim with nmap, as a non-root user,
   read-only root, all capabilities dropped. **No published port**: only the compose network
   reaches it. Its relative paths (`reports/`, `reports/monitor/`, `cache/`) and key store
   (`XDG_CONFIG_HOME`) live on the `recondata` volume. No browser in the image, so browser
   capture is off and Argus never asks for it.
2. **Every request goes through Argus** (`recon.py` client, `recon_api.py` routes under
   `/app/api/recon`): session cookie; reading needs a sign-in; passive scans and saving need
   the analyst role; active or combined scans need admin **and** the explicit authorization
   confirmation (also enforced by the engine); monitors need admin. State changes need a
   same-site request and are audited (`recon.scan`, `recon.save`, `recon.monitor.*`).
3. **Nothing from the browser becomes an engine path**: job ids (`^[0-9a-f]{12}$`), report
   files (`^recon_[A-Za-z0-9._-]+\.json$`), monitor ids and actions are checked first; raw
   nmap flags never pass through; port lists are digits, commas and dashes only; webhooks must
   be https. The engine token is fetched by Argus and refreshed once when the engine restarts.
4. **Live progress** is the engine's SSE stream relayed as is (`text/event-stream`, no
   buffering); the engine replays history first, so reloads catch up.
5. **Saving imports assets**: Save writes the report (engine) and runs the existing ReconX
   importer (ADR 0006: resolving-host IPs only, CDN edges and name/mail servers rejected), then
   re-scores so own-asset relevance applies. Monitor runs save on their own; the worker's
   `import_recon_reports` job (every 10 minutes) imports new saved reports once (file names
   remembered in `app_settings`, import is idempotent by content hash anyway).
6. **Argus pages**: Scans (filter, pick two to compare), New scan (passive by default, active
   options only for admins with the confirmation), live progress with Save, scan results
   (hosts, findings, ports, map, sources, downloads), Compare (summary + changes), Monitors
   (list, run/pause/resume/test/delete, add, recent alerts). Deep links work, including scan
   pages whose reference ends in `.json`.

## Consequences
* The engine keeps unsaved scans in memory only; a restart loses them (the UI says so).
* Scans run from the API container's network position; active scans contact targets from
  this host, as with the ReconX CLI.
* The ReconX CLI and its own dashboard still work standalone, outside the stack.
