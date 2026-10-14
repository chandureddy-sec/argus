# ADR 0016: Argus is the only UI

Date: 2026-10-14 · Status: accepted · Completes ADR 0013–0015

## Context
Step 4 of merging ReconX and ThreatLens: rebuild the last classic screens (overview,
vulnerabilities, ATT&CK, entities, search, sign-in) in Argus, then retire the classic
ThreatLens UI (`/ui`, server-rendered Jinja) and ReconX's own embedded dashboard.

## Decisions
1. **Sign-in is Argus's**: `POST /app/api/session` (JSON) and `DELETE /app/api/session` keep
   the ADR 0007 rules: same-site only, rate-limited per address and per account, the same
   message for every wrong username or password, a signed HttpOnly SameSite=Strict cookie,
   sessions ended by disabling the account or changing its password. `/app/login` is the
   only Argus page served without a session; every other page redirects there with
   `next=` (Argus paths only, no open redirect).
2. **New JSON** (`argus_intel.py`): the threat landscape (priority queue, malware families,
   techniques, located infrastructure, KEV latest and in our stack, patch priorities, PIRs,
   this week's activity, feed reliability), the Enterprise ATT&CK matrix, and global search
   (an exact hit returns where to open; otherwise matches by value, `tag:`, entity, CVE and
   case). Vulnerabilities and entities use the existing knowledge-base API.
3. **Pages**: Threat landscape, Vulnerabilities + detail (patch-priority reasons, KEV action,
   references), ATT&CK matrix (heat by family count), entity pages (techniques, actors,
   software, indicators, vulnerabilities, mitigations from the graph), Search, Login; the scan
   page gains an infrastructure **Graph** tab (self-contained force layout, zoom/pan,
   focus a node) so nothing the ReconX dashboard had is lost; Bulk check exports CSV with
   formula-safe cells.
4. **The classic UI is gone**: `threatlens/ui/` (routes, templates, static files) is deleted.
   Shared code moved out first: `session.py` (cookies), `dashboard.py` (read-side queries),
   `intake.py` (bulk input). Every old `/ui/...` address answers 301 with its Argus page
   (`/ui/lookup` → `/app/bulk`, `/ui/sources` → `/app/feeds`, the rest by name).
5. **ReconX's dashboard is gone**: `internal/cli/webui/` is deleted; `reconx serve` is the
   engine API (JSON, SSE) that Argus drives, never opens a browser, and its `/` says where the
   dashboard went. The CLI, reports and monitors are unchanged.
6. **Tests** that drove HTML pages were ported to the same behaviour through Argus and the
   API (sessions and their guards, TLP clearance on every read, bulk-check rules, blocking,
   catalog, feedback); pure template checks were dropped.

## Consequences
* One UI, one sign-in, one design for recon and threat intelligence.
* Running ReconX without Docker still works from the CLI; its web UI needs the stack.
