# ThreatLens

Self-hosted threat intelligence platform: collects open-source threat data,
scores it against your organization's profile and Priority Intelligence
Requirements, explains every verdict, and shares it in standard formats.
Part of [Argus](../README.md); lives alongside [ReconX](../docs/RECONX.md), which feeds it the organization's real
assets (see [ADR 0002](docs/adr/0002-monorepo-and-reconx-link.md)).

**Status:** Phases 0-4 complete and Docker-verified: collection, knowledge base, enrichment, the ReconX link, and scoring/trust/TLP/feedback. See [PLAN.md](PLAN.md) and [docs/PROGRESS.md](docs/PROGRESS.md).

## Quickstart (Windows)

From the `threatlens` folder, in PowerShell (`.\tl …`) or Command Prompt (`tl …`):

```powershell
.\tl up              # starts Docker Desktop if needed, creates .env, starts the stack
.\tl user "your name" admin   # creates your sign-in (asks for a password)
.\tl sources         # source health; any threatlens CLI command works: .\tl collect nvd
.\tl status          # containers and readiness
.\tl logs            # follow worker + API logs
.\tl down            # stop (data is kept)
```

`tl` finds Docker even in a terminal opened before Docker was installed. Analyst UI:
http://127.0.0.1:8000/app/ (Argus; sign in with that username and password). Manage accounts with
`.\tl passwd NAME` and `.\tl users list|role|disable|enable`. API keys (`.\tl key NAME analyst`)
are for programs such as ReconX, not for signing in. After changing code, `.\tl up --build`.

## Quickstart (any OS)

Requirements: [uv](https://docs.astral.sh/uv/) and Docker (Desktop on Windows).

```bash
cd threatlens
cp .env.example .env            # set POSTGRES_PASSWORD
docker compose up -d --build --wait
curl http://127.0.0.1:8000/readyz
```

Expected: `{"status":"ready","checks":{"postgres":{"ok":true,…},"redis":{"ok":true,…}}}`

Then create an API key and look at what the worker has collected:

```bash
docker compose exec worker threatlens keys create me --role admin   # prints the key once
docker compose exec worker threatlens allowlist-refresh             # also runs daily at 03:17 UTC
docker compose exec worker threatlens sources
curl -H "X-API-Key: tl_..." "http://127.0.0.1:8000/api/v1/indicators?type=ipv4-addr&limit=5"
curl -H "X-API-Key: tl_..." "http://127.0.0.1:8000/api/v1/entities/Emotet/techniques"
curl -H "X-API-Key: tl_..." "http://127.0.0.1:8000/api/v1/vulnerabilities?kev=true&sort=epss&limit=10"
curl -H "X-API-Key: tl_..." "http://127.0.0.1:8000/api/v1/graph/paths?from=<feodo-ip>&to=T1047"
```

Enrichment (analyst key): one value, a SOC alert, or the enricher catalogue.

```bash
curl -H "X-API-Key: tl_..." "http://127.0.0.1:8000/api/v1/lookup/ipv4-addr/162.243.103.246"
curl -H "X-API-Key: tl_..." "http://127.0.0.1:8000/api/v1/lookup/domain-name/example.com?active=true"  # + DNS (audited)
curl -H "X-API-Key: tl_..." -H "content-type: application/json"      -d '{"text": "beacon to 162.243.103[.]246 from host-17", "tlp": "TLP:GREEN"}'      http://127.0.0.1:8000/api/v1/enrich
curl -H "X-API-Key: tl_..." http://127.0.0.1:8000/api/v1/enrichers
docker compose exec worker threatlens lookup 162.243.103.246      # same, from the CLI
```

Every answer comes back with a verdict, score breakdown, evidence and recommended action.
Enrichers without their key (AbuseIPDB, VirusTotal, MalwareBazaar) report `skipped: no_api_key`;
RDAP, RIPEstat, GreyNoise (25/week), urlscan, crt.sh and DNS need none. URL values go in the path
(defanged is fine); send a `?` in the URL as `%3F`. Policy (passive-first, TLP, quotas): ADR 0005.

Scores, feedback and TLP (ADR 0008). Every indicator has a priority 0-100 with its full
breakdown (`config/scoring.yaml`). Indicators decay and expire, and analysts' TP/FP verdicts
adjust each feed's weight. Nobody sees anything above their TLP clearance.

```bash
curl -H "X-API-Key: tl_..." "http://127.0.0.1:8000/api/v1/indicators?sort=priority&min_score=60"
curl -H "X-API-Key: tl_..." -H "content-type: application/json" -d '{"verdict": "fp", "note": "our scanner"}'      http://127.0.0.1:8000/api/v1/indicators/<id>/feedback          # analyst: tp | fp | reset
curl -H "X-API-Key: tl_..." "http://127.0.0.1:8000/api/v1/vulnerabilities?patch_priority=P1&sort=patch"
.\tl rescore                                                     # the daily job, now: weights, P1-P4, decay, expiry
.\tl keys create reconx --role analyst --clearance TLP:GREEN     # a key that reads CLEAR/GREEN only
.\tl users clearance "name" --clearance TLP:RED                  # or --role-default
```

Blocklist and feed export (ADR 0010). **Response → Blocklist** in the UI, the **Block** button on
an indicator page, or **Block selected** on bulk-lookup results put values on the blocklist in
*monitor* mode (recorded only). Request *enforce*, and a second admin approves it. Enforced blocks
are published at a token URL that a firewall External Dynamic List can pull. Our own IPs and
domains, ReconX assets, private ranges, DNS resolvers and CDN edges are never blocked, checked
again on every export. Every block expires.

```bash
curl -H "X-API-Key: tl_..." -H "content-type: application/json" -d '{"value": "203.0.113[.]24", "note": "alert 77"}' http://127.0.0.1:8000/api/v1/blocks
curl -X POST -H "X-API-Key: tl_..." http://127.0.0.1:8000/api/v1/blocks/<id>/request-enforce   # analyst asks
curl -X POST -H "X-API-Key: tl_admin..." http://127.0.0.1:8000/api/v1/blocks/<id>/approve      # another admin approves
curl http://127.0.0.1:8000/feeds/tlf_.../ip.txt     # token from Platform → Settings → Feed export; also domain.txt, url.txt, blocks.csv, blocks.json, stix.json
```

Products, lookalikes and the report assistant (Phase 8; ADR 0021, 0022):

```bash
curl -X POST -H "X-API-Key: tl_..." -H "content-type: application/json" -d '{"kind": "daily"}' http://127.0.0.1:8000/api/v1/products/generate   # daily | weekly | vulns | exec
curl -H "X-API-Key: tl_..." http://127.0.0.1:8000/api/v1/products/<id>/pdf -o brief.pdf      # or /html; POST /verify rebuilds and compares fingerprints
curl -X POST -H "X-API-Key: tl_..." http://127.0.0.1:8000/api/v1/lookalikes/scan            # needs org.domains in config/org_profile.yaml
curl -X POST -H "X-API-Key: tl_..." -H "content-type: application/json" -d '{"title": "Vendor advisory", "text": "...", "tlp": "TLP:CLEAR"}' http://127.0.0.1:8000/api/v1/ai/extract   # TL_AI_ENABLED + a Claude key
uv run python scripts/ai_eval.py          # the SYNTHETIC 36-report evaluation (add --model with a key)
```

Own assets from ReconX (scans of your own domains only; ADR 0006):

```bash
reconx scan example.com --threatlens --threatlens-assets     # from the repository root
docker compose exec worker threatlens import-reconx /path/recon_example.com_….json   # or import a saved report
curl -H "X-API-Key: tl_..." "http://127.0.0.1:8000/api/v1/assets?flagged=true"     # own assets a feed lists
curl -H "X-API-Key: tl_..." http://127.0.0.1:8000/api/v1/assets/products            # observed tech stack + CVEs
```

The worker collects every enabled source on its own schedule. Sources that
need a free key (ThreatFox, OTX) show `skipped` until `TL_ABUSECH_AUTH_KEY` /
`TL_OTX_API_KEY` are set in `.env`. Argus, the analyst UI: http://127.0.0.1:8000/app/.

### Without Docker (SQLite trial)

```bash
export TL_DATABASE_URL=sqlite+aiosqlite:///./trial.db TL_LOG_JSON=false
uv run threatlens init-db
uv run threatlens allowlist-refresh
uv run threatlens collect --all      # NVD paces itself without a key: a few minutes
uv run threatlens sources
```

## Development

| Task | Command (`make` target in brackets) |
|---|---|
| Install | `uv sync` (`make install`) |
| Lint | `uv run ruff check src tests migrations && uv run ruff format --check src tests migrations` (`make lint`) |
| Type-check | `uv run mypy` (`make typecheck`) |
| Unit tests | `uv run pytest` (`make test`) |
| Integration tests (stack up) | `TL_INTEGRATION=1 uv run pytest -m integration` (`make test-integration`) |
| Validate profile + PIRs | `uv run threatlens validate-profile` (`make profile`) |
| Migration SQL without a DB | `uv run alembic upgrade head --sql` (`make sql`) |
| Run API natively | `uv run threatlens api` |
| Collect now | `uv run threatlens collect SOURCE… \| --due \| --all [--force]` |
| Sources / health | `uv run threatlens sources [enable\|disable NAME]` |
| Allowlist refresh | `uv run threatlens allowlist-refresh` |
| API keys | `uv run threatlens keys create NAME --role viewer\|analyst\|admin`, `keys list`, `keys revoke NAME` |
| Load one ATT&CK release | `uv run threatlens attack-load --version 19.1 [--domain mobile-attack] [--force]` |
| Extract IOCs from text | `uv run threatlens extract [FILE] [--defang] [--rejected]` |
| Run worker natively | `uv run arq threatlens.worker.WorkerSettings` |

Windows PowerShell sets the integration flag with `$env:TL_INTEGRATION=1`.

## Layout

```text
threatlens/
├── config/            org_profile.yaml, pirs.yaml (your organisation; blank until filled in)
├── migrations/        Alembic (async)
├── src/threatlens/    api/, net/ (hardened HTTP), ioc/, connectors/, kb/, enrich/, ui/, collect, allowlist,
│                      auth, jobs, worker, cli, settings, logs, profile, db, models
├── tests/             unit tests; integration/ needs Postgres + Redis
└── docs/              PLAN-linked ADRs, THREAT_MODEL, SOURCES, learn/
```

## Docs
[PLAN](PLAN.md) · [Data model](docs/DATA_MODEL.md) · [Threat model](docs/THREAT_MODEL.md) · [Sources](docs/SOURCES.md) ·
[ADRs](docs/adr/) · [Learning notes](docs/learn/) · [Original spec](PROMPT.md)
