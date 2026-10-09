# ThreatLens

Self-hosted threat intelligence platform: collects open-source threat data,
scores it against your organization's profile and Priority Intelligence
Requirements, explains every verdict, and shares it in standard formats.
Lives alongside [ReconX](../README.md), which feeds it the organization's real
assets (see [ADR 0002](docs/adr/0002-monorepo-and-reconx-link.md)).

**Status:** Phases 1 (collection) and 2 (knowledge base: ATT&CK, NVD, EPSS, KEV, OSV, graph) complete; Docker verification pending. See [PLAN.md](PLAN.md) and [docs/PROGRESS.md](docs/PROGRESS.md).

## Quickstart

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

The worker collects every enabled source on its own schedule. Sources that
need a free key (ThreatFox, OTX) show `skipped` until `TL_ABUSECH_AUTH_KEY` /
`TL_OTX_API_KEY` are set in `.env`. API docs: http://127.0.0.1:8000/docs (dev only).

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
├── config/            org_profile.yaml, pirs.yaml (SYNTHETIC examples)
├── migrations/        Alembic (async)
├── src/threatlens/    api/, net/ (hardened HTTP), ioc/, connectors/, collect, allowlist,
│                      auth, jobs, worker, cli, settings, logs, profile, db, models
├── tests/             unit tests; integration/ needs Postgres + Redis
└── docs/              PLAN-linked ADRs, THREAT_MODEL, SOURCES, learn/
```

## Docs
[PLAN](PLAN.md) · [Data model](docs/DATA_MODEL.md) · [Threat model](docs/THREAT_MODEL.md) · [Sources](docs/SOURCES.md) ·
[ADRs](docs/adr/) · [Learning notes](docs/learn/) · [Original spec](PROMPT.md)
