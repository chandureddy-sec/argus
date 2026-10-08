# ThreatLens

Self-hosted threat intelligence platform: collects open-source threat data,
scores it against your organization's profile and Priority Intelligence
Requirements, explains every verdict, and shares it in standard formats.
Lives alongside [ReconX](../README.md), which feeds it the organization's real
assets (see [ADR 0002](docs/adr/0002-monorepo-and-reconx-link.md)).

**Status:** Phase 0 (foundation) — see [PLAN.md](PLAN.md) and [docs/PROGRESS.md](docs/PROGRESS.md).

## Quickstart

Requirements: [uv](https://docs.astral.sh/uv/) and Docker (Desktop on Windows).

```bash
cd threatlens
cp .env.example .env            # set POSTGRES_PASSWORD
docker compose up -d --build --wait
curl http://127.0.0.1:8000/readyz
```

Expected: `{"status":"ready","checks":{"postgres":{"ok":true,…},"redis":{"ok":true,…}}}`

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

Windows PowerShell sets the integration flag with `$env:TL_INTEGRATION=1`.

## Layout

```text
threatlens/
├── config/            org_profile.yaml, pirs.yaml (SYNTHETIC examples)
├── migrations/        Alembic (async)
├── src/threatlens/    api/, settings, logs, profile, db, health, worker, cli
├── tests/             unit tests; integration/ needs Postgres + Redis
└── docs/              PLAN-linked ADRs, THREAT_MODEL, SOURCES, learn/
```

## Docs
[PLAN](PLAN.md) · [Threat model](docs/THREAT_MODEL.md) · [Sources](docs/SOURCES.md) ·
[ADRs](docs/adr/) · [Learning notes](docs/learn/) · [Original spec](PROMPT.md)
