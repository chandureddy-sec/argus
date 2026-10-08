# ADR 0001 — Technology stack

Date: 2026-10-08 · Status: accepted

## Context
The spec (PROMPT.md §3) sets defaults: FastAPI + Pydantic v2, PostgreSQL 16
with SQLAlchemy 2 and Alembic, Redis with arq or Celery, server-rendered UI,
Docker Compose, structlog, GitHub Actions with a set of scanners. The project
is maintained by one person, developed on Windows, and deployed on Linux.

## Decision
Adopt the defaults, with these specifics:

* **Packaging: uv** with a committed `uv.lock`. Same resolver locally, in CI
  and in the image; `uv sync --frozen` fails if the lock is stale.
* **Python 3.12** pinned in `.python-version` and the image, even though newer
  interpreters are installed locally, so tests run on what ships.
* **Jobs: arq.** asyncio-native, tiny, Redis-only. It is in maintenance mode
  upstream; our use (cron + queued jobs) is basic and easy to port to another
  queue if needed. Celery would add a second concurrency model for no gain.
* **DB access: SQLAlchemy 2 async + asyncpg.** Alembic runs online through the
  async engine and offline (`--sql`) for review without a database.
* **Containers:** multi-stage build (uv build stage → slim runtime), non-root
  user, read-only root filesystem, all capabilities dropped,
  `no-new-privileges`, ports bound to 127.0.0.1.
* **Config:** environment variables (`TL_*`) via pydantic-settings; secrets as
  `SecretStr` so they never appear in reprs or logs. Org profile and PIRs are
  YAML (committed, reviewed, no secrets).

## Consequences
* Contributors need uv (one binary). Make is optional; every target is a plain
  `uv run …` command.
* `make` isn't on stock Windows; the README lists the raw commands.
* Swapping arq later means changing `worker.py` and job enqueue calls only.
