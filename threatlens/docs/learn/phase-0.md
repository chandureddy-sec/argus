# Phase 0 — Foundations of a trustworthy platform

## Concept
Before collecting a single indicator, a threat intelligence platform needs
three things: **a definition of what matters** (org profile + PIRs), **a
deployable, observable skeleton** (containers, health checks, structured logs,
migrations), and **a security baseline** (threat model, CI scanners, hardened
containers) — because the platform will ingest content written by adversaries.

## Why it matters
* **PIRs** are the "Direction" step of the intelligence cycle. Without them a
  TIP becomes a feed aggregator: thousands of indicators, no priorities.
  Validating them strictly means a typo (`domain:` instead of `domains:`)
  fails at load time instead of silently making a PIR match nothing.
* **Liveness vs readiness:** if `/healthz` checked Postgres, an orchestrator
  would restart the API every time the database blipped — which doesn't fix the
  database and drops in-flight requests. Liveness asks "is this process
  alive?"; readiness asks "can it serve right now?".
* **Migrations from day one** make every schema change reviewable and
  repeatable, and offline mode (`alembic upgrade head --sql`) lets you review
  the exact SQL without a database.

## How it works here
* `src/threatlens/profile.py` — Pydantic models with `extra="forbid"`,
  domain/CIDR/CPE/ATT&CK-ID validation, and `cross_check()` which rejects PIRs
  that watch for data the profile doesn't contain. YAML is read with
  `safe_load` only.
* `src/threatlens/api/app.py` — app factory; `/healthz` never touches a
  dependency; `/readyz` runs Postgres and Redis checks concurrently with a
  2-second timeout and reports only the exception *type* (driver messages can
  include DSNs). Middleware adds a request ID (echoed only if it's a safe
  string) and security headers.
* `src/threatlens/logs.py` — JSON logs; a processor redacts key-like fields.
* `docker-compose.yml` — db → migrate (one-shot) → api + worker, all app
  containers non-root, read-only, no capabilities, ports on 127.0.0.1.
* `.github/workflows/threatlens.yml` — lint, strict typing, tests with real
  Postgres/Redis services, bandit, pip-audit, semgrep, gitleaks, Trivy, SBOM,
  and a compose smoke test.

## Hands-on exercise
1. `uv run threatlens validate-profile` — note the summary line.
2. Edit `config/pirs.yaml`: add `geography: [JP]` to PIR-1's `watch`. Run it
   again and read the error. Why is rejecting this better than ignoring it?
3. Change an IP range to `203.0.113.5/24`. Why does `strict=True` reject a
   network with host bits set?
4. With the stack up, run `docker compose stop redis`, then
   `curl -i localhost:8000/readyz` and `curl -i localhost:8000/healthz`.
   Explain the two status codes.
5. `uv run alembic upgrade head --sql` — find the extension statements and
   explain what `pg_trgm` will be used for.

## Common mistakes
* Putting dependency checks in the liveness probe (restart loops).
* Loading YAML with `yaml.load` (arbitrary object construction).
* Logging full exception messages from database drivers (credentials in DSNs).
* Committing `.env` — only `.env.example` is tracked.
* Publishing database/Redis ports on `0.0.0.0` "just for development".
