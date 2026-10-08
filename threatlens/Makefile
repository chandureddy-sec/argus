# ThreatLens tasks. Requires uv (https://docs.astral.sh/uv/) and, for the stack, Docker.
# On Windows without make, run the commands after each target directly.
.PHONY: install lint fmt typecheck test cov test-integration security up down logs migrate sql profile

install:
	uv sync

lint:
	uv run ruff check src tests migrations
	uv run ruff format --check src tests migrations

fmt:
	uv run ruff format src tests migrations
	uv run ruff check --fix src tests migrations

typecheck:
	uv run mypy

test:
	uv run pytest

cov:
	uv run pytest --cov --cov-report=term-missing --cov-report=xml

# Needs the stack: `make up` first.
test-integration:
	TL_INTEGRATION=1 uv run pytest -m integration

security:
	uv run bandit -c pyproject.toml -r src
	uv run pip-audit

up:
	test -f .env || cp .env.example .env
	docker compose up -d --build --wait

down:
	docker compose down

logs:
	docker compose logs -f api worker

migrate:
	uv run alembic upgrade head

# Print the migration SQL without a database.
sql:
	uv run alembic upgrade head --sql

profile:
	uv run threatlens validate-profile
