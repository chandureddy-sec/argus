"""Runtime configuration.

Everything comes from environment variables prefixed ``TL_`` (or a local ``.env``
file in development). Secrets are never read from the YAML profile files, which
are meant to be committed and shared.
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(StrEnum):
    DEV = "dev"
    TEST = "test"
    PROD = "prod"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TL_", env_file=".env", extra="ignore")

    env: Environment = Environment.DEV
    log_level: str = "INFO"
    log_json: bool = True

    # asyncpg DSN, e.g. postgresql+asyncpg://threatlens:***@db:5432/threatlens
    database_url: SecretStr = SecretStr(
        "postgresql+asyncpg://threatlens:threatlens@localhost:5432/threatlens"
    )
    redis_url: SecretStr = SecretStr("redis://localhost:6379/0")

    profile_path: Path = Path("config/org_profile.yaml")
    pirs_path: Path = Path("config/pirs.yaml")

    # Readiness probes must answer quickly even when a dependency hangs.
    readiness_timeout_s: float = Field(default=2.0, gt=0, le=30)

    # Raw feed documents are stored here, content-addressed and gzipped.
    data_dir: Path = Path("data")

    # Third-party keys (free tiers). A connector whose key is missing is
    # recorded as "skipped", never as an error.
    abusech_auth_key: SecretStr | None = None  # ThreatFox (required), URLhaus (optional)
    otx_api_key: SecretStr | None = None  # AlienVault OTX (required)

    # Knowledge base (Phase 2).
    attack_domains: list[str] = Field(
        default_factory=lambda: ["enterprise-attack", "mobile-attack", "ics-attack"]
    )
    nvd_api_key: SecretStr | None = None  # optional; raises NVD's rate limit tenfold
    # relevant: KEV, the org's tech stack and every CVE the platform has seen.
    # all: a full NVD mirror, kept current from the change feed.
    nvd_scope: Literal["relevant", "all"] = "relevant"
    nvd_max_requests: int = Field(default=60, ge=1, le=5000)  # per run
    osv_max_per_run: int = Field(default=300, ge=0, le=20_000)

    # Allowlisting: the top-N Tranco domains never become active indicators.
    tranco_top: int = Field(default=10_000, ge=0, le=1_000_000)

    # Requests per minute per API key, by role.
    rate_limit_viewer: int = Field(default=120, ge=1)
    rate_limit_analyst: int = Field(default=300, ge=1)
    rate_limit_admin: int = Field(default=600, ge=1)


@lru_cache
def get_settings() -> Settings:
    """Settings are read once per process; tests clear the cache to override."""
    return Settings()
