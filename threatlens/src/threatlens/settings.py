"""Runtime configuration.

Everything comes from environment variables prefixed ``TL_`` (or a local ``.env``
file in development). Secrets are never read from the YAML profile files, which
are meant to be committed and shared.
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from pathlib import Path

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


@lru_cache
def get_settings() -> Settings:
    """Settings are read once per process; tests clear the cache to override."""
    return Settings()
