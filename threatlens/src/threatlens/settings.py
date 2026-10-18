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
        "postgresql+asyncpg://threatlens:threatlens@127.0.0.1:5432/threatlens"
    )
    redis_url: SecretStr = SecretStr("redis://127.0.0.1:6379/0")  # IPv4: see .env.example

    profile_path: Path = Path("config/org_profile.yaml")
    pirs_path: Path = Path("config/pirs.yaml")
    scoring_path: Path = Path("config/scoring.yaml")

    # Readiness probes must answer quickly even when a dependency hangs.
    readiness_timeout_s: float = Field(default=2.0, gt=0, le=30)

    # Raw feed documents are stored here, content-addressed and gzipped.
    data_dir: Path = Path("data")

    # The built Argus front end (web/dist), served at /app. The image puts it in
    # /app/webapp; for a native run point it at web/dist.
    web_dist: Path = Path("webapp")

    # The ReconX engine (attack-surface scans), on the compose network only (ADR 0014).
    reconx_url: str | None = None

    # Third-party keys (free tiers). A connector whose key is missing is
    # recorded as "skipped", never as an error.
    abusech_auth_key: SecretStr | None = None  # ThreatFox (required), URLhaus (optional)
    otx_api_key: SecretStr | None = None  # AlienVault OTX (required)

    # Signs analyst UI session cookies. Without it, sessions end when the API restarts.
    secret_key: SecretStr | None = None

    # Development only: POST /app/api/auth/sso/mock signs in an SSO identity without
    # any identity provider checking it. Off unless TL_SSO_MOCK=true; never in production.
    sso_mock: bool = False

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

    # Enrichment (Phase 3). Keys are optional: an enricher without its key is
    # reported as skipped. MalwareBazaar uses TL_ABUSECH_AUTH_KEY.
    abuseipdb_api_key: SecretStr | None = None
    greynoise_api_key: SecretStr | None = None  # optional: raises the weekly allowance
    virustotal_api_key: SecretStr | None = None  # public API: non-commercial use only
    urlscan_api_key: SecretStr | None = None  # optional: raises the search quota
    ripestat_sourceapp: str = Field(default="threatlens", pattern=r"^[A-Za-z0-9_-]{1,64}$")
    enrich_timeout_s: float = Field(default=10.0, gt=0, le=60)  # per enricher call
    enrich_bulk_max: int = Field(default=100, ge=1, le=1000)  # observables per POST /enrich
    enrich_budget: int = Field(default=50, ge=0, le=10_000)  # metered calls per bulk request
    enrich_active_per_min: int = Field(default=30, ge=1)  # active lookups per key per minute
    # Background enrichment of new IP indicators with free passive enrichers
    # (RIPEstat ASN/geo) so the dashboard map has data; 0 turns it off.
    enrich_auto_per_run: int = Field(default=100, ge=0, le=5000)

    # Allowlisting: the top-N Tranco domains never become active indicators.
    tranco_top: int = Field(default=10_000, ge=0, le=1_000_000)

    # Requests per minute per API key, by role.
    rate_limit_viewer: int = Field(default=120, ge=1)
    rate_limit_analyst: int = Field(default=300, ge=1)
    rate_limit_admin: int = Field(default=600, ge=1)

    # Dissemination (Phase 6, ADR 0019).
    # The producer named in STIX bundles and on the TAXII discovery page.
    org_identity: str = Field(default="Argus", min_length=1, max_length=100)
    # Public base URL clients use to reach this server (TAXII discovery, export links).
    public_url: str = "http://127.0.0.1:8000"
    taxii_page_size: int = Field(default=500, ge=1, le=5000)
    # Development and demos only: let integrations and feeds marked "internal network"
    # reach this host itself (127.0.0.1 / ::1). Never needed in production.
    allow_loopback_destinations: bool = False
    # Alerts: at most this many messages per channel per hour; the rest are summarised.
    alert_max_per_hour: int = Field(default=20, ge=1, le=1000)

    # Production and AI (Phase 8, ADR 0021, 0022).
    # The most sensitive content a generated product may include.
    products_max_tlp: Literal["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER"] = "TLP:GREEN"
    # Lookalike-domain monitoring queries Certificate Transparency (crt.sh) by brand keyword.
    lookalike_ct: bool = True
    # The AI report assistant sends report text to the Claude API: off unless enabled.
    # The key is TL_AI_API_KEY, or the Anthropic SDK's own (ANTHROPIC_API_KEY, `ant auth login`).
    ai_enabled: bool = False
    ai_api_key: SecretStr | None = None
    ai_model: str = Field(default="claude-opus-5-5", pattern=r"^[a-z0-9.-]{3,100}$")
    # Reports marked above this are never sent to the model; TLP:RED never is.
    ai_max_tlp: Literal["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT"] = "TLP:GREEN"
    ai_timeout_s: float = Field(default=180.0, gt=0, le=900)


@lru_cache
def get_settings() -> Settings:
    """Settings are read once per process; tests clear the cache to override."""
    return Settings()
