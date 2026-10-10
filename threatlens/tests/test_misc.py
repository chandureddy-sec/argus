from __future__ import annotations

import json
import logging
import subprocess
import sys
from pathlib import Path

import pytest

from threatlens.cli import main
from threatlens.logs import configure_logging, get_logger
from threatlens.settings import Settings, get_settings

ROOT = Path(__file__).resolve().parents[1]


def test_settings_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TL_ENV", "prod")
    monkeypatch.setenv("TL_DATABASE_URL", "postgresql+asyncpg://u:pw-hunter2@h/db")
    get_settings.cache_clear()
    try:
        s = get_settings()
        assert s.env == "prod"
        assert "pw-hunter2" not in repr(s)  # SecretStr keeps DSNs out of reprs and logs
        assert s.database_url.get_secret_value().endswith("@h/db")
    finally:
        get_settings.cache_clear()


def test_settings_reject_bad_timeout() -> None:
    with pytest.raises(ValueError, match="greater than 0"):
        Settings(readiness_timeout_s=0)


def test_log_redaction_and_json(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("INFO", json=True)
    get_logger("t").info("evt", api_key="abc123", target="example.com", note="line1\nline2")
    line = capsys.readouterr().out.strip().splitlines()[-1]
    rec = json.loads(line)  # one JSON object per line, even with a newline in a value
    assert rec["api_key"] == "[REDACTED]"
    assert rec["target"] == "example.com"
    assert rec["event"] == "evt"
    logging.getLogger().handlers.clear()


def test_cli_validate_profile(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    args = ["--profile", str(ROOT / "config/org_profile.yaml"), "--pirs", str(ROOT / "config/pirs.yaml")]
    assert main(["validate-profile", *args]) == 0
    assert "3 PIRs" in capsys.readouterr().out

    bad = tmp_path / "p.yaml"
    bad.write_text("org: {name: A, domains: ['bad domain']}", encoding="utf-8")
    assert main(["validate-profile", "--profile", str(bad), "--pirs", str(ROOT / "config/pirs.yaml")]) == 1
    assert "not a valid domain" in capsys.readouterr().err


def test_migration_sql_offline() -> None:
    # Alembic's offline mode renders the migration SQL without a database.
    out = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head", "--sql"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert "CREATE EXTENSION IF NOT EXISTS pg_trgm" in out
    assert "CREATE TABLE app_meta" in out
    assert "INSERT INTO alembic_version (version_num) VALUES ('0001')" in out


def test_cli_lookup_rejects_values_before_any_lookup(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["lookup", "10.0.0.1"]) == 2  # private: never sent anywhere
    assert "rejected" in capsys.readouterr().err
