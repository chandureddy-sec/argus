"""UI accounts: password hashing, username rules, account changes and the
``threatlens users`` CLI."""

from __future__ import annotations

import io

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.test_jobs import cli_db  # noqa: F401  # fixture
from threatlens import cli
from threatlens.models import AuditLog, User
from threatlens.settings import Settings
from threatlens.users import (
    UserError,
    authenticate_user,
    check_name,
    create_user,
    hash_password,
    login_key,
    set_role,
    verify_password,
)

SM = async_sessionmaker[AsyncSession]
PW = "Threat-test-1"  # test account


def test_password_hashes_are_salted_and_verify() -> None:
    a, b = hash_password(PW), hash_password(PW)
    assert a != b  # random salt
    assert a.startswith("scrypt$16384$8$1$")
    assert PW not in a
    assert verify_password(PW, a)
    assert not verify_password(PW + "x", a)
    assert not verify_password(PW.lower(), a)  # case-sensitive


@pytest.mark.parametrize(
    "stored", ["", "plain", "md5$abc", "scrypt$16384$8$1$!!$!!", "scrypt$1073741824$8$1$AAAA$AAAA"]
)
def test_malformed_or_hostile_hashes_never_verify(stored: str) -> None:
    assert not verify_password(PW, stored)


def test_usernames() -> None:
    assert check_name("  chandu   reddy ") == "chandu reddy"
    assert login_key("Chandu  REDDY") == login_key("chandu reddy") == "chandu reddy"
    for bad in ("", "   ", "a" * 65, "x<script>", "a/b", "tab\\there"):
        with pytest.raises(UserError):
            check_name(bad)


async def test_create_and_authenticate(sm: SM) -> None:
    async with sm() as s, s.begin():
        row = await create_user(s, "Chandu Reddy", PW, "admin")
        assert row.name == "Chandu Reddy"
        assert row.login == "chandu reddy"
        with pytest.raises(UserError, match="already exists"):
            await create_user(s, "CHANDU reddy", PW, "viewer")
        with pytest.raises(UserError, match="at least 6"):
            await create_user(s, "short", "12345", "viewer")
        with pytest.raises(UserError, match="role must be"):
            await create_user(s, "bob", PW, "root")
    async with sm() as s, s.begin():
        assert await authenticate_user(s, "chandu reddy", PW) is not None
        assert await authenticate_user(s, "chandu reddy", "wrong") is None
        assert await authenticate_user(s, "nobody", PW) is None
        await set_role(s, "chandu reddy", "analyst")
    async with sm() as s:
        user = await s.scalar(select(User))
        assert user is not None
        assert user.role == "analyst"
        assert user.last_login_at is not None
        actions = (await s.scalars(select(AuditLog.action).order_by(AuditLog.id))).all()
    assert actions == ["user.create", "user.login", "user.role"]


def test_cli_users(
    cli_db: Settings,  # noqa: F811
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("﻿" + PW + "\r\n"))  # as PowerShell pipes it
    assert cli.main(["users", "create", "chandu reddy", "--role", "admin", "--password-stdin"]) == 0
    assert "created chandu reddy (admin)" in capsys.readouterr().out
    monkeypatch.setattr("sys.stdin", io.StringIO(PW + "\n"))
    assert cli.main(["users", "create", "Chandu Reddy", "--password-stdin"]) == 2
    assert "already exists" in capsys.readouterr().err

    prompts = iter(["new-password-1", "new-password-1"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda _prompt: next(prompts))
    assert cli.main(["users", "passwd", "chandu reddy"]) == 0
    prompts = iter(["one-password", "other-password"])
    assert cli.main(["users", "passwd", "chandu reddy"]) == 2
    assert "don't match" in capsys.readouterr().err

    assert cli.main(["users", "role", "chandu reddy"]) == 2  # never silently demote
    assert cli.main(["users", "role", "chandu reddy", "--role", "analyst"]) == 0
    assert cli.main(["users", "disable", "chandu reddy"]) == 0
    assert cli.main(["users", "passwd"]) == 2
    assert cli.main(["users", "enable", "nobody"]) == 2
    capsys.readouterr()
    assert cli.main(["users", "list"]) == 0
    listing = capsys.readouterr().out
    assert "chandu reddy" in listing
    assert "analyst" in listing
    assert "disabled" in listing
    assert PW not in listing
