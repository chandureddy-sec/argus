"""Tests for Team and Security (ADR 0017):

1. User management inside Argus Settings (create, role, password, disable/enable, self-protection).
2. Two-factor sign-in (RFC 6238 TOTP setup, verification, challenge flow, admin reset).
3. Single sign-on (SSO provider configuration, provider listing, mock login).
4. Audit log viewer (who blocked, approved, scanned or changed what, searchable & exportable).
"""

from __future__ import annotations

import time

import httpx

from tests.test_cases import SAME, App
from tests.test_cases import app as app  # fixture
from tests.test_enrich import http, seeded, upstream  # noqa: F401  # fixtures
from threatlens import totp
from threatlens.users import create_user


async def make_admin(app: App, name: str = "superadmin") -> int:
    async with app.sm() as s, s.begin():
        u = await create_user(s, name, f"{name}-password", "admin")
        uid = u.id
    return uid


# ── 1. User Management inside Argus ──────────────────────────────────────────


async def test_user_create_and_role(app: App) -> None:
    admin_id = await make_admin(app, "superadmin")
    await app.login("superadmin")

    # 1. List users
    r = await app.c.get("/app/api/settings/users")
    assert r.status_code == 200
    names = [u["name"] for u in r.json()]
    assert "superadmin" in names

    # 2. Non-admin cannot create users
    await app.login("anna")  # analyst
    r = await app.c.post(
        "/app/api/settings/users",
        json={"name": "bob", "password": "bob-password", "role": "analyst"},
        headers=SAME,
    )
    assert r.status_code == 403

    # 3. Admin creates user
    await app.login("superadmin")
    r = await app.c.post(
        "/app/api/settings/users",
        json={"name": "bob", "password": "bob-password", "role": "viewer", "clearance": "TLP:GREEN"},
        headers=SAME,
    )
    assert r.status_code == 200
    bob_data = r.json()
    bob_id = bob_data["id"]
    assert bob_data["name"] == "bob"
    assert bob_data["role"] == "viewer"
    assert bob_data["tlpClearance"] == "TLP:GREEN"

    # 4. Admin changes Bob's role and clearance
    r = await app.c.patch(
        f"/app/api/settings/users/{bob_id}/role",
        json={"role": "analyst", "clearance": "TLP:AMBER"},
        headers=SAME,
    )
    assert r.status_code == 200
    assert r.json()["role"] == "analyst"
    assert r.json()["clearance"] == "TLP:AMBER"

    # 5. Admin cannot demote sole admin
    r = await app.c.patch(
        f"/app/api/settings/users/{admin_id}/role",
        json={"role": "analyst"},
        headers=SAME,
    )
    assert r.status_code == 422


async def test_user_password_and_disable(app: App) -> None:
    admin_id = await make_admin(app, "mgtadmin")
    await app.login("mgtadmin")

    # Create user
    r = await app.c.post(
        "/app/api/settings/users",
        json={"name": "carol", "password": "carol-password", "role": "analyst"},
        headers=SAME,
    )
    assert r.status_code == 200
    carol_id = r.json()["id"]

    # Admin resets Carol's password
    r = await app.c.post(
        f"/app/api/settings/users/{carol_id}/password",
        json={"password": "carol-new-password"},
        headers=SAME,
    )
    assert r.status_code == 200

    # Carol signs in with new password
    await app.c.delete("/app/api/session", headers=SAME)
    r = await app.c.post(
        "/app/api/session",
        json={"username": "carol", "password": "carol-new-password"},
        headers=SAME,
    )
    assert r.status_code == 200

    # Admin disables Carol's account
    await app.login("mgtadmin")
    r = await app.c.post(f"/app/api/settings/users/{carol_id}/disable", headers=SAME)
    assert r.status_code == 200

    # Carol cannot sign in while disabled
    r = await app.c.post(
        "/app/api/session",
        json={"username": "carol", "password": "carol-new-password"},
        headers=SAME,
    )
    assert r.status_code == 401

    # Admin re-enables Carol's account
    r = await app.c.post(f"/app/api/settings/users/{carol_id}/enable", headers=SAME)
    assert r.status_code == 200

    # Admin cannot disable own account
    r = await app.c.post(f"/app/api/settings/users/{admin_id}/disable", headers=SAME)
    assert r.status_code == 422


# ── 2. Two-Factor Authentication (TOTP) ──────────────────────────────────────


async def test_totp_two_factor_flow(app: App) -> None:
    admin_id = await make_admin(app, "secadmin")
    await app.login("secadmin")

    # Status before enabling
    r = await app.c.get("/app/api/settings/2fa")
    assert r.status_code == 200
    assert r.json()["enabled"] is False

    # Setup TOTP
    r = await app.c.post("/app/api/settings/2fa/setup", headers=SAME)
    assert r.status_code == 200
    data = r.json()
    secret = data["secret"]
    assert "otpauth_url" in data
    assert "qr_svg" in data
    assert "<svg" in data["qr_svg"]

    # Wrong code is rejected
    r = await app.c.post(
        "/app/api/settings/2fa/enable",
        json={"secret": secret, "code": "000000"},
        headers=SAME,
    )
    assert r.status_code == 422

    # Correct code enables 2FA
    valid_code = totp.totp_code(secret)
    r = await app.c.post(
        "/app/api/settings/2fa/enable",
        json={"secret": secret, "code": valid_code},
        headers=SAME,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "enabled"

    # Status now shows enabled
    r = await app.c.get("/app/api/settings/2fa")
    assert r.json()["enabled"] is True

    # Check /me reports totp_enabled
    r = await app.c.get("/app/api/me")
    assert r.json()["totp_enabled"] is True

    # Sign out
    await app.c.delete("/app/api/session", headers=SAME)

    # Attempt login without TOTP code: returns challenge
    r = await app.c.post(
        "/app/api/session",
        json={"username": "secadmin", "password": "secadmin-password"},
        headers=SAME,
    )
    assert r.status_code == 200
    assert r.json()["ok"] is False
    assert r.json()["totp_required"] is True

    # Attempt login with wrong TOTP code: 401
    r = await app.c.post(
        "/app/api/session",
        json={"username": "secadmin", "password": "secadmin-password", "totp_code": "000000"},
        headers=SAME,
    )
    assert r.status_code == 401

    # Attempt login with correct TOTP code: 200 with cookie
    code = totp.totp_code(secret)
    r = await app.c.post(
        "/app/api/session",
        json={"username": "secadmin", "password": "secadmin-password", "totp_code": code},
        headers=SAME,
    )
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert "tl_user" in r.cookies

    # Replaying the exact same TOTP code within the window is blocked
    await app.c.delete("/app/api/session", headers=SAME)
    r = await app.c.post(
        "/app/api/session",
        json={"username": "secadmin", "password": "secadmin-password", "totp_code": code},
        headers=SAME,
    )
    assert r.status_code == 401
    assert "already used" in r.text

    # The next step's code (a different one, within the accepted drift) still signs in
    r = await app.c.post(
        "/app/api/session",
        json={
            "username": "secadmin",
            "password": "secadmin-password",
            "totp_code": totp.totp_code(secret, time.time() + 30),
        },
        headers=SAME,
    )
    assert r.status_code == 200
    assert r.json()["ok"] is True

    # An API key is not a user account: no 2FA for it
    r = await app.c.get("/app/api/settings/2fa", headers=app.h("viewer"))
    assert r.status_code == 400
    assert "only available for user accounts" in r.text

    # Admin reset-2fa for user
    r = await app.c.post(f"/app/api/settings/users/{admin_id}/reset-2fa", headers=SAME)
    assert r.status_code == 200

    # Now login succeeds without TOTP
    await app.c.delete("/app/api/session", headers=SAME)
    r = await app.c.post(
        "/app/api/session",
        json={"username": "secadmin", "password": "secadmin-password"},
        headers=SAME,
    )
    assert r.status_code == 200
    assert r.json()["ok"] is True


# ── 3. Single Sign-On (SSO) ──────────────────────────────────────────────────


def mock_sso(app: App, on: bool = True) -> None:
    """TL_SSO_MOCK for this app (the fixture builds Settings before the test runs)."""
    transport = app.c._transport
    assert isinstance(transport, httpx.ASGITransport)
    transport.app.state.settings.sso_mock = on  # type: ignore[attr-defined]


SSO_ON = {
    "enabled": True,
    "default_role": "analyst",
    "auto_provision": True,
    "providers": {"google": {"enabled": True, "client_id": "g", "client_secret": "s"}},
}


async def test_sso_configuration_and_mock_login(app: App) -> None:
    mock_sso(app)
    await make_admin(app, "ssoadmin")
    await app.login("ssoadmin")

    # Read default SSO settings
    r = await app.c.get("/app/api/settings/sso")
    assert r.status_code == 200
    assert r.json()["enabled"] is False

    # Update SSO settings (enable Google and Okta)
    r = await app.c.put(
        "/app/api/settings/sso",
        json={
            "enabled": True,
            "default_role": "analyst",
            "auto_provision": True,
            "providers": {
                "google": {"enabled": True, "client_id": "google-client-id", "client_secret": "sec123"},
                "microsoft": {"enabled": False},
                "okta": {
                    "enabled": True,
                    "client_id": "okta-id",
                    "client_secret": "sec456",
                    "domain": "example.okta.com",
                },
            },
        },
        headers=SAME,
    )
    assert r.status_code == 200

    # Public providers list shows google and okta
    r = await app.c.get("/app/api/auth/sso/providers")
    assert r.status_code == 200
    prov_ids = [p["id"] for p in r.json()]
    assert "google" in prov_ids
    assert "okta" in prov_ids
    assert "microsoft" not in prov_ids

    # Mock SSO sign-in
    r = await app.c.post(
        "/app/api/auth/sso/mock",
        json={"provider": "google", "email": "sam@corp.com", "name": "Sam Analyst"},
    )
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert "tl_user" in r.cookies

    # Verify Sam's session and role
    r = await app.c.get("/app/api/me")
    assert r.status_code == 200
    assert r.json()["name"] == "Sam Analyst"
    assert r.json()["role"] == "analyst"


async def test_sso_mock_is_off_by_default(app: App) -> None:
    await make_admin(app, "ssoadmin")
    await app.login("ssoadmin")
    assert (await app.c.put("/app/api/settings/sso", json=SSO_ON, headers=SAME)).status_code == 200
    await app.c.delete("/app/api/session", headers=SAME)
    r = await app.c.post(
        "/app/api/auth/sso/mock", json={"provider": "google", "email": "x@corp.com", "name": "ssoadmin"}
    )
    assert r.status_code == 404
    assert "tl_user" not in r.cookies


async def test_sso_mock_honours_the_sso_switches(app: App) -> None:
    mock_sso(app)
    # SSO never configured: refused
    r = await app.c.post("/app/api/auth/sso/mock", json={"provider": "google", "email": "x@corp.com"})
    assert r.status_code == 403
    await make_admin(app, "ssoadmin")
    await app.login("ssoadmin")
    assert (await app.c.put("/app/api/settings/sso", json=SSO_ON, headers=SAME)).status_code == 200
    await app.c.delete("/app/api/session", headers=SAME)
    # a provider that is switched off: refused
    r = await app.c.post("/app/api/auth/sso/mock", json={"provider": "okta", "email": "x@corp.com"})
    assert r.status_code == 403


async def test_sso_mock_cannot_take_over_an_existing_account(app: App) -> None:
    mock_sso(app)
    await make_admin(app, "ssoadmin")
    await app.login("ssoadmin")
    assert (await app.c.put("/app/api/settings/sso", json=SSO_ON, headers=SAME)).status_code == 200
    await app.c.delete("/app/api/session", headers=SAME)
    app.c.cookies.clear()
    # claiming the admin's name (or login as email) must not sign in as the admin
    for claim in ({"email": "a@corp.com", "name": "ssoadmin"}, {"email": "ssoadmin", "name": ""}):
        r = await app.c.post("/app/api/auth/sso/mock", json={"provider": "google", **claim})
        assert r.status_code == 403, claim
        assert "tl_user" not in r.cookies
    assert (await app.c.get("/app/api/me")).status_code == 401


async def test_sso_mock_never_creates_admins(app: App) -> None:
    mock_sso(app)
    await make_admin(app, "ssoadmin")
    await app.login("ssoadmin")
    body = {**SSO_ON, "default_role": "admin"}
    assert (await app.c.put("/app/api/settings/sso", json=body, headers=SAME)).status_code == 200
    await app.c.delete("/app/api/session", headers=SAME)
    app.c.cookies.clear()
    r = await app.c.post(
        "/app/api/auth/sso/mock", json={"provider": "google", "email": "new@corp.com", "name": "New Person"}
    )
    assert r.status_code == 200
    assert (await app.c.get("/app/api/me")).json()["role"] == "analyst"


async def test_sso_mock_respects_auto_provision_off(app: App) -> None:
    mock_sso(app)
    await make_admin(app, "ssoadmin")
    await app.login("ssoadmin")
    body = {**SSO_ON, "auto_provision": False}
    assert (await app.c.put("/app/api/settings/sso", json=body, headers=SAME)).status_code == 200
    await app.c.delete("/app/api/session", headers=SAME)
    app.c.cookies.clear()
    r = await app.c.post("/app/api/auth/sso/mock", json={"provider": "google", "email": "nobody@corp.com"})
    assert r.status_code == 403


# ── 4. Audit Log Viewer ──────────────────────────────────────────────────────


async def test_audit_log_viewer_search_and_export(app: App) -> None:
    await make_admin(app, "auditor")
    await app.login("auditor")

    # Perform a few distinct auditable actions
    # 1. Create a user
    await app.c.post(
        "/app/api/settings/users",
        json={"name": "targetuser", "password": "targetuser-pass", "role": "viewer"},
        headers=SAME,
    )
    # 2. Add to never-block
    await app.c.post(
        "/app/api/neverblock",
        json={"value": "192.0.2.1", "reason": "corporate test resolver"},
        headers=SAME,
    )

    # Browse audit logs
    r = await app.c.get("/app/api/settings/audit")
    assert r.status_code == 200
    data = r.json()
    assert data["total"] > 0
    actions = [item["action"] for item in data["items"]]
    assert "user.create" in actions
    assert "auditor" in data["actors"]

    # Search by keyword
    r = await app.c.get("/app/api/settings/audit", params={"q": "targetuser"})
    assert r.status_code == 200
    hits = r.json()["items"]
    assert len(hits) >= 1
    assert any("targetuser" in h["target"] for h in hits)

    # Filter by category
    r = await app.c.get("/app/api/settings/audit", params={"category": "user"})
    assert r.status_code == 200
    user_hits = r.json()["items"]
    assert all(h["action"].startswith("user.") or h["action"].startswith("api_key.") for h in user_hits)

    # Export CSV
    r = await app.c.get("/app/api/settings/audit/export", params={"category": "user"})
    assert r.status_code == 200
    assert "text/csv" in r.headers["content-type"]
    csv_text = r.text
    assert "ID,Timestamp (UTC),Actor,Action,Target,Details" in csv_text
    assert "user.create" in csv_text
