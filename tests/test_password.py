import pytest

from backend import auth


def test_no_password_by_default():
    assert auth.has_password() is False
    assert auth.verify_password("anything") is False


def test_set_and_verify():
    auth.set_password("hunter2-extra")
    assert auth.has_password() is True
    assert auth.verify_password("hunter2-extra") is True
    assert auth.verify_password("wrong") is False


def test_minimum_length_enforced():
    with pytest.raises(ValueError):
        auth.set_password("short")


def test_max_length_enforced():
    with pytest.raises(ValueError):
        auth.set_password("x" * 200)


def test_clear_password():
    auth.set_password("temp-password-1")
    auth.clear_password()
    assert auth.has_password() is False
    assert auth.verify_password("temp-password-1") is False


def test_set_password_replaces_old():
    auth.set_password("first-password-x")
    auth.set_password("second-password-x")
    assert auth.verify_password("first-password-x") is False
    assert auth.verify_password("second-password-x") is True


def test_verify_credential_accepts_either():
    token_plain = auth.ensure_initial_token()
    auth.set_password("daily-password-1")

    assert auth.verify_credential(token_plain) is True
    assert auth.verify_credential("daily-password-1") is True
    assert auth.verify_credential("neither") is False


# ── HTTP flows via TestClient ─────────────────────────────────────────────────

def test_status_reports_password_state(client):
    r = client.get("/api/auth/status")
    assert r.status_code == 200
    assert r.json()["password_set"] is False

    r = client.post("/api/auth/set-password", json={"password": "fresh-pw-12"})
    assert r.status_code == 200
    assert r.json()["password_set"] is True

    r = client.get("/api/auth/status")
    assert r.json()["password_set"] is True


def test_login_with_password_returns_method_password(anon_client, admin_token):
    # First, set a password while authed via the token
    r = anon_client.post(
        "/api/auth/set-password",
        json={"password": "letmein-please"},
        headers={"X-Auth-Token": admin_token},
    )
    assert r.status_code == 200

    # Then log in with the password
    r = anon_client.post("/api/auth/login", json={"token": "letmein-please"})
    assert r.status_code == 200
    body = r.json()
    assert body["method"] == "password"
    assert body["password_set"] is True
    # Cookie should be set so subsequent requests are authed
    assert "dws_token" in r.cookies


def test_login_with_token_still_works_after_password_set(anon_client, admin_token):
    anon_client.post(
        "/api/auth/set-password",
        json={"password": "another-pw-1"},
        headers={"X-Auth-Token": admin_token},
    )
    r = anon_client.post("/api/auth/login", json={"token": admin_token})
    assert r.status_code == 200
    assert r.json()["method"] == "token"


def test_login_rejects_invalid_credential(anon_client):
    r = anon_client.post("/api/auth/login", json={"token": "nope"})
    assert r.status_code == 401


def test_set_password_requires_current_when_changing(client):
    client.post("/api/auth/set-password", json={"password": "first-time-12"})

    # No `current` → 403
    r = client.post("/api/auth/set-password", json={"password": "second-time-12"})
    assert r.status_code == 403

    # Wrong `current` → 403
    r = client.post("/api/auth/set-password",
                    json={"password": "second-time-12", "current": "wrong"})
    assert r.status_code == 403

    # Right `current` → 200
    r = client.post("/api/auth/set-password",
                    json={"password": "second-time-12", "current": "first-time-12"})
    assert r.status_code == 200


def test_clear_password_requires_current(client):
    client.post("/api/auth/set-password", json={"password": "removeme-12"})

    r = client.post("/api/auth/clear-password", json={})
    assert r.status_code == 403

    r = client.post("/api/auth/clear-password", json={"current": "removeme-12"})
    assert r.status_code == 200
    assert r.json()["password_set"] is False


def test_password_endpoints_require_auth(anon_client):
    r = anon_client.post("/api/auth/set-password", json={"password": "anything-1"})
    assert r.status_code == 401
    r = anon_client.post("/api/auth/clear-password", json={})
    assert r.status_code == 401


# ── Whitespace tolerance — both ends strip surrounding whitespace ─────────────

def test_password_stripped_on_set_and_verify():
    """Saving with trailing whitespace and logging in without (or vice versa)
    should still match — prevents hard-to-debug autofill / mobile-keyboard
    lockouts."""
    auth.set_password("  daily-pw-12  ")
    assert auth.verify_password("daily-pw-12") is True
    assert auth.verify_password("  daily-pw-12  ") is True
    assert auth.verify_password("daily-pw-12 ") is True
    assert auth.verify_password(" daily-pw-12") is True


def test_login_with_password_tolerates_whitespace(anon_client, admin_token):
    anon_client.post(
        "/api/auth/set-password",
        json={"password": "trim-me-pw-12  "},  # saved with trailing space
        headers={"X-Auth-Token": admin_token},
    )
    # Login without the trailing space — must still succeed
    r = anon_client.post("/api/auth/login", json={"token": "trim-me-pw-12"})
    assert r.status_code == 200
    assert r.json()["method"] == "password"
