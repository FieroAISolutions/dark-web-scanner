"""
Per-test isolation: redirect DB, encryption-key, and token files into a
unique tmp directory, reset module-level caches, and (when requested)
provide a FastAPI TestClient already authenticated via X-Auth-Token.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


@pytest.fixture(autouse=True)
def isolate_state(tmp_path, monkeypatch):
    from backend import auth, db, secrets_store

    monkeypatch.setattr(db, "DB_PATH", tmp_path / "scanner.db")
    monkeypatch.setattr(secrets_store, "KEY_PATH", tmp_path / ".scanner_key")
    monkeypatch.setattr(auth, "TOKEN_FILE", tmp_path / "admin_token.txt")
    # Reset cached Fernet so a fresh key is generated for this test
    monkeypatch.setattr(secrets_store, "_fernet", None)

    db.init()
    yield


@pytest.fixture
def admin_token():
    """Create or recover the admin token and return its plaintext value."""
    from backend import auth
    plain = auth.ensure_initial_token()
    if plain is None and auth.TOKEN_FILE.exists():
        # Another fixture already initialised the token; read the plaintext.
        plain = auth.TOKEN_FILE.read_text().strip()
    assert plain, "expected a token to be generated"
    return plain


@pytest.fixture
def client(admin_token, monkeypatch):
    """Authenticated FastAPI TestClient. Uses a pre-set auth cookie."""
    from fastapi.testclient import TestClient
    from backend import main as main_mod

    # Allow the TestClient's default Host: testserver to pass our middleware
    monkeypatch.setattr(
        main_mod, "ALLOWED_HOST_NAMES",
        {"localhost", "127.0.0.1", "testserver"},
    )

    c = TestClient(main_mod.app)
    c.cookies.set("dws_token", admin_token)
    return c


@pytest.fixture
def anon_client(monkeypatch):
    """Unauthenticated TestClient (no token set)."""
    from fastapi.testclient import TestClient
    from backend import auth, main as main_mod

    monkeypatch.setattr(
        main_mod, "ALLOWED_HOST_NAMES",
        {"localhost", "127.0.0.1", "testserver"},
    )
    # Make sure a token exists in the DB so /api/auth/login can succeed in tests
    auth.ensure_initial_token()
    return TestClient(main_mod.app)
