"""
Auth for the local web UI.

Two credentials are supported:

  • A 256-bit URL-safe **recovery token**, generated on first run, hashed
    (SHA-256) into the config DB and written plaintext to
    `data/admin_token.txt` (0600). Designed for emergency / first-run
    access — supplied via `?token=…`, an `X-Auth-Token` header, or the
    login form.

  • An optional **password** (bcrypt-hashed). When a password is set,
    operators can sign in with it from the login form. After successful
    sign-in (whether by token or password), the cookie always carries
    the recovery token, so per-request verification stays cheap (single
    SHA-256 compare instead of bcrypt).

The recovery token is therefore both an emergency credential and the
session value. Regenerating it logs out every browser. Setting/clearing
the password does not log anybody out.
"""

from __future__ import annotations

import hashlib
import logging
import secrets as _secrets
from pathlib import Path
from typing import Optional

import bcrypt
from fastapi import HTTPException, Request, status

from . import db, log_redact, secrets_store

log = logging.getLogger("dws.auth")

TOKEN_COOKIE = "dws_token"
TOKEN_FILE = Path(__file__).resolve().parent.parent / "data" / "admin_token.txt"
COOKIE_MAX_AGE = 60 * 60 * 24 * 30  # 30 days

MIN_PASSWORD_LEN = 8


# ── token (recovery + session) ────────────────────────────────────────────────

def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _stored_token_hash() -> str:
    return (db.get_config_row()["admin_token_hash"] or "").strip()


def _set_token_hash(h: str) -> None:
    db.update_config({"admin_token_hash": h})


def ensure_initial_token() -> Optional[str]:
    """Generate-and-persist on first run. Returns the plaintext only when newly created."""
    if _stored_token_hash():
        return None
    plain = _secrets.token_urlsafe(32)
    _set_token_hash(_hash_token(plain))
    _write_token_file(plain)
    return plain


def regenerate_token() -> str:
    plain = _secrets.token_urlsafe(32)
    _set_token_hash(_hash_token(plain))
    _write_token_file(plain)
    return plain


def _write_token_file(plain: str) -> None:
    log_redact.register_secret(plain)
    try:
        TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
        TOKEN_FILE.write_text(plain + "\n", encoding="utf-8")
        secrets_store.restrict_path(TOKEN_FILE)
    except OSError:
        log.warning("could not write admin token file at %s", TOKEN_FILE)


def read_recovery_token() -> str:
    """Return the plaintext recovery token from disk, or empty if unavailable."""
    try:
        if TOKEN_FILE.exists():
            token = TOKEN_FILE.read_text(encoding="utf-8").strip()
            log_redact.register_secret(token)
            return token
    except OSError:
        pass
    return ""


def verify_token(provided: str) -> bool:
    if not provided:
        return False
    expected = _stored_token_hash()
    if not expected:
        return False
    return _secrets.compare_digest(_hash_token(provided), expected)


# ── password ──────────────────────────────────────────────────────────────────

def _stored_password_hash() -> str:
    return (db.get_config_row()["admin_password_hash"] or "").strip()


def has_password() -> bool:
    return bool(_stored_password_hash())


def set_password(new_password: str) -> None:
    # Strip surrounding whitespace so a stray space (autofill, mobile keyboard
    # double-space) can't lock the user out of their own account.
    pw = (new_password or "").strip().encode("utf-8")
    if len(pw) < MIN_PASSWORD_LEN:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LEN} characters")
    if len(pw) > 128:
        raise ValueError("password too long (max 128 bytes)")
    digest = bcrypt.hashpw(pw, bcrypt.gensalt(rounds=12)).decode("ascii")
    db.update_config({"admin_password_hash": digest})


def clear_password() -> None:
    db.update_config({"admin_password_hash": ""})


def verify_password(provided: str) -> bool:
    if not provided:
        return False
    stored = _stored_password_hash()
    if not stored:
        return False
    try:
        return bcrypt.checkpw((provided or "").strip().encode("utf-8"),
                              stored.encode("ascii"))
    except (ValueError, TypeError):
        return False


# ── unified credential check + request helpers ────────────────────────────────

def verify_credential(provided: str) -> bool:
    """True if `provided` matches the recovery token or the configured password."""
    return verify_token(provided) or verify_password(provided)


def extract_token(request: Request) -> str:
    """Pull the credential from cookie / query / header. Cookies always carry the token."""
    return (
        request.cookies.get(TOKEN_COOKIE)
        or request.query_params.get("token")
        or request.headers.get("X-Auth-Token")
        or ""
    )


async def require_auth(request: Request) -> None:
    """
    Cheap per-request check: cookie/header/qs MUST carry the recovery token.
    Password is only accepted at /api/auth/login, where we re-issue a token cookie.
    """
    if not verify_token(extract_token(request)):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="auth required")


def cookie_kwargs() -> dict:
    return dict(
        key=TOKEN_COOKIE,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=COOKIE_MAX_AGE,
        path="/",
    )
