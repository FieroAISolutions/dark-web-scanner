"""
Token-based auth for the local web UI.

A 256-bit URL-safe token is generated on first run, hashed (SHA-256) into
the config DB, and printed plaintext to `data/admin_token.txt` (0600). The
plaintext can be supplied via:

  • a `dws_token` HttpOnly SameSite=Strict cookie (set by the login endpoint),
  • an `?token=…` query parameter (e.g. on the very first visit),
  • or an `X-Auth-Token` request header (for API clients).

The token cannot be brute-forced over the wire (256-bit random), so we
just SHA-256 it; PBKDF2/bcrypt are not required for high-entropy tokens.
"""

from __future__ import annotations

import hashlib
import logging
import secrets as _secrets
from pathlib import Path
from typing import Optional

from fastapi import Cookie, HTTPException, Query, Request, status

from . import db, secrets_store

log = logging.getLogger("dws.auth")

TOKEN_COOKIE = "dws_token"
TOKEN_FILE = Path(__file__).resolve().parent.parent / "data" / "admin_token.txt"
COOKIE_MAX_AGE = 60 * 60 * 24 * 30  # 30 days


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _stored_hash() -> str:
    return (db.get_config_row()["admin_token_hash"] or "").strip()


def _set_hash(h: str) -> None:
    db.update_config({"admin_token_hash": h})


def ensure_initial_token() -> Optional[str]:
    """
    Make sure an admin token exists. Returns the plaintext token IF a new one
    was just generated (so callers can surface it in the console). Returns
    None when an existing token is in place.
    """
    if _stored_hash():
        return None
    plain = _secrets.token_urlsafe(32)
    _set_hash(_hash(plain))
    try:
        TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
        TOKEN_FILE.write_text(plain + "\n", encoding="utf-8")
        secrets_store.restrict_path(TOKEN_FILE)
    except OSError:
        log.warning("could not write admin token file at %s", TOKEN_FILE)
    return plain


def regenerate_token() -> str:
    plain = _secrets.token_urlsafe(32)
    _set_hash(_hash(plain))
    try:
        TOKEN_FILE.write_text(plain + "\n", encoding="utf-8")
        secrets_store.restrict_path(TOKEN_FILE)
    except OSError:
        log.warning("could not write admin token file at %s", TOKEN_FILE)
    return plain


def verify(provided: str) -> bool:
    if not provided:
        return False
    expected = _stored_hash()
    if not expected:
        return False
    return _secrets.compare_digest(_hash(provided), expected)


def extract_token(request: Request) -> str:
    return (
        request.cookies.get(TOKEN_COOKIE)
        or request.query_params.get("token")
        or request.headers.get("X-Auth-Token")
        or ""
    )


async def require_auth(request: Request) -> None:
    if not verify(extract_token(request)):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="auth required")


def cookie_kwargs() -> dict:
    return dict(
        key=TOKEN_COOKIE,
        httponly=True,
        # Lax (not Strict) so the cookie survives the first cross-site
        # top-level navigation that brings the user here from a terminal
        # link, email, etc. CSRF is still defended via the Origin/Host
        # checks in main.py and Lax already blocks cross-site POSTs.
        samesite="lax",
        secure=False,  # localhost http; flip to True if you reverse-proxy via TLS
        max_age=COOKIE_MAX_AGE,
        path="/",
    )
