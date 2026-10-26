"""Recovery-token and password login with expiring, revocable browser sessions."""

from __future__ import annotations

import hashlib
import logging
import time
import threading
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
_sessions: dict[str, tuple[float, str]] = {}
_session_lock = threading.Lock()
_bcrypt_slot = threading.BoundedSemaphore(1)


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
    _write_token_file(plain)
    _set_token_hash(_hash_token(plain))
    return plain


def regenerate_token() -> str:
    plain = _secrets.token_urlsafe(32)
    _write_token_file(plain)
    _set_token_hash(_hash_token(plain))
    return plain


def _write_token_file(plain: str) -> None:
    log_redact.register_secret(plain)
    secrets_store.private_write(TOKEN_FILE, (plain + "\n").encode("utf-8"))


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
    if not provided or len(provided) > 512:
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
    if len(pw) > 72:
        raise ValueError("password too long (max 72 UTF-8 bytes)")
    digest = bcrypt.hashpw(pw, bcrypt.gensalt(rounds=12)).decode("ascii")
    db.update_config({"admin_password_hash": digest})


def clear_password() -> None:
    db.update_config({"admin_password_hash": ""})


def verify_password(provided: str) -> bool:
    if not provided or len(provided) > 512:
        return False
    stored = _stored_password_hash()
    if not stored:
        return False
    pw = provided.strip().encode("utf-8")
    if len(pw) > 72:
        return False
    if not _bcrypt_slot.acquire(blocking=False):
        return False
    try:
        return bcrypt.checkpw(pw,
                              stored.encode("ascii"))
    except (ValueError, TypeError):
        return False
    finally:
        _bcrypt_slot.release()


# ── unified credential check + request helpers ────────────────────────────────

def verify_credential(provided: str) -> bool:
    """True if `provided` matches the recovery token or the configured password."""
    return verify_token(provided) or verify_password(provided)


def issue_session() -> str:
    session = _secrets.token_urlsafe(32)
    now = time.monotonic()
    with _session_lock:
        for key, (expiry, _) in list(_sessions.items()):
            if expiry <= now:
                del _sessions[key]
        if len(_sessions) >= 128:
            del _sessions[next(iter(_sessions))]
        _sessions[_hash_token(session)] = (now + COOKIE_MAX_AGE, _stored_token_hash())
    return session


def verify_session(provided: str) -> bool:
    if not provided or len(provided) > 512:
        return False
    with _session_lock:
        entry = _sessions.get(_hash_token(provided))
    return bool(entry and entry[0] > time.monotonic()
                and _secrets.compare_digest(entry[1], _stored_token_hash()))


def revoke_session(provided: str) -> None:
    with _session_lock:
        _sessions.pop(_hash_token(provided), None)


def extract_token(request: Request) -> str:
    return request.headers.get("X-Auth-Token") or ""


def authenticated(request: Request) -> bool:
    return (verify_session(request.headers.get("X-Session-Token") or "")
            or verify_token(extract_token(request)))


async def require_auth(request: Request) -> None:
    if not authenticated(request):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="auth required")
