"""
Symmetric encryption-at-rest for sensitive config values (HIBP API key,
SMTP password, webhook URL).

The encryption key is generated on first run and stored in
`data/.scanner_key` with 0600 permissions. Ciphertext is prefixed with
`enc:v1:` so we can detect (and migrate) legacy plaintext values.

Threat model: protects secrets if the database file is exfiltrated on
its own (backups, snapshots, accidental commits). Does NOT protect
against an attacker with full filesystem access on the same host.
For that, use OS keyring or full-disk encryption.
"""

from __future__ import annotations

import base64
import logging
import os
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

log = logging.getLogger("dws.secrets")

PREFIX = "enc:v1:"
KEY_PATH = Path(__file__).resolve().parent.parent / "data" / ".scanner_key"

_fernet: Optional[Fernet] = None


def _restrict(path: Path) -> None:
    """Best-effort 0600 permissions; no-op on Windows."""
    try:
        os.chmod(path, 0o600)
    except (OSError, NotImplementedError):
        pass


def _load_or_create_key() -> bytes:
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    if KEY_PATH.exists():
        data = KEY_PATH.read_bytes().strip()
        if data:
            return data
    key = Fernet.generate_key()
    KEY_PATH.write_bytes(key)
    _restrict(KEY_PATH)
    log.info("generated new encryption key at %s", KEY_PATH)
    return key


def _f() -> Fernet:
    global _fernet
    if _fernet is None:
        _fernet = Fernet(_load_or_create_key())
    return _fernet


def is_encrypted(value: str) -> bool:
    return isinstance(value, str) and value.startswith(PREFIX)


def encrypt(value: str) -> str:
    if not value:
        return ""
    if is_encrypted(value):
        return value
    token = _f().encrypt(value.encode("utf-8")).decode("ascii")
    return PREFIX + token


def decrypt(value: str) -> str:
    if not value:
        return ""
    if not is_encrypted(value):
        # Legacy plaintext — return as-is. Caller is responsible for
        # invoking migrate() during startup to upgrade these in place.
        return value
    raw = value[len(PREFIX):]
    try:
        return _f().decrypt(raw.encode("ascii")).decode("utf-8")
    except InvalidToken:
        log.error("failed to decrypt secret — was the encryption key changed?")
        return ""


def migrate_legacy(get_row, update_fn, secret_fields) -> int:
    """Encrypt any legacy plaintext secrets in place. Returns count of migrated values."""
    row = dict(get_row())
    upgrades = {}
    for field in secret_fields:
        val = row.get(field) or ""
        if val and not is_encrypted(val):
            upgrades[field] = encrypt(val)
    if upgrades:
        update_fn(upgrades)
        log.info("migrated %d legacy secret(s) to encrypted-at-rest", len(upgrades))
    return len(upgrades)


def restrict_path(path: Path) -> None:
    """Public helper for callers (e.g. db.py) to apply 0600 perms."""
    _restrict(path)
