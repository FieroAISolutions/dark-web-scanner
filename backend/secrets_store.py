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
_windows_sid: Optional[str] = None


def _restrict(path: Path) -> None:
    """Fail closed if owner-only permissions cannot be applied."""
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        import csv
        import subprocess
        global _windows_sid
        if _windows_sid is None:
            _windows_sid = next(csv.reader(subprocess.check_output(
                ["whoami", "/user", "/fo", "csv", "/nh"], text=True).splitlines()))[1]
        sid = _windows_sid
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        descriptor = ctypes.c_void_p()
        convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
        convert.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                            ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
        convert.restype = wintypes.BOOL
        rights = "OICI;FA" if path.is_dir() else ";FA"
        if not convert(f"D:P(A;{rights};;;{sid})", 1, ctypes.byref(descriptor), None):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            apply = advapi.SetFileSecurityW
            apply.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
            apply.restype = wintypes.BOOL
            if not apply(str(path), 0x80000004, descriptor):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            free = ctypes.WinDLL("kernel32").LocalFree
            free.argtypes = [ctypes.c_void_p]
            free.restype = ctypes.c_void_p
            free(descriptor)
    else:
        os.chmod(path, 0o700 if path.is_dir() else 0o600)


def private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    _restrict(path)


def private_write(path: Path, data: bytes) -> None:
    private_directory(path.parent)
    if path.exists():
        _restrict(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        _restrict(path)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
    finally:
        os.close(fd)


def _load_or_create_key() -> bytes:
    private_directory(KEY_PATH.parent)
    if KEY_PATH.exists():
        _restrict(KEY_PATH)
        data = KEY_PATH.read_bytes().strip()
        if data:
            return data
    key = Fernet.generate_key()
    private_write(KEY_PATH, key)
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
