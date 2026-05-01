import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable, Optional

from . import severity as sev_mod

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "scanner.db"
_write_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    enabled INTEGER NOT NULL DEFAULT 0,
    interval_hours INTEGER NOT NULL DEFAULT 6,
    hibp_api_key TEXT NOT NULL DEFAULT '',
    hibp_rpm INTEGER NOT NULL DEFAULT 10,
    include_pastes INTEGER NOT NULL DEFAULT 1,
    alert_on_new INTEGER NOT NULL DEFAULT 1,
    smtp_host TEXT NOT NULL DEFAULT '',
    smtp_port INTEGER NOT NULL DEFAULT 587,
    smtp_user TEXT NOT NULL DEFAULT '',
    smtp_pass TEXT NOT NULL DEFAULT '',
    from_addr TEXT NOT NULL DEFAULT '',
    to_email TEXT NOT NULL DEFAULT '',
    webhook_url TEXT NOT NULL DEFAULT '',
    webhook_kind TEXT NOT NULL DEFAULT 'generic',
    user_agent TEXT NOT NULL DEFAULT 'DarkWebScanner/1.0'
);

CREATE TABLE IF NOT EXISTS monitored_emails (
    email TEXT PRIMARY KEY,
    added_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS breaches (
    name TEXT PRIMARY KEY,
    title TEXT,
    domain TEXT,
    breach_date TEXT,
    added_date TEXT,
    modified_date TEXT,
    pwn_count INTEGER,
    description TEXT,
    data_classes TEXT,
    is_verified INTEGER,
    is_fabricated INTEGER,
    is_sensitive INTEGER,
    is_retired INTEGER,
    is_spam_list INTEGER,
    logo_path TEXT
);

CREATE TABLE IF NOT EXISTS email_breaches (
    email TEXT NOT NULL,
    breach_name TEXT NOT NULL,
    first_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (email, breach_name)
);

CREATE TABLE IF NOT EXISTS pastes (
    id TEXT PRIMARY KEY,
    source TEXT,
    title TEXT,
    paste_date TEXT,
    email_count INTEGER
);

CREATE TABLE IF NOT EXISTS email_pastes (
    email TEXT NOT NULL,
    paste_id TEXT NOT NULL,
    first_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (email, paste_id)
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at TEXT,
    email_count INTEGER NOT NULL DEFAULT 0,
    new_breaches INTEGER NOT NULL DEFAULT 0,
    new_pastes INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'running',
    error TEXT,
    persist INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_email_breaches_email ON email_breaches(email);
CREATE INDEX IF NOT EXISTS idx_email_breaches_seen  ON email_breaches(first_seen_at);
CREATE INDEX IF NOT EXISTS idx_email_pastes_email   ON email_pastes(email);
CREATE INDEX IF NOT EXISTS idx_scan_runs_started    ON scan_runs(started_at DESC);
"""


def init() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with connect() as conn:
        conn.executescript(SCHEMA)
        cur = conn.execute("SELECT COUNT(*) FROM config")
        if cur.fetchone()[0] == 0:
            conn.execute("INSERT INTO config (id) VALUES (1)")
        conn.commit()


@contextmanager
def connect():
    conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=NORMAL")
    try:
        yield conn
    finally:
        conn.close()


def write(fn):
    """Decorator: serialize writes via the module lock."""
    def wrapper(*args, **kwargs):
        with _write_lock:
            return fn(*args, **kwargs)
    return wrapper


# ── config ────────────────────────────────────────────────────────────────────

def get_config_row() -> sqlite3.Row:
    with connect() as conn:
        row = conn.execute("SELECT * FROM config WHERE id = 1").fetchone()
        if row is None:
            conn.execute("INSERT INTO config (id) VALUES (1)")
            row = conn.execute("SELECT * FROM config WHERE id = 1").fetchone()
        return row


@write
def update_config(fields: dict) -> None:
    if not fields:
        return
    cols = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values())
    with connect() as conn:
        conn.execute(f"UPDATE config SET {cols} WHERE id = 1", values)


# ── monitored emails ──────────────────────────────────────────────────────────

def list_emails() -> list[dict]:
    with connect() as conn:
        rows = conn.execute("""
            SELECT m.email, m.added_at,
                   (SELECT COUNT(*) FROM email_breaches eb WHERE eb.email = m.email) AS breach_count,
                   (SELECT COUNT(*) FROM email_pastes  ep WHERE ep.email = m.email) AS paste_count,
                   (SELECT MAX(first_seen_at) FROM email_breaches eb WHERE eb.email = m.email) AS last_breach_at
            FROM monitored_emails m
            ORDER BY m.email
        """).fetchall()
        return [dict(r) for r in rows]


@write
def add_emails(emails: Iterable[str]) -> tuple[list[str], list[str]]:
    added, skipped = [], []
    with connect() as conn:
        for email in emails:
            try:
                conn.execute("INSERT INTO monitored_emails (email) VALUES (?)", (email,))
                added.append(email)
            except sqlite3.IntegrityError:
                skipped.append(email)
    return added, skipped


@write
def remove_email(email: str) -> bool:
    with connect() as conn:
        cur = conn.execute("DELETE FROM monitored_emails WHERE email = ?", (email,))
        return cur.rowcount > 0


def get_emails() -> list[str]:
    with connect() as conn:
        return [r["email"] for r in conn.execute("SELECT email FROM monitored_emails ORDER BY email")]


# ── breaches & pastes ─────────────────────────────────────────────────────────

@write
def upsert_breach(b: dict) -> None:
    with connect() as conn:
        conn.execute("""
            INSERT INTO breaches (name, title, domain, breach_date, added_date, modified_date,
                                  pwn_count, description, data_classes, is_verified, is_fabricated,
                                  is_sensitive, is_retired, is_spam_list, logo_path)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                title=excluded.title, domain=excluded.domain, breach_date=excluded.breach_date,
                added_date=excluded.added_date, modified_date=excluded.modified_date,
                pwn_count=excluded.pwn_count, description=excluded.description,
                data_classes=excluded.data_classes, is_verified=excluded.is_verified,
                is_fabricated=excluded.is_fabricated, is_sensitive=excluded.is_sensitive,
                is_retired=excluded.is_retired, is_spam_list=excluded.is_spam_list,
                logo_path=excluded.logo_path
        """, (
            b.get("Name"), b.get("Title"), b.get("Domain"), b.get("BreachDate"),
            b.get("AddedDate"), b.get("ModifiedDate"), b.get("PwnCount"),
            b.get("Description"), json.dumps(b.get("DataClasses") or []),
            int(bool(b.get("IsVerified"))), int(bool(b.get("IsFabricated"))),
            int(bool(b.get("IsSensitive"))), int(bool(b.get("IsRetired"))),
            int(bool(b.get("IsSpamList"))), b.get("LogoPath"),
        ))


@write
def link_email_breach(email: str, breach_name: str) -> bool:
    """Returns True if this is a NEW link (not previously seen)."""
    with connect() as conn:
        try:
            conn.execute(
                "INSERT INTO email_breaches (email, breach_name) VALUES (?, ?)",
                (email, breach_name),
            )
            return True
        except sqlite3.IntegrityError:
            return False


def email_breach_names(email: str) -> set[str]:
    with connect() as conn:
        return {r[0] for r in conn.execute(
            "SELECT breach_name FROM email_breaches WHERE email = ?", (email,))}


@write
def upsert_paste(p: dict) -> None:
    with connect() as conn:
        conn.execute("""
            INSERT INTO pastes (id, source, title, paste_date, email_count)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                source=excluded.source, title=excluded.title,
                paste_date=excluded.paste_date, email_count=excluded.email_count
        """, (p.get("Id"), p.get("Source"), p.get("Title"), p.get("Date"), p.get("EmailCount")))


@write
def link_email_paste(email: str, paste_id: str) -> bool:
    with connect() as conn:
        try:
            conn.execute(
                "INSERT INTO email_pastes (email, paste_id) VALUES (?, ?)",
                (email, paste_id),
            )
            return True
        except sqlite3.IntegrityError:
            return False


def email_paste_ids(email: str) -> set[str]:
    with connect() as conn:
        return {r[0] for r in conn.execute(
            "SELECT paste_id FROM email_pastes WHERE email = ?", (email,))}


def list_findings(limit: int = 200, only_new_since: Optional[str] = None) -> list[dict]:
    sql = """
        SELECT eb.email, eb.breach_name, eb.first_seen_at,
               b.title, b.domain, b.breach_date, b.pwn_count, b.data_classes,
               b.is_sensitive, b.is_verified, b.is_fabricated, b.is_spam_list,
               b.is_retired, b.logo_path
        FROM email_breaches eb
        LEFT JOIN breaches b ON b.name = eb.breach_name
    """
    params: list = []
    if only_new_since:
        sql += " WHERE eb.first_seen_at >= ?"
        params.append(only_new_since)
    sql += " ORDER BY eb.first_seen_at DESC LIMIT ?"
    params.append(limit)
    with connect() as conn:
        rows = conn.execute(sql, params).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["data_classes"] = json.loads(d.get("data_classes") or "[]")
            except Exception:
                d["data_classes"] = []
            d["severity"] = sev_mod.compute(d)
            out.append(d)
        return sev_mod.by_severity(out)


def severity_counts() -> dict:
    """Count email_breach links bucketed by computed severity level."""
    with connect() as conn:
        rows = conn.execute("""
            SELECT b.data_classes, b.is_sensitive, b.is_verified,
                   b.is_fabricated, b.is_spam_list, b.is_retired
              FROM email_breaches eb
              LEFT JOIN breaches b ON b.name = eb.breach_name
        """).fetchall()
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in rows:
        try:
            dc = json.loads(r["data_classes"] or "[]")
        except Exception:
            dc = []
        level = sev_mod.compute({
            "data_classes": dc,
            "is_sensitive": r["is_sensitive"],
            "is_verified": r["is_verified"],
            "is_fabricated": r["is_fabricated"],
            "is_spam_list": r["is_spam_list"],
            "is_retired": r["is_retired"],
        })["level"]
        counts[level] = counts.get(level, 0) + 1
    return counts


def list_pastes(limit: int = 200) -> list[dict]:
    with connect() as conn:
        rows = conn.execute("""
            SELECT ep.email, ep.paste_id, ep.first_seen_at,
                   p.source, p.title, p.paste_date, p.email_count
            FROM email_pastes ep
            LEFT JOIN pastes p ON p.id = ep.paste_id
            ORDER BY ep.first_seen_at DESC
            LIMIT ?
        """, (limit,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["severity"] = sev_mod.compute_paste(d)
            out.append(d)
        return out


# ── scan runs ─────────────────────────────────────────────────────────────────

@write
def create_run(email_count: int, persist: bool) -> int:
    with connect() as conn:
        cur = conn.execute(
            "INSERT INTO scan_runs (email_count, persist) VALUES (?, ?)",
            (email_count, 1 if persist else 0),
        )
        return cur.lastrowid


@write
def finish_run(run_id: int, *, new_breaches: int, new_pastes: int,
               status: str = "ok", error: Optional[str] = None) -> None:
    with connect() as conn:
        conn.execute("""
            UPDATE scan_runs
               SET finished_at = datetime('now'),
                   new_breaches = ?, new_pastes = ?, status = ?, error = ?
             WHERE id = ?
        """, (new_breaches, new_pastes, status, error, run_id))


def get_run(run_id: int) -> Optional[dict]:
    with connect() as conn:
        row = conn.execute("SELECT * FROM scan_runs WHERE id = ?", (run_id,)).fetchone()
        return dict(row) if row else None


def recent_runs(limit: int = 20) -> list[dict]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM scan_runs ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def dashboard_stats() -> dict:
    with connect() as conn:
        emails = conn.execute("SELECT COUNT(*) FROM monitored_emails").fetchone()[0]
        breaches = conn.execute("SELECT COUNT(*) FROM email_breaches").fetchone()[0]
        pastes = conn.execute("SELECT COUNT(*) FROM email_pastes").fetchone()[0]
        unique_breaches = conn.execute(
            "SELECT COUNT(DISTINCT breach_name) FROM email_breaches").fetchone()[0]
        last_run = conn.execute(
            "SELECT * FROM scan_runs ORDER BY started_at DESC LIMIT 1").fetchone()
        return {
            "monitored_count": emails,
            "total_breach_findings": breaches,
            "unique_breaches": unique_breaches,
            "total_paste_findings": pastes,
            "last_run": dict(last_run) if last_run else None,
        }
