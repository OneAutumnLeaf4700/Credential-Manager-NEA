"""
database/db_manager.py — SQLite initialisation and connection management.

Replaces the legacy four-database design with a single vault.db file.
All schema creation runs inside initialise(), called once at startup.
"""
from __future__ import annotations
import contextlib
import sqlite3
from typing import Generator

from config import DB_PATH

# ── Schema ────────────────────────────────────────────────────────────────────
_SCHEMA = """
-- Authentication table: stores the PBKDF2 salt and the Fernet key
-- wrapped with the derived key.  Only one row (id = 1) ever exists.
CREATE TABLE IF NOT EXISTS auth (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    salt            BLOB    NOT NULL,
    encrypted_key   BLOB    NOT NULL,
    kdf_iterations  INTEGER NOT NULL DEFAULT 600000
);

-- Credentials table: every field except title and category is encrypted.
CREATE TABLE IF NOT EXISTS credentials (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    title        TEXT    NOT NULL,
    username_enc BLOB    NOT NULL DEFAULT '',
    password_enc BLOB    NOT NULL,
    website_enc  BLOB    NOT NULL DEFAULT '',
    notes_enc    BLOB    NOT NULL DEFAULT '',
    category     TEXT    NOT NULL DEFAULT 'General',
    is_favourite INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT    NOT NULL,
    updated_at   TEXT    NOT NULL
);

-- Application settings: single row, id is always 1.
CREATE TABLE IF NOT EXISTS settings (
    id                  INTEGER PRIMARY KEY CHECK (id = 1),
    clipboard_clear_secs INTEGER NOT NULL DEFAULT 30
);

INSERT OR IGNORE INTO settings (id, clipboard_clear_secs)
VALUES (1, 30);
"""


def initialise() -> None:
    """Create tables and default rows if they do not already exist."""
    with get_connection() as conn:
        conn.executescript(_SCHEMA)


@contextlib.contextmanager
def get_connection() -> Generator[sqlite3.Connection, None, None]:
    """
    Context manager that provides a committed SQLite connection.

    Usage::

        with get_connection() as conn:
            conn.execute("SELECT ...")

    Commits on clean exit, rolls back on any exception.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")  # better concurrency
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
