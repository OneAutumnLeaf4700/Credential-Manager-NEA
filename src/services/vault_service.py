"""
services/vault_service.py — CRUD operations for the credential vault.

VaultService is stateful: it holds the active Fernet cipher for the session.
Instantiate it once after a successful login and inject it into UI components.

Search runs post-decryption so it works on plaintext content (title, username,
website) without leaking anything to the database layer.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from cryptography.fernet import Fernet

from database.db_manager import get_connection
from models.credential import Credential
from services.crypto_service import (
    decrypt_field,
    encrypt_field,
    make_fernet,
)

# ── Helpers ───────────────────────────────────────────────────────────────────

def _utc_now() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _row_to_credential(fernet: Fernet, row) -> Credential:
    """Decrypt a database row into a Credential object."""
    return Credential(
        id=row["id"],
        title=row["title"],
        username=decrypt_field(fernet, bytes(row["username_enc"])) if row["username_enc"] else "",
        password=decrypt_field(fernet, bytes(row["password_enc"])),
        website=decrypt_field(fernet, bytes(row["website_enc"])) if row["website_enc"] else "",
        notes=decrypt_field(fernet, bytes(row["notes_enc"])) if row["notes_enc"] else "",
        category=row["category"],
        is_favourite=bool(row["is_favourite"]),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _encrypt_row(fernet: Fernet, cred: Credential) -> tuple:
    """Return a tuple of values ready for a DB INSERT or UPDATE."""
    return (
        cred.title,
        encrypt_field(fernet, cred.username),
        encrypt_field(fernet, cred.password),
        encrypt_field(fernet, cred.website),
        encrypt_field(fernet, cred.notes),
        cred.category,
        int(cred.is_favourite),
        cred.created_at,
        cred.updated_at,
    )


# ── Service class ─────────────────────────────────────────────────────────────

class VaultService:
    """
    Provides authenticated CRUD access to stored credentials.

    Args:
        fernet_key: The raw Fernet key returned by auth_service after login.
    """

    def __init__(self, fernet_key: bytes) -> None:
        self._fernet: Fernet = make_fernet(fernet_key)

    # ── Write operations ──────────────────────────────────────────────────────

    def add_credential(self, cred: Credential) -> int:
        """
        Persist a new credential.

        Args:
            cred: Credential with id=None.

        Returns:
            The auto-assigned integer primary key.
        """
        now = _utc_now()
        cred.created_at = now
        cred.updated_at = now
        row = _encrypt_row(self._fernet, cred)

        with get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO credentials
                    (title, username_enc, password_enc, website_enc,
                     notes_enc, category, is_favourite, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                row,
            )
            return cursor.lastrowid

    def update_credential(self, cred: Credential) -> None:
        """
        Update all fields of an existing credential.

        Args:
            cred: Credential with a valid id.

        Raises:
            ValueError: If cred.id is None.
        """
        if cred.id is None:
            raise ValueError("Cannot update a credential without an id.")
        cred.updated_at = _utc_now()
        row = _encrypt_row(self._fernet, cred)

        with get_connection() as conn:
            conn.execute(
                """
                UPDATE credentials
                SET title=?, username_enc=?, password_enc=?, website_enc=?,
                    notes_enc=?, category=?, is_favourite=?,
                    created_at=?, updated_at=?
                WHERE id=?
                """,
                (*row, cred.id),
            )

    def delete_credential(self, credential_id: int) -> None:
        """Permanently delete a credential by its primary key."""
        with get_connection() as conn:
            conn.execute("DELETE FROM credentials WHERE id = ?", (credential_id,))

    def toggle_favourite(self, credential_id: int, value: bool) -> None:
        """Set or clear the favourite flag without loading/re-encrypting the full record."""
        with get_connection() as conn:
            conn.execute(
                "UPDATE credentials SET is_favourite = ? WHERE id = ?",
                (int(value), credential_id),
            )

    # ── Read operations ───────────────────────────────────────────────────────

    def get_all(
        self,
        search: str = "",
        category: str = "",
        favourites_only: bool = False,
    ) -> List[Credential]:
        """
        Return credentials matching the given filters, sorted by title.

        Args:
            search:         Case-insensitive text filter applied to title,
                            username, and website after decryption.
            category:       If non-empty and not "All", restrict to that category.
            favourites_only: If True, return only starred credentials.

        Returns:
            List of fully decrypted Credential objects.
        """
        query = "SELECT * FROM credentials"
        params: list = []
        clauses: list = []

        if favourites_only:
            clauses.append("is_favourite = 1")

        if category and category not in ("", "All"):
            clauses.append("category = ?")
            params.append(category)

        if clauses:
            query += " WHERE " + " AND ".join(clauses)

        query += " ORDER BY title COLLATE NOCASE"

        with get_connection() as conn:
            rows = conn.execute(query, params).fetchall()

        results: List[Credential] = []
        for row in rows:
            try:
                cred = _row_to_credential(self._fernet, row)
            except Exception:
                # Skip any record that fails decryption (e.g. corrupted data)
                continue

            if search:
                needle = search.lower()
                if not any(
                    needle in field.lower()
                    for field in (cred.title, cred.username, cred.website)
                ):
                    continue

            results.append(cred)

        return results

    def get_categories(self) -> List[str]:
        """Return a sorted list of all distinct category names in the vault."""
        with get_connection() as conn:
            rows = conn.execute(
                "SELECT DISTINCT category FROM credentials ORDER BY category"
            ).fetchall()
        return [row["category"] for row in rows]

    # ── Settings ──────────────────────────────────────────────────────────────

    def get_settings(self) -> dict:
        """Return the application settings dict."""
        with get_connection() as conn:
            row = conn.execute("SELECT * FROM settings WHERE id = 1").fetchone()
        return dict(row) if row else {"clipboard_clear_secs": 30}

    def save_settings(self, settings: dict) -> None:
        """Persist updated application settings."""
        with get_connection() as conn:
            conn.execute(
                "UPDATE settings SET clipboard_clear_secs = ? WHERE id = 1",
                (settings["clipboard_clear_secs"],),
            )
