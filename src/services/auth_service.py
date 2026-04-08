"""
services/auth_service.py — Master password setup, verification, and rotation.

All sensitive data flows:
  password → derive_key() → wrap_fernet_key() → stored in DB
  password → derive_key() → unwrap_fernet_key() → Fernet key in memory only
"""
from __future__ import annotations

from cryptography.fernet import InvalidToken

from database.db_manager import get_connection
from services.crypto_service import (
    KDF_ITERATIONS,
    derive_key,
    generate_fernet_key,
    generate_salt,
    unwrap_fernet_key,
    wrap_fernet_key,
)


class AuthError(Exception):
    """Raised when authentication fails (wrong password or vault not set up)."""


# ── Public API ────────────────────────────────────────────────────────────────

def is_vault_initialised() -> bool:
    """Return True if a master password has already been created."""
    with get_connection() as conn:
        row = conn.execute("SELECT id FROM auth WHERE id = 1").fetchone()
    return row is not None


def create_master_password(password: str) -> bytes:
    """
    Initialise the vault with a new master password.

    Generates a fresh Fernet key, wraps it with the derived password key,
    and persists the salt + wrapped key in the auth table.

    Args:
        password: The chosen master password (plain text).

    Returns:
        The raw Fernet key for the current session (32-byte URL-safe base64).

    Raises:
        RuntimeError: If a master password already exists.
    """
    if is_vault_initialised():
        raise RuntimeError("Vault is already initialised — use change_master_password() instead.")

    salt = generate_salt()
    wrapping_key = derive_key(password, salt)
    fernet_key = generate_fernet_key()
    wrapped_key = wrap_fernet_key(fernet_key, wrapping_key)

    with get_connection() as conn:
        conn.execute(
            "INSERT INTO auth (id, salt, encrypted_key, kdf_iterations) VALUES (1, ?, ?, ?)",
            (salt, wrapped_key, KDF_ITERATIONS),
        )

    return fernet_key


def verify_master_password(password: str) -> bytes:
    """
    Verify *password* against the stored wrapped key.

    Args:
        password: The master password entered by the user.

    Returns:
        The raw Fernet key for the current session.

    Raises:
        AuthError: If the password is wrong or the vault is not initialised.
    """
    with get_connection() as conn:
        row = conn.execute(
            "SELECT salt, encrypted_key, kdf_iterations FROM auth WHERE id = 1"
        ).fetchone()

    if row is None:
        raise AuthError("Vault is not initialised.")

    salt = bytes(row["salt"])
    encrypted_key = bytes(row["encrypted_key"])
    iterations = int(row["kdf_iterations"])

    wrapping_key = derive_key(password, salt, iterations)

    try:
        fernet_key = unwrap_fernet_key(encrypted_key, wrapping_key)
    except (InvalidToken, Exception):
        raise AuthError("Incorrect master password.")

    return fernet_key


def change_master_password(
    old_password: str,
    new_password: str,
    fernet_key: bytes,
) -> None:
    """
    Replace the master password.

    The Fernet key (and therefore all encrypted data) remains unchanged;
    only the wrapping key is rotated.

    Args:
        old_password: Current master password (for verification).
        new_password: Replacement master password.
        fernet_key:   The active Fernet key from the current session.

    Raises:
        AuthError: If old_password is wrong.
    """
    # Verify the old password first (raises AuthError on failure)
    verify_master_password(old_password)

    new_salt = generate_salt()
    new_wrapping_key = derive_key(new_password, new_salt)
    new_wrapped_key = wrap_fernet_key(fernet_key, new_wrapping_key)

    with get_connection() as conn:
        conn.execute(
            "UPDATE auth SET salt = ?, encrypted_key = ?, kdf_iterations = ? WHERE id = 1",
            (new_salt, new_wrapped_key, KDF_ITERATIONS),
        )
