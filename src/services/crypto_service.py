"""
services/crypto_service.py — All cryptographic primitives.

Security model
--------------
1. The user's master password is never stored.
2. On first setup a random 32-byte salt is generated and saved in the DB.
3. PBKDF2-HMAC-SHA256 with 600 000 iterations derives a 32-byte key from
   (password + salt).  This is the *wrapping key*.
4. A random Fernet key is generated and **encrypted** (wrapped) with the
   wrapping key using Fernet.  Only the wrapped form is stored on disk.
5. At login the wrapping key is re-derived and used to unwrap the Fernet key.
   If the password is wrong, cryptography.fernet.InvalidToken is raised.
6. The Fernet key is used for every individual credential field at rest.

Nothing secret is ever written to disk unprotected.
"""
from __future__ import annotations
import base64
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Number of PBKDF2 iterations — increase only affects new vaults / password changes.
KDF_ITERATIONS: int = 600_000
SALT_LENGTH: int = 32


# ── Key derivation ────────────────────────────────────────────────────────────

def generate_salt() -> bytes:
    """Return a cryptographically random 32-byte salt."""
    return os.urandom(SALT_LENGTH)


def derive_key(password: str, salt: bytes, iterations: int = KDF_ITERATIONS) -> bytes:
    """
    Derive a 32-byte wrapping key from *password* and *salt* via PBKDF2-HMAC-SHA256.

    Args:
        password:   The master password (plain text).
        salt:       A random 32-byte salt stored in the auth table.
        iterations: KDF iteration count (defaults to KDF_ITERATIONS).

    Returns:
        32-byte derived key.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


# ── Fernet key wrapping / unwrapping ─────────────────────────────────────────

def generate_fernet_key() -> bytes:
    """Return a new random 32-byte Fernet key (URL-safe base64 encoded)."""
    return Fernet.generate_key()


def wrap_fernet_key(fernet_key: bytes, wrapping_key: bytes) -> bytes:
    """
    Encrypt *fernet_key* with *wrapping_key*.

    Args:
        fernet_key:   The Fernet key to protect.
        wrapping_key: 32-byte derived key from derive_key().

    Returns:
        Fernet-encrypted ciphertext of fernet_key.
    """
    wrapper = Fernet(base64.urlsafe_b64encode(wrapping_key))
    return wrapper.encrypt(fernet_key)


def unwrap_fernet_key(encrypted_key: bytes, wrapping_key: bytes) -> bytes:
    """
    Decrypt the wrapped Fernet key.

    Raises:
        InvalidToken: If *wrapping_key* is wrong (i.e. incorrect master password).
    """
    wrapper = Fernet(base64.urlsafe_b64encode(wrapping_key))
    return wrapper.decrypt(encrypted_key)


# ── Per-value encryption / decryption ────────────────────────────────────────

def make_fernet(fernet_key: bytes) -> Fernet:
    """Return a Fernet cipher instance ready for encrypt/decrypt calls."""
    return Fernet(fernet_key)


def encrypt_field(fernet: Fernet, value: str) -> bytes:
    """Encrypt a string credential field; returns raw ciphertext bytes."""
    return fernet.encrypt(value.encode("utf-8"))


def decrypt_field(fernet: Fernet, data: bytes) -> str:
    """Decrypt ciphertext bytes back to a string credential field."""
    return fernet.decrypt(data).decode("utf-8")
