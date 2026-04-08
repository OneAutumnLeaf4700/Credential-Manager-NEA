"""
models/credential.py — Credential data model.

This module defines the Credential dataclass which is the core domain object
passed between services and UI components. All fields are plain Python types;
encryption/decryption is handled entirely in the service layer.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Credential:
    """Represents a single stored credential entry."""

    title: str                        # Human-readable service name, e.g. "GitHub"
    username: str                     # Login username or email
    password: str                     # Plain-text password (decrypted in memory only)
    website: str = ""                 # URL or domain
    notes: str = ""                   # Free-form notes
    category: str = "General"         # Category tag
    is_favourite: bool = False        # Starred / pinned entry
    created_at: str = ""              # ISO-8601 UTC timestamp (set by service)
    updated_at: str = ""              # ISO-8601 UTC timestamp (set by service)
    id: Optional[int] = None          # Database primary key (None before first save)

    # ── Convenience ──────────────────────────────────────────────────────────

    @property
    def display_username(self) -> str:
        """Truncate username for display if it is very long."""
        return self.username if len(self.username) <= 32 else self.username[:29] + "..."

    @property
    def display_website(self) -> str:
        """Strip scheme from URL for compact display."""
        url = self.website
        for prefix in ("https://", "http://", "www."):
            if url.startswith(prefix):
                url = url[len(prefix):]
        return url.rstrip("/")
