"""
utils/clipboard.py — Clipboard copy with automatic clearing.

Copies text to the system clipboard and schedules a timer to overwrite it
with an empty string after *clear_after_secs* seconds.  Only one timer is
active at a time; each new copy cancels any pending clear.
"""
from __future__ import annotations

import threading
from typing import Optional

import pyperclip

_clear_timer: Optional[threading.Timer] = None


def copy_with_autoclean(text: str, clear_after_secs: int = 30) -> None:
    """
    Copy *text* to the clipboard and schedule an auto-clear.

    Args:
        text:             The string to copy.
        clear_after_secs: Seconds until the clipboard is cleared.
                          Pass 0 to disable auto-clear.
    """
    global _clear_timer

    # Cancel any previously scheduled clear
    if _clear_timer is not None:
        _clear_timer.cancel()
        _clear_timer = None

    pyperclip.copy(text)

    if clear_after_secs > 0:
        _clear_timer = threading.Timer(clear_after_secs, _clear_clipboard)
        _clear_timer.daemon = True  # Don't block process exit
        _clear_timer.start()


def _clear_clipboard() -> None:
    """Overwrite the clipboard with an empty string (best-effort)."""
    try:
        pyperclip.copy("")
    except Exception:
        pass
