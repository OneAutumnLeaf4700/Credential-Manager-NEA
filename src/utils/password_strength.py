"""
utils/password_strength.py — Password strength scoring.

Returns a numeric score (0–4), a human-readable label, and a hex colour
suitable for driving the strength meter widget.

Scoring criteria
----------------
+1  Length >= 8
+1  Length >= 14
+1  Contains both uppercase and lowercase letters
+1  Contains at least one digit
+1  Contains at least one special character

Score ranges map to:
  0 — Very Weak  (red)
  1 — Weak       (orange)
  2 — Fair       (amber)
  3 — Strong     (green)
  4 — Very Strong (dark green)
"""
from __future__ import annotations

import re
from typing import Tuple

# (label, hex colour)
_LEVELS: Tuple[Tuple[str, str], ...] = (
    ("Very Weak",   "#ef4444"),
    ("Weak",        "#f97316"),
    ("Fair",        "#f59e0b"),
    ("Strong",      "#22c55e"),
    ("Very Strong", "#16a34a"),
)


def score_password(password: str) -> Tuple[int, str, str]:
    """
    Evaluate password strength.

    Args:
        password: The plain-text password to evaluate.

    Returns:
        A 3-tuple of (score, label, colour) where score is 0–4.
    """
    if not password:
        return 0, "", "#475569"

    points = 0

    if len(password) >= 8:
        points += 1
    if len(password) >= 14:
        points += 1
    if re.search(r"[A-Z]", password) and re.search(r"[a-z]", password):
        points += 1
    if re.search(r"\d", password):
        points += 1
    if re.search(r"[^A-Za-z0-9]", password):
        points += 1

    score = min(points, 4)
    label, colour = _LEVELS[score]
    return score, label, colour
