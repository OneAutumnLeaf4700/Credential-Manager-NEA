"""
ui/theme.py — Design system constants.

All colours, typography sizes, spacing values, and helper functions live here.
Import this module wherever UI code needs visual constants.
"""
from __future__ import annotations

import sys

import customtkinter as ctk

# ── Colour palette ────────────────────────────────────────────────────────────
# Background hierarchy (dark → light = deeper → more elevated)
BG_PRIMARY   = "#0f1117"   # Main window canvas
BG_SURFACE   = "#1a1d27"   # Panels, content areas
BG_CARD      = "#1e2232"   # Credential cards / list rows
BG_INPUT     = "#252a3a"   # Entry fields
SIDEBAR_BG   = "#13151f"   # Left navigation sidebar

# Interactive state overlays
HOVER_OVERLAY  = "#252a3a"  # Row hover
ACTIVE_OVERLAY = "#2d3350"  # Active / pressed

# Accent
ACCENT       = "#6366f1"   # Indigo — primary buttons, active nav, focus rings
ACCENT_HOVER = "#4f46e5"
ACCENT_DIM   = "#312e81"   # Subtle accent background

# Semantic colours
SUCCESS = "#22c55e"
WARNING = "#f59e0b"
DANGER  = "#ef4444"
INFO    = "#38bdf8"

# Text hierarchy
TEXT_PRIMARY   = "#f1f5f9"
TEXT_SECONDARY = "#94a3b8"
TEXT_MUTED     = "#475569"
TEXT_ON_ACCENT = "#ffffff"

# Borders
BORDER       = "#2a2f45"
BORDER_FOCUS = ACCENT

# ── Typography ────────────────────────────────────────────────────────────────
# Platform-appropriate default font stack
if sys.platform == "win32":
    _FAMILY = "Segoe UI"
elif sys.platform == "darwin":
    _FAMILY = "SF Pro Display"
else:
    _FAMILY = "Ubuntu"

# Font tuples: (family, size[, weight])
FONT_DISPLAY = (_FAMILY, 22, "bold")     # Screen / section titles
FONT_HEADING = (_FAMILY, 16, "bold")     # Card / section headings
FONT_SUBHEAD = (_FAMILY, 14, "bold")     # Sub-headings, field labels
FONT_BODY    = (_FAMILY, 13)             # Body copy, list items
FONT_SMALL   = (_FAMILY, 12)             # Secondary info, captions
FONT_CAPTION = (_FAMILY, 11)             # Timestamps, hints
FONT_MONO    = ("Consolas" if sys.platform == "win32" else "Monospace", 13)

# ── Spacing ───────────────────────────────────────────────────────────────────
PAD_XS = 4
PAD_SM = 8
PAD_MD = 16
PAD_LG = 24
PAD_XL = 40

# ── Geometry ──────────────────────────────────────────────────────────────────
RADIUS_SM   = 6
RADIUS_MD   = 10
RADIUS_LG   = 16

SIDEBAR_W   = 220    # Sidebar fixed width in pixels
AUTH_W      = 480    # Auth screen window width
AUTH_H      = 540    # Login screen window height
SETUP_H     = 700    # Setup screen window height (more widgets)
VAULT_W     = 1180   # Main vault window width
VAULT_H     = 740    # Main vault window height
MIN_W       = 960
MIN_H       = 600

# ── Category accent colours ───────────────────────────────────────────────────
CATEGORY_COLOURS: dict[str, str] = {
    "General":  "#6366f1",
    "Social":   "#ec4899",
    "Finance":  "#22c55e",
    "Work":     "#38bdf8",
    "Shopping": "#f59e0b",
    "Other":    "#94a3b8",
}

DEFAULT_CATEGORIES = list(CATEGORY_COLOURS.keys())

# Icon colours cycle — used to give each credential a unique letter-icon hue
_ICON_PALETTE = [
    "#6366f1", "#ec4899", "#22c55e", "#38bdf8",
    "#f59e0b", "#f97316", "#a78bfa", "#34d399",
]


def icon_colour(title: str) -> str:
    """Deterministically map a credential title to an icon accent colour."""
    if not title:
        return _ICON_PALETTE[0]
    return _ICON_PALETTE[sum(ord(c) for c in title) % len(_ICON_PALETTE)]


# ── Button style helpers ──────────────────────────────────────────────────────

def primary_btn_kw(**overrides) -> dict:
    """Keyword arguments for a primary (accent-coloured) CTkButton."""
    base = dict(
        fg_color=ACCENT,
        hover_color=ACCENT_HOVER,
        text_color=TEXT_ON_ACCENT,
        corner_radius=RADIUS_MD,
        font=FONT_SUBHEAD,
    )
    base.update(overrides)
    return base


def ghost_btn_kw(**overrides) -> dict:
    """Keyword arguments for a ghost (transparent background) CTkButton."""
    base = dict(
        fg_color="transparent",
        hover_color=HOVER_OVERLAY,
        text_color=TEXT_SECONDARY,
        corner_radius=RADIUS_SM,
        font=FONT_BODY,
        border_width=0,
    )
    base.update(overrides)
    return base


def danger_btn_kw(**overrides) -> dict:
    """Keyword arguments for a danger (red) CTkButton."""
    base = dict(
        fg_color=DANGER,
        hover_color="#dc2626",
        text_color=TEXT_ON_ACCENT,
        corner_radius=RADIUS_MD,
        font=FONT_SUBHEAD,
    )
    base.update(overrides)
    return base


def input_kw(**overrides) -> dict:
    """Keyword arguments shared by all CTkEntry fields."""
    base = dict(
        fg_color=BG_INPUT,
        text_color=TEXT_PRIMARY,
        placeholder_text_color=TEXT_MUTED,
        border_color=BORDER,
        border_width=1,
        corner_radius=RADIUS_MD,
        font=FONT_BODY,
    )
    base.update(overrides)
    return base


# ── Theme bootstrap ───────────────────────────────────────────────────────────

def apply_theme() -> None:
    """Configure CustomTkinter global appearance before creating any widgets."""
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
