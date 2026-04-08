"""
ui/components/strength_meter.py — Visual password strength meter widget.

Usage::

    meter = StrengthMeter(parent)
    meter.grid(...)
    meter.update("MyP@ssw0rd!")
"""
from __future__ import annotations

import customtkinter as ctk

from ui.theme import (
    BG_SURFACE, FONT_CAPTION, PAD_SM, PAD_XS, RADIUS_SM,
    TEXT_MUTED, TEXT_SECONDARY,
)
from utils.password_strength import score_password

# Number of segments in the bar
_SEGMENTS = 5


class StrengthMeter(ctk.CTkFrame):
    """
    A horizontal row of coloured segments with a text label showing
    password strength as the user types.
    """

    def __init__(self, parent: ctk.CTkBaseClass, **kwargs) -> None:
        kwargs.setdefault("fg_color", "transparent")
        kwargs.setdefault("corner_radius", 0)
        super().__init__(parent, **kwargs)

        self._score: int = 0

        self.grid_columnconfigure(0, weight=1)
        self._build()

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self) -> None:
        # Segment bar row
        bar_frame = ctk.CTkFrame(self, fg_color="transparent")
        bar_frame.grid(row=0, column=0, sticky="ew")
        for i in range(_SEGMENTS):
            bar_frame.grid_columnconfigure(i, weight=1)

        self._segments: list[ctk.CTkFrame] = []
        for i in range(_SEGMENTS):
            seg = ctk.CTkFrame(
                bar_frame,
                height=5,
                corner_radius=RADIUS_SM,
                fg_color=self._segment_colour(i, 0, "#2a2f45"),
            )
            seg.grid(row=0, column=i, padx=(0, 3) if i < _SEGMENTS - 1 else 0, sticky="ew")
            self._segments.append(seg)

        # Label row
        self._label = ctk.CTkLabel(
            self,
            text="",
            font=FONT_CAPTION,
            text_color=TEXT_MUTED,
            anchor="w",
        )
        self._label.grid(row=1, column=0, sticky="w", pady=(PAD_XS, 0))

    # ── Public API ────────────────────────────────────────────────────────────

    def update(self, password: str) -> None:
        """Recompute and redraw the meter for *password*."""
        score, label, colour = score_password(password)
        self._score = score

        dim_colour = "#2a2f45"
        for i, seg in enumerate(self._segments):
            seg.configure(fg_color=colour if i <= score else dim_colour)

        self._label.configure(
            text=label if password else "",
            text_color=colour if password else TEXT_MUTED,
        )

    # ── Internal ──────────────────────────────────────────────────────────────

    @staticmethod
    def _segment_colour(index: int, score: int, dim: str) -> str:
        return dim
