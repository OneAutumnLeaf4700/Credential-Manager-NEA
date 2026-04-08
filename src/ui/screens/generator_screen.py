"""
ui/screens/generator_screen.py — Password generator panel.

Configurable options: length (8–64), character sets (uppercase, lowercase,
digits, symbols), exclude-ambiguous toggle.  Generated password is shown in
a large read-only field with copy and regenerate buttons.
"""
from __future__ import annotations

import secrets
import string

import customtkinter as ctk

from ui.components.strength_meter import StrengthMeter
from ui.theme import (
    ACCENT, BG_CARD, BG_INPUT, BG_PRIMARY, BG_SURFACE, BORDER, FONT_BODY,
    FONT_CAPTION, FONT_DISPLAY, FONT_HEADING, FONT_MONO, FONT_SUBHEAD,
    PAD_LG, PAD_MD, PAD_SM, PAD_XL, PAD_XS, RADIUS_LG, RADIUS_MD,
    SUCCESS, TEXT_MUTED, TEXT_PRIMARY, TEXT_SECONDARY,
    ghost_btn_kw, input_kw, primary_btn_kw,
)
from utils.clipboard import copy_with_autoclean

# Characters that are easy to confuse (l/1/I, O/0, etc.)
_AMBIGUOUS = "lI1O0o"


class GeneratorScreen(ctk.CTkFrame):
    """
    Full-height generator panel.

    Args:
        parent:   The App content frame.
        settings: Mutable settings dict (reads clipboard_clear_secs).
    """

    def __init__(self, parent: ctk.CTkBaseClass, settings: dict) -> None:
        super().__init__(parent, fg_color=BG_PRIMARY, corner_radius=0)
        self._settings = settings

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self._upper_var = ctk.BooleanVar(value=True)
        self._lower_var = ctk.BooleanVar(value=True)
        self._digit_var = ctk.BooleanVar(value=True)
        self._symbol_var = ctk.BooleanVar(value=True)
        self._ambig_var = ctk.BooleanVar(value=False)
        self._length_var = ctk.IntVar(value=20)

        self._build()
        self._generate()

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self) -> None:
        # Page header
        hdr = ctk.CTkFrame(self, fg_color=BG_SURFACE, corner_radius=0, height=70)
        hdr.grid(row=0, column=0, sticky="ew")
        hdr.grid_propagate(False)
        ctk.CTkLabel(
            hdr, text="Generator", font=FONT_DISPLAY, text_color=TEXT_PRIMARY,
        ).grid(row=0, column=0, sticky="w", padx=PAD_LG, pady=PAD_MD)

        # Centred content
        scroll = ctk.CTkScrollableFrame(
            self, fg_color=BG_PRIMARY, scrollbar_fg_color=BG_PRIMARY,
        )
        scroll.grid(row=1, column=0, sticky="nsew")
        scroll.grid_columnconfigure(0, weight=1)

        content = ctk.CTkFrame(scroll, fg_color="transparent")
        content.grid(row=0, column=0, sticky="ew", padx=PAD_XL, pady=PAD_XL)
        content.grid_columnconfigure(0, weight=1)

        self._build_output(content)
        self._build_length(content)
        self._build_options(content)
        self._build_actions(content)

    def _build_output(self, parent: ctk.CTkFrame) -> None:
        """Generated password display + copy / regenerate."""
        card = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=RADIUS_LG)
        card.grid(row=0, column=0, sticky="ew", pady=(0, PAD_LG))
        card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            card, text="Generated Password",
            font=FONT_SUBHEAD, text_color=TEXT_SECONDARY, anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=PAD_LG, pady=(PAD_LG, PAD_SM))

        # Password display field (read-only)
        self._pw_var = ctk.StringVar()
        pw_row = ctk.CTkFrame(card, fg_color="transparent")
        pw_row.grid(row=1, column=0, sticky="ew", padx=PAD_LG, pady=(0, PAD_SM))
        pw_row.grid_columnconfigure(0, weight=1)

        self._pw_display = ctk.CTkEntry(
            pw_row, textvariable=self._pw_var,
            state="readonly", height=48,
            font=FONT_MONO,
            fg_color=BG_INPUT, text_color=TEXT_PRIMARY,
            border_color=BORDER, border_width=1,
            corner_radius=RADIUS_MD,
        )
        self._pw_display.grid(row=0, column=0, sticky="ew", padx=(0, PAD_XS))

        # Regenerate
        ctk.CTkButton(
            pw_row, text="↻", width=48, height=48,
            **ghost_btn_kw(font=FONT_HEADING),
            command=self._generate,
        ).grid(row=0, column=1, padx=(0, PAD_XS))

        # Copy
        self._copy_btn = ctk.CTkButton(
            pw_row, text="Copy", width=80, height=48,
            **primary_btn_kw(),
            command=self._copy,
        )
        self._copy_btn.grid(row=0, column=2)

        # Strength meter
        self._meter = StrengthMeter(card)
        self._meter.grid(row=2, column=0, sticky="ew", padx=PAD_LG, pady=(0, PAD_LG))

    def _build_length(self, parent: ctk.CTkFrame) -> None:
        """Length slider."""
        card = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=RADIUS_LG)
        card.grid(row=1, column=0, sticky="ew", pady=(0, PAD_LG))
        card.grid_columnconfigure(0, weight=1)

        label_row = ctk.CTkFrame(card, fg_color="transparent")
        label_row.grid(row=0, column=0, sticky="ew", padx=PAD_LG, pady=(PAD_LG, PAD_SM))
        label_row.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            label_row, text="Password Length",
            font=FONT_SUBHEAD, text_color=TEXT_SECONDARY, anchor="w",
        ).grid(row=0, column=0, sticky="w")

        self._len_label = ctk.CTkLabel(
            label_row, text="20",
            font=FONT_HEADING, text_color=TEXT_PRIMARY,
        )
        self._len_label.grid(row=0, column=1)

        self._slider = ctk.CTkSlider(
            card,
            from_=8, to=64,
            number_of_steps=56,
            variable=self._length_var,
            fg_color=BG_INPUT,
            progress_color=ACCENT,
            button_color=ACCENT,
            button_hover_color=ACCENT,
            command=self._on_length_change,
        )
        self._slider.grid(row=1, column=0, sticky="ew", padx=PAD_LG, pady=(0, PAD_LG))

    def _build_options(self, parent: ctk.CTkFrame) -> None:
        """Character set checkboxes."""
        card = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=RADIUS_LG)
        card.grid(row=2, column=0, sticky="ew", pady=(0, PAD_LG))
        card.grid_columnconfigure((0, 1), weight=1)

        ctk.CTkLabel(
            card, text="Character Sets",
            font=FONT_SUBHEAD, text_color=TEXT_SECONDARY, anchor="w",
        ).grid(row=0, column=0, columnspan=2, sticky="w", padx=PAD_LG, pady=(PAD_LG, PAD_SM))

        checkboxes = [
            (self._upper_var, "Uppercase (A–Z)", 1, 0),
            (self._lower_var, "Lowercase (a–z)", 1, 1),
            (self._digit_var, "Numbers (0–9)", 2, 0),
            (self._symbol_var, "Symbols (!@#$…)", 2, 1),
        ]

        cb_kw = dict(
            font=FONT_BODY, text_color=TEXT_PRIMARY,
            fg_color=ACCENT, hover_color=ACCENT,
            checkmark_color="white",
        )
        for var, text, row, col in checkboxes:
            ctk.CTkCheckBox(
                card, text=text, variable=var,
                command=self._generate, **cb_kw,
            ).grid(row=row, column=col, sticky="w", padx=PAD_LG, pady=PAD_SM)

        # Exclude ambiguous
        ctk.CTkCheckBox(
            card, text="Exclude ambiguous characters (l, 1, I, O, 0…)",
            variable=self._ambig_var,
            command=self._generate, **cb_kw,
        ).grid(row=3, column=0, columnspan=2, sticky="w", padx=PAD_LG, pady=(PAD_SM, PAD_LG))

    def _build_actions(self, parent: ctk.CTkFrame) -> None:
        """Generate button."""
        ctk.CTkButton(
            parent, text="Generate New Password", height=46,
            **primary_btn_kw(), command=self._generate,
        ).grid(row=3, column=0, sticky="ew", pady=(0, PAD_LG))

    # ── Logic ─────────────────────────────────────────────────────────────────

    def _on_length_change(self, value: float) -> None:
        length = int(value)
        self._len_label.configure(text=str(length))
        self._generate()

    def _build_alphabet(self) -> str:
        parts: list[str] = []
        if self._upper_var.get():
            parts.append(string.ascii_uppercase)
        if self._lower_var.get():
            parts.append(string.ascii_lowercase)
        if self._digit_var.get():
            parts.append(string.digits)
        if self._symbol_var.get():
            parts.append("!@#$%^&*()_+-=[]{}|;:,.<>?")
        alphabet = "".join(parts)
        if self._ambig_var.get():
            alphabet = "".join(c for c in alphabet if c not in _AMBIGUOUS)
        return alphabet

    def _generate(self) -> None:
        alphabet = self._build_alphabet()
        if not alphabet:
            self._pw_var.set("Select at least one character set")
            self._meter.update("")
            return

        length = int(self._length_var.get())
        # Guarantee at least one character from each selected set
        guaranteed: list[str] = []
        if self._upper_var.get():
            pool = [c for c in string.ascii_uppercase if c not in _AMBIGUOUS or not self._ambig_var.get()]
            if pool:
                guaranteed.append(secrets.choice(pool))
        if self._lower_var.get():
            pool = [c for c in string.ascii_lowercase if c not in _AMBIGUOUS or not self._ambig_var.get()]
            if pool:
                guaranteed.append(secrets.choice(pool))
        if self._digit_var.get():
            pool = [c for c in string.digits if c not in _AMBIGUOUS or not self._ambig_var.get()]
            if pool:
                guaranteed.append(secrets.choice(pool))
        if self._symbol_var.get():
            guaranteed.append(secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?"))

        remaining = length - len(guaranteed)
        rest = [secrets.choice(alphabet) for _ in range(max(0, remaining))]
        combined = guaranteed + rest
        secrets.SystemRandom().shuffle(combined)
        password = "".join(combined)

        self._pw_var.set(password)
        self._meter.update(password)

    def _copy(self) -> None:
        password = self._pw_var.get()
        if not password or "Select at least" in password:
            return
        clear_secs = self._settings.get("clipboard_clear_secs", 30)
        copy_with_autoclean(password, clear_secs)
        self._copy_btn.configure(text="✓ Copied!")
        self._copy_btn.after(1500, lambda: self._copy_btn.configure(text="Copy"))

    # ── Lifecycle hooks ───────────────────────────────────────────────────────

    def on_show(self) -> None:
        pass

    def on_settings_change(self, settings: dict) -> None:
        self._settings = settings
