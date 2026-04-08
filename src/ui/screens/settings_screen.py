"""
ui/screens/settings_screen.py — Application settings panel.

Sections:
  • Security   — clipboard auto-clear timer, change master password
  • About       — app name, version, disclaimer
"""
from __future__ import annotations

from typing import Callable, Optional

import customtkinter as ctk

from services.auth_service import AuthError, change_master_password
from services.vault_service import VaultService
from ui.components.strength_meter import StrengthMeter
from ui.theme import (
    ACCENT, BG_CARD, BG_INPUT, BG_PRIMARY, BG_SURFACE, BORDER, DANGER,
    FONT_BODY, FONT_CAPTION, FONT_DISPLAY, FONT_HEADING, FONT_SUBHEAD,
    PAD_LG, PAD_MD, PAD_SM, PAD_XL, PAD_XS, RADIUS_LG, RADIUS_MD,
    SUCCESS, TEXT_MUTED, TEXT_PRIMARY, TEXT_SECONDARY,
    danger_btn_kw, ghost_btn_kw, input_kw, primary_btn_kw,
)

_VERSION = "2.0.0"
_CLEAR_OPTIONS = [
    ("15 seconds",  15),
    ("30 seconds",  30),
    ("60 seconds",  60),
    ("2 minutes",  120),
    ("Never",        0),
]


class SettingsScreen(ctk.CTkFrame):
    """
    Full-height settings panel.

    Args:
        parent:             App content frame.
        vault_service:      Active VaultService.
        settings:           Mutable settings dict (shared reference).
        on_settings_change: Called with new settings dict after save.
    """

    def __init__(
        self,
        parent: ctk.CTkBaseClass,
        vault_service: VaultService,
        settings: dict,
        on_settings_change: Optional[Callable[[dict], None]] = None,
    ) -> None:
        super().__init__(parent, fg_color=BG_PRIMARY, corner_radius=0)
        self._service = vault_service
        self._settings = settings
        self._on_change = on_settings_change

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self._build()

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self) -> None:
        # Header
        hdr = ctk.CTkFrame(self, fg_color=BG_SURFACE, corner_radius=0, height=70)
        hdr.grid(row=0, column=0, sticky="ew")
        hdr.grid_propagate(False)
        ctk.CTkLabel(
            hdr, text="Settings", font=FONT_DISPLAY, text_color=TEXT_PRIMARY,
        ).grid(row=0, column=0, sticky="w", padx=PAD_LG, pady=PAD_MD)

        # Scrollable body
        scroll = ctk.CTkScrollableFrame(
            self, fg_color=BG_PRIMARY, scrollbar_fg_color=BG_PRIMARY,
        )
        scroll.grid(row=1, column=0, sticky="nsew")
        scroll.grid_columnconfigure(0, weight=1)

        content = ctk.CTkFrame(scroll, fg_color="transparent")
        content.grid(row=0, column=0, sticky="ew", padx=PAD_XL, pady=PAD_XL)
        content.grid_columnconfigure(0, weight=1)

        self._build_security(content)
        self._build_change_password(content)
        self._build_about(content)

    # ── Security section ──────────────────────────────────────────────────────

    def _build_security(self, parent: ctk.CTkFrame) -> None:
        card = self._section_card(parent, 0, "🔒  Security")

        # Clipboard auto-clear
        row = ctk.CTkFrame(card, fg_color="transparent")
        row.grid(row=2, column=0, sticky="ew", padx=PAD_LG, pady=(0, PAD_LG))
        row.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            row, text="Clipboard auto-clear",
            font=FONT_SUBHEAD, text_color=TEXT_PRIMARY, anchor="w",
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            row,
            text="Automatically overwrites the clipboard after copying a password.",
            font=FONT_CAPTION, text_color=TEXT_MUTED, anchor="w",
        ).grid(row=1, column=0, sticky="w", pady=(PAD_XS, PAD_SM))

        current_secs = self._settings.get("clipboard_clear_secs", 30)
        current_label = next(
            (label for label, secs in _CLEAR_OPTIONS if secs == current_secs),
            "30 seconds",
        )
        self._clear_var = ctk.StringVar(value=current_label)

        ctk.CTkOptionMenu(
            row,
            values=[label for label, _ in _CLEAR_OPTIONS],
            variable=self._clear_var,
            fg_color=BG_INPUT,
            button_color=ACCENT,
            button_hover_color=ACCENT,
            dropdown_fg_color=BG_SURFACE,
            text_color=TEXT_PRIMARY,
            font=FONT_BODY,
            height=38,
            corner_radius=RADIUS_MD,
        ).grid(row=2, column=0, sticky="w")

        self._sec_status = ctk.CTkLabel(
            card, text="", font=FONT_CAPTION, text_color=SUCCESS,
        )
        self._sec_status.grid(row=3, column=0, sticky="w", padx=PAD_LG)

        ctk.CTkButton(
            card, text="Save Settings", width=140, height=38,
            **primary_btn_kw(), command=self._save_settings,
        ).grid(row=4, column=0, sticky="w", padx=PAD_LG, pady=(PAD_SM, PAD_LG))

    # ── Change master password section ────────────────────────────────────────

    def _build_change_password(self, parent: ctk.CTkFrame) -> None:
        card = self._section_card(parent, 1, "🔑  Change Master Password")

        def _entry(placeholder: str, row: int) -> ctk.CTkEntry:
            e = ctk.CTkEntry(
                card, placeholder_text=placeholder,
                show="•", height=40, **input_kw(),
            )
            e.grid(row=row, column=0, sticky="ew", padx=PAD_LG, pady=(0, PAD_SM))
            return e

        # Content starts at row=2 (row=0 title, row=1 divider from _section_card)
        ctk.CTkLabel(
            card, text="Current password",
            font=FONT_CAPTION, text_color=TEXT_MUTED, anchor="w",
        ).grid(row=2, column=0, sticky="w", padx=PAD_LG, pady=(0, PAD_XS))
        self._old_pw = _entry("Enter current master password", 3)

        ctk.CTkLabel(
            card, text="New password",
            font=FONT_CAPTION, text_color=TEXT_MUTED, anchor="w",
        ).grid(row=4, column=0, sticky="w", padx=PAD_LG, pady=(0, PAD_XS))
        self._new_pw = _entry("Enter new master password", 5)

        # Strength meter for new password
        self._pw_meter = StrengthMeter(card)
        self._pw_meter.grid(row=6, column=0, sticky="ew", padx=PAD_LG, pady=(0, PAD_SM))
        self._new_pw.bind("<KeyRelease>", lambda _: self._pw_meter.update(self._new_pw.get()))

        ctk.CTkLabel(
            card, text="Confirm new password",
            font=FONT_CAPTION, text_color=TEXT_MUTED, anchor="w",
        ).grid(row=7, column=0, sticky="w", padx=PAD_LG, pady=(0, PAD_XS))
        self._confirm_pw = _entry("Confirm new master password", 8)

        self._pw_status = ctk.CTkLabel(
            card, text="", font=FONT_CAPTION, text_color=DANGER, wraplength=400,
        )
        self._pw_status.grid(row=9, column=0, padx=PAD_LG, pady=(0, PAD_SM))

        ctk.CTkButton(
            card, text="Change Password", width=160, height=38,
            **primary_btn_kw(), command=self._change_password,
        ).grid(row=10, column=0, sticky="w", padx=PAD_LG, pady=(0, PAD_LG))

    # ── About section ─────────────────────────────────────────────────────────

    def _build_about(self, parent: ctk.CTkFrame) -> None:
        card = self._section_card(parent, 2, "ℹ️  About")

        lines = [
            (f"KeyVault v{_VERSION}", FONT_HEADING, TEXT_PRIMARY),
            ("A-Level Computer Science NEA Project", FONT_BODY, TEXT_SECONDARY),
            ("", FONT_BODY, TEXT_MUTED),
            (
                "⚠  This is an educational project. Do not store production "
                "credentials. No warranty is provided.",
                FONT_CAPTION, TEXT_MUTED,
            ),
        ]
        # Content starts at row=2 (row=0 title, row=1 divider from _section_card)
        for i, (text, font, colour) in enumerate(lines):
            ctk.CTkLabel(
                card, text=text, font=font, text_color=colour,
                anchor="w", wraplength=500, justify="left",
            ).grid(row=i + 2, column=0, sticky="w", padx=PAD_LG,
                   pady=(PAD_SM if i == 0 else 0, PAD_SM if i == len(lines) - 1 else 0))

        # Padding at bottom
        ctk.CTkLabel(card, text="").grid(row=len(lines) + 2, column=0)

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _section_card(parent: ctk.CTkFrame, row: int, title: str) -> ctk.CTkFrame:
        """Create and return a titled card frame. Content starts at row=1."""
        card = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=RADIUS_LG)
        card.grid(row=row, column=0, sticky="ew", pady=(0, PAD_LG))
        card.grid_columnconfigure(0, weight=1)

        # Row 0: section title
        ctk.CTkLabel(
            card, text=title, font=FONT_HEADING, text_color=TEXT_PRIMARY, anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=PAD_LG, pady=(PAD_LG, PAD_XS))

        # Row 1: thin divider line
        ctk.CTkFrame(card, height=1, fg_color=BORDER).grid(
            row=1, column=0, sticky="ew", padx=PAD_LG, pady=(0, PAD_SM),
        )
        return card

    # ── Actions ───────────────────────────────────────────────────────────────

    def _save_settings(self) -> None:
        label = self._clear_var.get()
        secs = next((s for l, s in _CLEAR_OPTIONS if l == label), 30)
        self._settings["clipboard_clear_secs"] = secs
        self._service.save_settings(self._settings)
        if self._on_change:
            self._on_change(self._settings)
        self._sec_status.configure(text="✓ Settings saved.", text_color=SUCCESS)
        self.after(2500, lambda: self._sec_status.configure(text=""))

    def _change_password(self) -> None:
        old = self._old_pw.get()
        new = self._new_pw.get()
        confirm = self._confirm_pw.get()

        if not old or not new or not confirm:
            self._pw_status.configure(text="All fields are required.", text_color=DANGER)
            return
        if new != confirm:
            self._pw_status.configure(text="New passwords do not match.", text_color=DANGER)
            return
        if len(new) < 8:
            self._pw_status.configure(text="New password must be at least 8 characters.", text_color=DANGER)
            return

        self._pw_status.configure(text="Updating…", text_color=TEXT_MUTED)
        self.update_idletasks()

        try:
            # We need the current Fernet key — retrieve it by verifying old password
            from services.auth_service import verify_master_password
            fernet_key = verify_master_password(old)
            change_master_password(old, new, fernet_key)
        except AuthError as exc:
            self._pw_status.configure(text=str(exc), text_color=DANGER)
            return
        except Exception as exc:
            self._pw_status.configure(text=f"Error: {exc}", text_color=DANGER)
            return

        self._pw_status.configure(text="✓ Master password changed successfully.", text_color=SUCCESS)
        self._old_pw.delete(0, "end")
        self._new_pw.delete(0, "end")
        self._confirm_pw.delete(0, "end")
        self._pw_meter.update("")
        self.after(3000, lambda: self._pw_status.configure(text=""))

    # ── Lifecycle hooks ───────────────────────────────────────────────────────

    def on_show(self) -> None:
        pass

    def on_settings_change(self, settings: dict) -> None:
        self._settings = settings
