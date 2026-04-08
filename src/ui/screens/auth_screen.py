"""
ui/screens/auth_screen.py — Login and first-run setup screens.

Both screens live inside the same CTkFrame so the single App window can
switch between them without any geometry changes.  The frame calls the
supplied callback on successful authentication.
"""
from __future__ import annotations

import re
from typing import Callable

import customtkinter as ctk

from services.auth_service import AuthError, create_master_password, verify_master_password
from ui.components.strength_meter import StrengthMeter
from ui.theme import (
    ACCENT, BG_PRIMARY, BG_SURFACE, BORDER, DANGER, FONT_BODY,
    FONT_CAPTION, FONT_DISPLAY, FONT_HEADING, FONT_SUBHEAD,
    PAD_LG, PAD_MD, PAD_SM, PAD_XL, PAD_XS, RADIUS_LG, RADIUS_MD,
    SUCCESS, TEXT_MUTED, TEXT_PRIMARY, TEXT_SECONDARY,
    input_kw, primary_btn_kw,
)

# Minimum master password requirements
_MIN_LENGTH = 8


class AuthScreen(ctk.CTkFrame):
    """
    Handles two modes via internal sub-frames:
      - 'login'  — vault exists, user enters master password
      - 'setup'  — first run, user creates master password

    Args:
        parent:      Parent widget (the App window).
        mode:        "login" or "setup".
        on_success:  Callback receiving the Fernet key bytes after auth.
    """

    def __init__(
        self,
        parent: ctk.CTkBaseClass,
        mode: str,
        on_success: Callable[[bytes], None],
    ) -> None:
        super().__init__(parent, fg_color=BG_PRIMARY, corner_radius=0)
        self._on_success = on_success
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        if mode == "login":
            self._build_login()
        else:
            self._build_setup()

    # ── Login ─────────────────────────────────────────────────────────────────

    def _build_login(self) -> None:
        card = self._centered_card()

        # Logo / icon
        ctk.CTkLabel(card, text="🔐", font=(None, 52)).grid(
            row=0, column=0, pady=(PAD_XL, PAD_MD)
        )

        ctk.CTkLabel(
            card, text="KeyVault", font=FONT_DISPLAY, text_color=TEXT_PRIMARY,
        ).grid(row=1, column=0, pady=(0, PAD_XS))

        ctk.CTkLabel(
            card,
            text="Your vault is locked. Enter your master password to continue.",
            font=FONT_BODY, text_color=TEXT_SECONDARY, wraplength=340,
        ).grid(row=2, column=0, pady=(0, PAD_LG))

        # Password entry row
        pw_frame = ctk.CTkFrame(card, fg_color="transparent")
        pw_frame.grid(row=3, column=0, sticky="ew", padx=PAD_MD, pady=(0, PAD_XS))
        pw_frame.grid_columnconfigure(0, weight=1)

        self._login_pw = ctk.CTkEntry(
            pw_frame, placeholder_text="Master password",
            show="•", height=44, **input_kw(),
        )
        self._login_pw.grid(row=0, column=0, sticky="ew", padx=(0, PAD_XS))

        show_btn = ctk.CTkButton(
            pw_frame, text="👁", width=44, height=44,
            fg_color=BG_SURFACE, hover_color=ACCENT,
            text_color=TEXT_SECONDARY, corner_radius=RADIUS_MD,
            font=FONT_BODY, command=lambda: self._toggle_show(self._login_pw, show_btn),
        )
        show_btn.grid(row=0, column=1)

        self._login_status = ctk.CTkLabel(
            card, text="", font=FONT_CAPTION, text_color=DANGER,
        )
        self._login_status.grid(row=4, column=0, pady=(0, PAD_MD))

        unlock_btn = ctk.CTkButton(
            card, text="Unlock Vault", height=46,
            **primary_btn_kw(), command=self._do_login,
        )
        unlock_btn.grid(row=5, column=0, sticky="ew", padx=PAD_MD, pady=(0, PAD_XL))

        self._login_pw.bind("<Return>", lambda _: self._do_login())
        self._login_pw.focus_set()

    def _do_login(self) -> None:
        password = self._login_pw.get()
        if not password:
            self._login_status.configure(text="Please enter your master password.")
            return

        self._login_status.configure(text="Verifying…", text_color=TEXT_MUTED)
        self.update_idletasks()

        try:
            fernet_key = verify_master_password(password)
        except AuthError as exc:
            self._login_status.configure(text=str(exc), text_color=DANGER)
            self._login_pw.delete(0, "end")
            return

        self._on_success(fernet_key)

    # ── Setup ─────────────────────────────────────────────────────────────────

    def _build_setup(self) -> None:
        card = self._centered_card()

        ctk.CTkLabel(card, text="🔑", font=(None, 48)).grid(
            row=0, column=0, pady=(PAD_LG, PAD_SM)
        )

        ctk.CTkLabel(
            card, text="Create Your Vault",
            font=FONT_DISPLAY, text_color=TEXT_PRIMARY,
        ).grid(row=1, column=0, pady=(0, PAD_XS))

        ctk.CTkLabel(
            card,
            text="Choose a strong master password to protect your credentials.\nYou cannot recover it if forgotten.",
            font=FONT_BODY, text_color=TEXT_SECONDARY, wraplength=340, justify="center",
        ).grid(row=2, column=0, pady=(0, PAD_MD))

        # Requirements hint
        req_frame = ctk.CTkFrame(card, fg_color=BG_SURFACE, corner_radius=RADIUS_MD)
        req_frame.grid(row=3, column=0, sticky="ew", padx=PAD_MD, pady=(0, PAD_MD))
        ctk.CTkLabel(
            req_frame,
            text="  ≥ 8 characters  ·  1 uppercase  ·  1 number  ·  1 symbol",
            font=FONT_CAPTION, text_color=TEXT_MUTED,
        ).grid(padx=PAD_MD, pady=PAD_SM)

        # Password entry
        pw_frame = ctk.CTkFrame(card, fg_color="transparent")
        pw_frame.grid(row=4, column=0, sticky="ew", padx=PAD_MD, pady=(0, PAD_XS))
        pw_frame.grid_columnconfigure(0, weight=1)

        self._setup_pw = ctk.CTkEntry(
            pw_frame, placeholder_text="Master password",
            show="•", height=44, **input_kw(),
        )
        self._setup_pw.grid(row=0, column=0, sticky="ew", padx=(0, PAD_XS))
        show_btn1 = ctk.CTkButton(
            pw_frame, text="👁", width=44, height=44,
            fg_color=BG_SURFACE, hover_color=ACCENT,
            text_color=TEXT_SECONDARY, corner_radius=RADIUS_MD, font=FONT_BODY,
            command=lambda: self._toggle_show(self._setup_pw, show_btn1),
        )
        show_btn1.grid(row=0, column=1)

        # Strength meter
        self._meter = StrengthMeter(card)
        self._meter.grid(row=5, column=0, sticky="ew", padx=PAD_MD, pady=(PAD_XS, PAD_SM))
        self._setup_pw.bind("<KeyRelease>", lambda _: self._meter.update(self._setup_pw.get()))

        # Confirm entry
        cf_frame = ctk.CTkFrame(card, fg_color="transparent")
        cf_frame.grid(row=6, column=0, sticky="ew", padx=PAD_MD, pady=(0, PAD_XS))
        cf_frame.grid_columnconfigure(0, weight=1)

        self._setup_cf = ctk.CTkEntry(
            cf_frame, placeholder_text="Confirm master password",
            show="•", height=44, **input_kw(),
        )
        self._setup_cf.grid(row=0, column=0, sticky="ew", padx=(0, PAD_XS))
        show_btn2 = ctk.CTkButton(
            cf_frame, text="👁", width=44, height=44,
            fg_color=BG_SURFACE, hover_color=ACCENT,
            text_color=TEXT_SECONDARY, corner_radius=RADIUS_MD, font=FONT_BODY,
            command=lambda: self._toggle_show(self._setup_cf, show_btn2),
        )
        show_btn2.grid(row=0, column=1)

        self._setup_status = ctk.CTkLabel(
            card, text="", font=FONT_CAPTION, text_color=DANGER, wraplength=340,
        )
        self._setup_status.grid(row=7, column=0, pady=(0, PAD_SM))

        ctk.CTkButton(
            card, text="Create Vault", height=46,
            **primary_btn_kw(), command=self._do_setup,
        ).grid(row=8, column=0, sticky="ew", padx=PAD_MD, pady=(0, PAD_XL))

        self._setup_pw.bind("<Return>", lambda _: self._setup_cf.focus_set())
        self._setup_cf.bind("<Return>", lambda _: self._do_setup())
        self._setup_pw.focus_set()

    def _do_setup(self) -> None:
        password = self._setup_pw.get()
        confirm = self._setup_cf.get()

        error = self._validate_new_password(password, confirm)
        if error:
            self._setup_status.configure(text=error, text_color=DANGER)
            return

        self._setup_status.configure(text="Creating vault…", text_color=TEXT_MUTED)
        self.update_idletasks()

        try:
            fernet_key = create_master_password(password)
        except Exception as exc:
            self._setup_status.configure(text=str(exc), text_color=DANGER)
            return

        self._setup_status.configure(text="Vault created!", text_color=SUCCESS)
        self.after(500, lambda: self._on_success(fernet_key))

    # ── Shared helpers ────────────────────────────────────────────────────────

    def _centered_card(self) -> ctk.CTkFrame:
        """Return a centered card frame placed in the grid."""
        outer = ctk.CTkFrame(self, fg_color="transparent")
        outer.grid(row=0, column=0)
        card = ctk.CTkFrame(
            outer, fg_color=BG_SURFACE,
            corner_radius=RADIUS_LG, width=400,
        )
        card.grid(row=0, column=0, padx=PAD_XL, pady=PAD_XL)
        card.grid_columnconfigure(0, weight=1)
        return card

    @staticmethod
    def _toggle_show(entry: ctk.CTkEntry, btn: ctk.CTkButton) -> None:
        if entry.cget("show") == "•":
            entry.configure(show="")
            btn.configure(text="🙈")
        else:
            entry.configure(show="•")
            btn.configure(text="👁")

    @staticmethod
    def _validate_new_password(password: str, confirm: str) -> str:
        """Return an error message string, or empty string if valid."""
        if not password:
            return "Password cannot be empty."
        if len(password) < _MIN_LENGTH:
            return f"Password must be at least {_MIN_LENGTH} characters."
        if not re.search(r"[A-Z]", password):
            return "Password must contain at least one uppercase letter."
        if not re.search(r"\d", password):
            return "Password must contain at least one digit."
        if not re.search(r"[^A-Za-z0-9]", password):
            return "Password must contain at least one special character."
        if password != confirm:
            return "Passwords do not match."
        return ""
