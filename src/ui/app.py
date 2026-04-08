"""
ui/app.py — Root application window and navigation controller.

Single CTk() window that transitions between two modes:
  1. Auth mode  — small centered window showing login or first-run setup
  2. Vault mode — large window with sidebar + main content area

This avoids ever creating a second CTk() root window.
"""
from __future__ import annotations

from typing import Optional

import customtkinter as ctk

from database.db_manager import initialise
from services.auth_service import is_vault_initialised
from services.vault_service import VaultService
from ui.theme import (
    ACCENT, BG_PRIMARY, BG_SURFACE, FONT_BODY, FONT_CAPTION, FONT_SUBHEAD,
    PAD_LG, PAD_MD, PAD_SM, PAD_XS, RADIUS_MD, SIDEBAR_W,
    AUTH_W, AUTH_H, SETUP_H, VAULT_W, VAULT_H, MIN_W, MIN_H,
    TEXT_MUTED, TEXT_PRIMARY, TEXT_SECONDARY, HOVER_OVERLAY, ACTIVE_OVERLAY,
    apply_theme,
)


class App(ctk.CTk):
    """
    The single root window for the entire application.

    All screens are CTkFrames rendered inside this window.
    Navigation lifts the appropriate frame into view.
    """

    def __init__(self) -> None:
        super().__init__()
        apply_theme()
        initialise()

        self._vault_service: Optional[VaultService] = None
        self._screens: dict = {}
        self._active_nav: Optional[str] = None
        self._nav_buttons: dict[str, ctk.CTkFrame] = {}

        self.configure(fg_color=BG_PRIMARY)
        self.title("KeyVault")
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        if is_vault_initialised():
            self._show_auth("login")
        else:
            self._show_auth("setup")

    # ── Auth mode ─────────────────────────────────────────────────────────────

    def _show_auth(self, mode: str) -> None:
        """Switch to a small centered auth window, sized to fit its content."""
        self._clear_window()
        self.resizable(False, False)
        self.title("KeyVault — " + ("Unlock Vault" if mode == "login" else "Create Vault"))

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        from ui.screens.auth_screen import AuthScreen
        auth = AuthScreen(self, mode=mode, on_success=self._on_auth_success)
        auth.grid(row=0, column=0, sticky="nsew")

        # Let Tk calculate the natural size of the content, then center on that.
        self.update_idletasks()
        w = max(self.winfo_reqwidth(), AUTH_W)
        h = max(self.winfo_reqheight(), AUTH_H if mode == "login" else SETUP_H)
        self._center(w, h)

    def _on_auth_success(self, fernet_key: bytes) -> None:
        """Callback fired after successful login or vault creation."""
        self._vault_service = VaultService(fernet_key)
        settings = self._vault_service.get_settings()
        self._show_vault(settings)

    # ── Vault mode ────────────────────────────────────────────────────────────

    def _show_vault(self, settings: dict) -> None:
        """Switch to the full-size vault window with sidebar."""
        self._clear_window()
        self.resizable(True, True)
        self.minsize(MIN_W, MIN_H)
        self._center(VAULT_W, VAULT_H)
        self.title("KeyVault")

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_content(settings)
        self._navigate("vault")

    def _build_sidebar(self) -> None:
        sidebar = ctk.CTkFrame(
            self, width=SIDEBAR_W, fg_color=BG_SURFACE, corner_radius=0,
        )
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)
        sidebar.grid_columnconfigure(0, weight=1)
        sidebar.grid_rowconfigure(2, weight=1)  # Spacer pushes lock to bottom

        # ── Logo ──────────────────────────────────────────────────────────────
        logo_frame = ctk.CTkFrame(sidebar, fg_color="transparent", height=70)
        logo_frame.grid(row=0, column=0, sticky="ew")
        logo_frame.grid_propagate(False)
        logo_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            logo_frame, text="🔐  KeyVault",
            font=FONT_SUBHEAD, text_color=TEXT_PRIMARY, anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=PAD_LG, pady=PAD_MD)

        # Divider
        ctk.CTkFrame(sidebar, height=1, fg_color="#2a2f45").grid(
            row=1, column=0, sticky="ew", padx=PAD_LG,
        )

        # ── Nav items ─────────────────────────────────────────────────────────
        nav_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        nav_frame.grid(row=2, column=0, sticky="nsew", pady=PAD_MD)
        nav_frame.grid_columnconfigure(0, weight=1)

        nav_items = [
            ("vault",     "🏦  Vault"),
            ("generator", "⚡  Generator"),
            ("settings",  "⚙️  Settings"),
        ]
        for i, (key, label) in enumerate(nav_items):
            btn_frame = ctk.CTkFrame(nav_frame, fg_color="transparent", corner_radius=RADIUS_MD)
            btn_frame.grid(row=i, column=0, sticky="ew", padx=PAD_SM, pady=PAD_XS)
            btn_frame.grid_columnconfigure(1, weight=1)

            # Active indicator bar (3px left stripe)
            indicator = ctk.CTkFrame(btn_frame, width=3, fg_color="transparent", corner_radius=2)
            indicator.grid(row=0, column=0, sticky="ns", padx=(PAD_XS, 0), pady=PAD_XS)

            btn = ctk.CTkButton(
                btn_frame, text=label,
                fg_color="transparent",
                hover_color=HOVER_OVERLAY,
                text_color=TEXT_SECONDARY,
                anchor="w",
                font=FONT_BODY,
                corner_radius=RADIUS_MD,
                height=40,
                command=lambda k=key: self._navigate(k),
            )
            btn.grid(row=0, column=1, sticky="ew", pady=PAD_XS, padx=(0, PAD_XS))

            self._nav_buttons[key] = (btn_frame, indicator, btn)

        # ── Spacer ────────────────────────────────────────────────────────────
        ctk.CTkFrame(nav_frame, fg_color="transparent").grid(row=len(nav_items), column=0)

        # ── Bottom — lock button ──────────────────────────────────────────────
        ctk.CTkFrame(sidebar, height=1, fg_color="#2a2f45").grid(
            row=3, column=0, sticky="ew", padx=PAD_LG,
        )
        ctk.CTkButton(
            sidebar,
            text="🔒  Lock Vault",
            fg_color="transparent",
            hover_color=HOVER_OVERLAY,
            text_color=TEXT_MUTED,
            anchor="w",
            font=FONT_BODY,
            corner_radius=RADIUS_MD,
            height=46,
            command=self._lock_vault,
        ).grid(row=4, column=0, sticky="ew", padx=PAD_SM, pady=PAD_MD)

    def _build_content(self, settings: dict) -> None:
        content = ctk.CTkFrame(self, fg_color=BG_PRIMARY, corner_radius=0)
        content.grid(row=0, column=1, sticky="nsew")
        content.grid_columnconfigure(0, weight=1)
        content.grid_rowconfigure(0, weight=1)

        from ui.screens.vault_screen import VaultScreen
        from ui.screens.generator_screen import GeneratorScreen
        from ui.screens.settings_screen import SettingsScreen

        self._screens = {
            "vault": VaultScreen(content, self._vault_service, settings),
            "generator": GeneratorScreen(content, settings),
            "settings": SettingsScreen(
                content, self._vault_service, settings,
                on_settings_change=self._on_settings_change,
            ),
        }

        for screen in self._screens.values():
            screen.grid(row=0, column=0, sticky="nsew")

    # ── Navigation ────────────────────────────────────────────────────────────

    def _navigate(self, section: str) -> None:
        if section not in self._screens:
            return

        self._active_nav = section
        self._screens[section].lift()
        self._screens[section].on_show()

        for key, (frame, indicator, btn) in self._nav_buttons.items():
            if key == section:
                indicator.configure(fg_color=ACCENT)
                btn.configure(text_color=TEXT_PRIMARY, fg_color=ACTIVE_OVERLAY)
            else:
                indicator.configure(fg_color="transparent")
                btn.configure(text_color=TEXT_SECONDARY, fg_color="transparent")

    # ── Settings propagation ──────────────────────────────────────────────────

    def _on_settings_change(self, settings: dict) -> None:
        for screen in self._screens.values():
            screen.on_settings_change(settings)

    # ── Lock / close ─────────────────────────────────────────────────────────

    def _lock_vault(self) -> None:
        self._vault_service = None
        self._screens = {}
        self._nav_buttons = {}
        self._show_auth("login")

    def _on_close(self) -> None:
        self.destroy()

    # ── Utilities ─────────────────────────────────────────────────────────────

    def _clear_window(self) -> None:
        for widget in self.winfo_children():
            widget.destroy()
        # Reset grid configuration
        for i in range(4):
            self.grid_columnconfigure(i, weight=0)
            self.grid_rowconfigure(i, weight=0)

    def _center(self, w: int, h: int) -> None:
        self.update_idletasks()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x = (sw - w) // 2
        y = (sh - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")
