"""
ui/screens/vault_screen.py — Main vault view.

Displays a live-filtered, scrollable list of credential cards with a search
bar, category filter, and favourites toggle at the top.
"""
from __future__ import annotations

from typing import Optional

import customtkinter as ctk

from models.credential import Credential
from services.vault_service import VaultService
from ui.components.credential_card import CredentialCard
from ui.dialogs.credential_dialog import CredentialDialog
from ui.theme import (
    ACCENT, BG_CARD, BG_PRIMARY, BG_SURFACE, BORDER, FONT_BODY,
    FONT_CAPTION, FONT_DISPLAY, FONT_HEADING, FONT_SUBHEAD,
    PAD_LG, PAD_MD, PAD_SM, PAD_XL, PAD_XS, RADIUS_MD, RADIUS_LG,
    SUCCESS, TEXT_MUTED, TEXT_PRIMARY, TEXT_SECONDARY, WARNING,
    ghost_btn_kw, input_kw, primary_btn_kw,
)


class VaultScreen(ctk.CTkFrame):
    """
    Full-height frame that fills the main content area.

    Args:
        parent:        The App content frame.
        vault_service: Active VaultService for the session.
        settings:      Mutable settings dict (reads clipboard_clear_secs).
    """

    def __init__(
        self,
        parent: ctk.CTkBaseClass,
        vault_service: VaultService,
        settings: dict,
    ) -> None:
        super().__init__(parent, fg_color=BG_PRIMARY, corner_radius=0)
        self._service = vault_service
        self._settings = settings
        self._search_var = ctk.StringVar()
        self._category_var = ctk.StringVar(value="All")
        self._fav_only = False

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self._build_header()
        self._build_list_area()
        self._load()

    # ── Header ────────────────────────────────────────────────────────────────

    def _build_header(self) -> None:
        hdr = ctk.CTkFrame(self, fg_color=BG_SURFACE, corner_radius=0, height=70)
        hdr.grid(row=0, column=0, sticky="ew")
        hdr.grid_propagate(False)
        hdr.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            hdr, text="Vault", font=FONT_DISPLAY, text_color=TEXT_PRIMARY,
        ).grid(row=0, column=0, sticky="w", padx=PAD_LG, pady=PAD_MD)

        # Search bar
        search_frame = ctk.CTkFrame(hdr, fg_color="transparent")
        search_frame.grid(row=0, column=1, sticky="ew", padx=PAD_MD, pady=PAD_MD)
        search_frame.grid_columnconfigure(0, weight=1)

        self._search_entry = ctk.CTkEntry(
            search_frame,
            placeholder_text="Search credentials…",
            textvariable=self._search_var,
            height=38,
            **input_kw(),
        )
        self._search_entry.grid(row=0, column=0, sticky="ew")
        self._search_var.trace_add("write", lambda *_: self._load())

        # Add button
        ctk.CTkButton(
            hdr, text="+ Add", width=90, height=38,
            **primary_btn_kw(), command=self._open_add_dialog,
        ).grid(row=0, column=2, padx=(0, PAD_LG), pady=PAD_MD)

    # ── Filter bar ────────────────────────────────────────────────────────────

    def _build_list_area(self) -> None:
        outer = ctk.CTkFrame(self, fg_color=BG_PRIMARY, corner_radius=0)
        outer.grid(row=1, column=0, sticky="nsew")
        outer.grid_columnconfigure(0, weight=1)
        outer.grid_rowconfigure(1, weight=1)

        outer.grid_rowconfigure(2, weight=1)

        # ── Filter bar (row 0) ────────────────────────────────────────────────
        filter_bar = ctk.CTkFrame(outer, fg_color=BG_SURFACE, corner_radius=0, height=48)
        filter_bar.grid(row=0, column=0, sticky="ew")
        filter_bar.grid_propagate(False)
        filter_bar.grid_columnconfigure(2, weight=1)

        ctk.CTkLabel(
            filter_bar, text="Category:", font=FONT_BODY, text_color=TEXT_MUTED,
        ).grid(row=0, column=0, padx=(PAD_LG, PAD_SM), pady=PAD_SM)

        self._cat_menu = ctk.CTkOptionMenu(
            filter_bar,
            values=["All"],
            variable=self._category_var,
            fg_color=BG_CARD,
            button_color=ACCENT,
            button_hover_color=ACCENT,
            dropdown_fg_color=BG_SURFACE,
            text_color=TEXT_PRIMARY,
            font=FONT_BODY,
            height=32,
            corner_radius=RADIUS_MD,
            command=lambda _: self._load(),
        )
        self._cat_menu.grid(row=0, column=1, pady=PAD_SM)

        self._fav_btn = ctk.CTkButton(
            filter_bar, text="☆ Favourites", width=110, height=32,
            **ghost_btn_kw(text_color=TEXT_MUTED),
            command=self._toggle_favourites,
        )
        self._fav_btn.grid(row=0, column=3, padx=(0, PAD_SM), pady=PAD_SM)

        self._count_label = ctk.CTkLabel(
            filter_bar, text="", font=FONT_CAPTION, text_color=TEXT_MUTED,
        )
        self._count_label.grid(row=0, column=4, padx=(0, PAD_LG), pady=PAD_SM)

        # ── Column header bar (row 1) ─────────────────────────────────────────
        col_hdr = ctk.CTkFrame(outer, fg_color=BG_PRIMARY, corner_radius=0, height=32)
        col_hdr.grid(row=1, column=0, sticky="ew")
        col_hdr.grid_propagate(False)
        col_hdr.grid_columnconfigure(1, weight=1)
        col_hdr.grid_columnconfigure(2, weight=1)

        for col, text, padx in [
            (0, "   Service", (PAD_LG, 0)),
            (1, "Username", (64, 0)),
            (2, "Password / Actions", (0, PAD_LG)),
        ]:
            ctk.CTkLabel(
                col_hdr, text=text, font=FONT_CAPTION,
                text_color=TEXT_MUTED, anchor="w",
            ).grid(row=0, column=col, sticky="w", padx=padx, pady=PAD_XS)

        # ── Scrollable credential list (row 2, expands) ───────────────────────
        self._scroll = ctk.CTkScrollableFrame(
            outer, fg_color=BG_PRIMARY,
            scrollbar_fg_color=BG_PRIMARY,
        )
        self._scroll.grid(row=2, column=0, sticky="nsew", padx=PAD_LG, pady=(0, PAD_LG))
        self._scroll.grid_columnconfigure(0, weight=1)

    # ── Data loading ──────────────────────────────────────────────────────────

    def _load(self) -> None:
        """Clear the list and repopulate from the vault service."""
        for widget in self._scroll.winfo_children():
            widget.destroy()

        search = self._search_var.get().strip()
        category = self._category_var.get()
        credentials = self._service.get_all(
            search=search,
            category=category,
            favourites_only=self._fav_only,
        )

        # Refresh category menu
        cats = ["All"] + self._service.get_categories()
        self._cat_menu.configure(values=cats)

        n = len(credentials)
        self._count_label.configure(
            text=f"{n} item{'s' if n != 1 else ''}",
        )

        if not credentials:
            self._show_empty(search)
            return

        clear_secs = self._settings.get("clipboard_clear_secs", 30)
        for cred in credentials:
            card = CredentialCard(
                self._scroll,
                credential=cred,
                clear_secs=clear_secs,
                on_edit=self._open_edit_dialog,
                on_delete=self._delete_credential,
                on_toggle_favourite=self._toggle_favourite,
            )
            card.grid(sticky="ew", pady=(0, PAD_XS))

    def _show_empty(self, search: str) -> None:
        """Display a friendly empty-state message."""
        frame = ctk.CTkFrame(self._scroll, fg_color="transparent")
        frame.grid(row=0, column=0, pady=PAD_XL)
        frame.grid_columnconfigure(0, weight=1)

        if search or self._fav_only:
            icon, msg, sub = "🔍", "No results found", f'No credentials match "{search}"' if search else "No favourites yet."
        else:
            icon = "🔐"
            msg = "Your vault is empty"
            sub = "Add your first credential to get started."

        ctk.CTkLabel(frame, text=icon, font=(None, 48)).grid(row=0, column=0, pady=(0, PAD_MD))
        ctk.CTkLabel(frame, text=msg, font=FONT_HEADING, text_color=TEXT_PRIMARY).grid(row=1, column=0)
        ctk.CTkLabel(frame, text=sub, font=FONT_BODY, text_color=TEXT_MUTED).grid(row=2, column=0, pady=(PAD_XS, PAD_LG))

        if not search and not self._fav_only:
            ctk.CTkButton(
                frame, text="+ Add Credential", **primary_btn_kw(),
                command=self._open_add_dialog,
            ).grid(row=3, column=0)

    # ── Callbacks ─────────────────────────────────────────────────────────────

    def _open_add_dialog(self) -> None:
        dlg = CredentialDialog(self.winfo_toplevel(), self._service)
        self.wait_window(dlg)
        if dlg.result:
            self._load()

    def _open_edit_dialog(self, credential: Credential) -> None:
        dlg = CredentialDialog(self.winfo_toplevel(), self._service, credential=credential)
        self.wait_window(dlg)
        if dlg.result:
            self._load()

    def _delete_credential(self, credential_id: int) -> None:
        self._service.delete_credential(credential_id)
        self._load()

    def _toggle_favourite(self, credential_id: int, value: bool) -> None:
        self._service.toggle_favourite(credential_id, value)
        if self._fav_only:
            self._load()

    def _toggle_favourites(self) -> None:
        self._fav_only = not self._fav_only
        if self._fav_only:
            self._fav_btn.configure(text="★ Favourites", text_color=WARNING)
        else:
            self._fav_btn.configure(text="☆ Favourites", text_color=TEXT_MUTED)
        self._load()

    # ── Lifecycle hooks ───────────────────────────────────────────────────────

    def on_show(self) -> None:
        """Called by App when this screen is navigated to."""
        self._load()

    def on_settings_change(self, settings: dict) -> None:
        """Called when the user saves new settings."""
        self._settings = settings
