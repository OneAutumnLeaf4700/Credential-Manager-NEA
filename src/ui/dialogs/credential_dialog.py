"""
ui/dialogs/credential_dialog.py — Add / Edit credential modal dialog.

Opens as a CTkToplevel (child window) that blocks the parent via grab_set().
The result is stored in dialog.result before the window is destroyed, so the
caller can read it with wait_window():

    dlg = CredentialDialog(parent, vault_service)
    parent.wait_window(dlg)
    if dlg.result:
        ...
"""
from __future__ import annotations

import string
import secrets
from typing import Optional

import customtkinter as ctk

from models.credential import Credential
from services.vault_service import VaultService
from ui.components.strength_meter import StrengthMeter
from ui.theme import (
    ACCENT, BG_PRIMARY, BG_SURFACE, BG_INPUT, BORDER, DANGER, FONT_BODY,
    FONT_CAPTION, FONT_HEADING, FONT_SUBHEAD, PAD_LG, PAD_MD, PAD_SM,
    PAD_XL, PAD_XS, RADIUS_LG, RADIUS_MD, SUCCESS, TEXT_MUTED,
    TEXT_PRIMARY, TEXT_SECONDARY, DEFAULT_CATEGORIES,
    danger_btn_kw, ghost_btn_kw, input_kw, primary_btn_kw,
)


class CredentialDialog(ctk.CTkToplevel):
    """
    Modal dialog for adding or editing a credential.

    Args:
        parent:        Parent widget.
        vault_service: Active VaultService for save operations.
        credential:    Existing Credential to edit, or None to add.
    """

    def __init__(
        self,
        parent: ctk.CTkBaseClass,
        vault_service: VaultService,
        credential: Optional[Credential] = None,
    ) -> None:
        super().__init__(parent)
        self._service = vault_service
        self._editing: Optional[Credential] = credential
        self.result: Optional[Credential] = None

        self._setup_window()
        self._build()

        # Make modal
        self.grab_set()
        self.focus_force()
        self._title_entry.focus_set()

    # ── Window setup ──────────────────────────────────────────────────────────

    def _setup_window(self) -> None:
        title = "Edit Credential" if self._editing else "Add Credential"
        self.title(title)
        self.configure(fg_color=BG_PRIMARY)
        self.resizable(False, False)

        # Center over parent
        self.update_idletasks()
        pw, ph = self.master.winfo_width(), self.master.winfo_height()
        px, py = self.master.winfo_x(), self.master.winfo_y()
        w, h = 520, 660
        x = px + (pw - w) // 2
        y = py + (ph - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Header
        header = ctk.CTkFrame(self, fg_color=BG_SURFACE, corner_radius=0, height=60)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_propagate(False)
        header.grid_columnconfigure(0, weight=1)
        title_text = "Edit Credential" if self._editing else "Add New Credential"
        ctk.CTkLabel(
            header, text=title_text, font=FONT_HEADING, text_color=TEXT_PRIMARY,
        ).grid(row=0, column=0, sticky="w", padx=PAD_LG, pady=PAD_MD)

        # Scrollable body
        body = ctk.CTkScrollableFrame(
            self, fg_color=BG_PRIMARY, scrollbar_fg_color=BG_PRIMARY,
        )
        body.grid(row=1, column=0, sticky="nsew")
        body.grid_columnconfigure(0, weight=1)
        self._build_form(body)

        # Footer
        footer = ctk.CTkFrame(self, fg_color=BG_SURFACE, corner_radius=0, height=64)
        footer.grid(row=2, column=0, sticky="ew")
        footer.grid_propagate(False)
        footer.grid_columnconfigure(0, weight=1)

        btn_row = ctk.CTkFrame(footer, fg_color="transparent")
        btn_row.grid(row=0, column=0, sticky="e", padx=PAD_LG, pady=PAD_MD)

        ctk.CTkButton(
            btn_row, text="Cancel", width=100, height=36,
            **ghost_btn_kw(text_color=TEXT_SECONDARY),
            command=self.destroy,
        ).pack(side="left", padx=(0, PAD_SM))

        save_text = "Save Changes" if self._editing else "Add Credential"
        ctk.CTkButton(
            btn_row, text=save_text, width=130, height=36,
            **primary_btn_kw(), command=self._save,
        ).pack(side="left")

    def _build_form(self, parent: ctk.CTkFrame) -> None:
        """Render all form fields into *parent*."""
        e = self._editing

        # ── Service name ──────────────────────────────────────────────────────
        self._label(parent, "Service Name *", 0)
        self._title_entry = ctk.CTkEntry(
            parent, placeholder_text="e.g. GitHub, Netflix", height=40, **input_kw(),
        )
        self._title_entry.grid(row=1, column=0, sticky="ew", padx=PAD_LG, pady=(0, PAD_MD))
        if e:
            self._title_entry.insert(0, e.title)

        # ── Username ──────────────────────────────────────────────────────────
        self._label(parent, "Username / Email *", 2)
        self._user_entry = ctk.CTkEntry(
            parent, placeholder_text="you@example.com", height=40, **input_kw(),
        )
        self._user_entry.grid(row=3, column=0, sticky="ew", padx=PAD_LG, pady=(0, PAD_MD))
        if e:
            self._user_entry.insert(0, e.username)

        # ── Password ──────────────────────────────────────────────────────────
        self._label(parent, "Password *", 4)
        pw_row = ctk.CTkFrame(parent, fg_color="transparent")
        pw_row.grid(row=5, column=0, sticky="ew", padx=PAD_LG, pady=(0, PAD_XS))
        pw_row.grid_columnconfigure(0, weight=1)

        self._pw_entry = ctk.CTkEntry(
            pw_row, placeholder_text="Password", show="•",
            height=40, **input_kw(),
        )
        self._pw_entry.grid(row=0, column=0, sticky="ew", padx=(0, PAD_XS))
        if e:
            self._pw_entry.insert(0, e.password)

        show_btn = ctk.CTkButton(
            pw_row, text="👁", width=40, height=40,
            fg_color=BG_INPUT, hover_color=ACCENT,
            text_color=TEXT_SECONDARY, corner_radius=RADIUS_MD, font=FONT_BODY,
            command=lambda: self._toggle_show(self._pw_entry, show_btn),
        )
        show_btn.grid(row=0, column=1, padx=(0, PAD_XS))

        gen_btn = ctk.CTkButton(
            pw_row, text="⚡ Generate", width=110, height=40,
            **ghost_btn_kw(text_color=ACCENT),
            command=self._generate_password,
        )
        gen_btn.grid(row=0, column=2)

        # Strength meter
        self._meter = StrengthMeter(parent)
        self._meter.grid(row=6, column=0, sticky="ew", padx=PAD_LG, pady=(PAD_XS, PAD_MD))
        self._pw_entry.bind("<KeyRelease>", lambda _: self._meter.update(self._pw_entry.get()))
        if e:
            self._meter.update(e.password)

        # ── Website ───────────────────────────────────────────────────────────
        self._label(parent, "Website / URL", 7)
        self._web_entry = ctk.CTkEntry(
            parent, placeholder_text="https://example.com", height=40, **input_kw(),
        )
        self._web_entry.grid(row=8, column=0, sticky="ew", padx=PAD_LG, pady=(0, PAD_MD))
        if e:
            self._web_entry.insert(0, e.website)

        # ── Category ─────────────────────────────────────────────────────────
        self._label(parent, "Category", 9)
        categories = DEFAULT_CATEGORIES
        self._cat_var = ctk.StringVar(value=(e.category if e else "General"))
        ctk.CTkOptionMenu(
            parent,
            values=categories,
            variable=self._cat_var,
            fg_color=BG_INPUT,
            button_color=ACCENT,
            button_hover_color=ACCENT,
            dropdown_fg_color=BG_SURFACE,
            text_color=TEXT_PRIMARY,
            font=FONT_BODY,
            height=40,
            corner_radius=RADIUS_MD,
        ).grid(row=10, column=0, sticky="ew", padx=PAD_LG, pady=(0, PAD_MD))

        # ── Notes ─────────────────────────────────────────────────────────────
        self._label(parent, "Notes", 11)
        self._notes_entry = ctk.CTkTextbox(
            parent, height=80,
            fg_color=BG_INPUT, text_color=TEXT_PRIMARY,
            border_color=BORDER, border_width=1,
            corner_radius=RADIUS_MD, font=FONT_BODY,
        )
        self._notes_entry.grid(row=12, column=0, sticky="ew", padx=PAD_LG, pady=(0, PAD_MD))
        if e and e.notes:
            self._notes_entry.insert("0.0", e.notes)

        # Status
        self._status = ctk.CTkLabel(
            parent, text="", font=FONT_CAPTION,
            text_color=DANGER, wraplength=460,
        )
        self._status.grid(row=13, column=0, padx=PAD_LG, pady=(0, PAD_LG))

    @staticmethod
    def _label(parent: ctk.CTkFrame, text: str, row: int) -> None:
        ctk.CTkLabel(
            parent, text=text, font=FONT_SUBHEAD,
            text_color=TEXT_SECONDARY, anchor="w",
        ).grid(row=row, column=0, sticky="w", padx=PAD_LG, pady=(PAD_SM, PAD_XS))

    # ── Actions ───────────────────────────────────────────────────────────────

    @staticmethod
    def _toggle_show(entry: ctk.CTkEntry, btn: ctk.CTkButton) -> None:
        if entry.cget("show") == "•":
            entry.configure(show="")
            btn.configure(text="🙈")
        else:
            entry.configure(show="•")
            btn.configure(text="👁")

    def _generate_password(self) -> None:
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        pwd = "".join(secrets.choice(alphabet) for _ in range(20))
        self._pw_entry.delete(0, "end")
        self._pw_entry.insert(0, pwd)
        self._pw_entry.configure(show="")
        self._meter.update(pwd)

    def _save(self) -> None:
        title = self._title_entry.get().strip()
        username = self._user_entry.get().strip()
        password = self._pw_entry.get()
        website = self._web_entry.get().strip()
        category = self._cat_var.get()
        notes = self._notes_entry.get("0.0", "end").strip()

        if not title:
            self._status.configure(text="Service name is required.", text_color=DANGER)
            return
        if not username:
            self._status.configure(text="Username is required.", text_color=DANGER)
            return
        if not password:
            self._status.configure(text="Password is required.", text_color=DANGER)
            return

        self._status.configure(text="Saving…", text_color=TEXT_MUTED)
        self.update_idletasks()

        try:
            if self._editing:
                cred = self._editing
                cred.title = title
                cred.username = username
                cred.password = password
                cred.website = website
                cred.category = category
                cred.notes = notes
                self._service.update_credential(cred)
            else:
                cred = Credential(
                    title=title, username=username, password=password,
                    website=website, notes=notes, category=category,
                )
                new_id = self._service.add_credential(cred)
                cred.id = new_id

            self.result = cred
            self.destroy()

        except Exception as exc:
            self._status.configure(text=f"Error: {exc}", text_color=DANGER)
