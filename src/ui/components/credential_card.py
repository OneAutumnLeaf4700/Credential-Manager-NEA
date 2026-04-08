"""
ui/components/credential_card.py — A single credential row card.

Each card renders: coloured letter icon | title + website | username |
masked password with show/hide | copy-username | copy-password | favourite
star | edit | delete.

All callbacks are injected by the vault screen so the card stays decoupled
from dialogs and services.
"""
from __future__ import annotations

from typing import Callable, Optional

import customtkinter as ctk

from models.credential import Credential
from ui.theme import (
    ACCENT, BG_CARD, DANGER, FONT_BODY, FONT_CAPTION,
    FONT_SUBHEAD, HOVER_OVERLAY, PAD_MD, PAD_SM, PAD_XS,
    RADIUS_MD, RADIUS_SM, SUCCESS, TEXT_MUTED,
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_ON_ACCENT, WARNING,
    ghost_btn_kw, icon_colour,
)
from utils.clipboard import copy_with_autoclean

_MASKED = "••••••••"


class CredentialCard(ctk.CTkFrame):
    """
    A single credential row rendered inside the vault's scrollable list.

    Args:
        parent:             Parent widget (scrollable frame).
        credential:         Decrypted Credential object.
        clear_secs:         Seconds before clipboard auto-clears.
        on_edit:            Called with the credential when Edit is clicked.
        on_delete:          Called with the credential id when Delete is confirmed.
        on_toggle_favourite: Called with (id, new_bool) when star is clicked.
    """

    def __init__(
        self,
        parent: ctk.CTkBaseClass,
        credential: Credential,
        clear_secs: int = 30,
        on_edit: Optional[Callable[[Credential], None]] = None,
        on_delete: Optional[Callable[[int], None]] = None,
        on_toggle_favourite: Optional[Callable[[int, bool], None]] = None,
        **kwargs,
    ) -> None:
        kwargs.setdefault("fg_color", BG_CARD)
        kwargs.setdefault("corner_radius", RADIUS_MD)
        super().__init__(parent, **kwargs)

        self._cred = credential
        self._clear_secs = clear_secs
        self._on_edit = on_edit
        self._on_delete = on_delete
        self._on_toggle_fav = on_toggle_favourite
        self._password_visible = False
        self._delete_confirm = False

        self._build()
        self._bind_hover()

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self) -> None:
        self.grid_columnconfigure(1, weight=1)   # title+website expands
        self.grid_columnconfigure(2, weight=1)   # username expands

        # ── Icon ──────────────────────────────────────────────────────────────
        letter = (self._cred.title[0].upper()) if self._cred.title else "?"
        colour = icon_colour(self._cred.title)

        icon_frame = ctk.CTkFrame(
            self, width=40, height=40,
            fg_color=colour, corner_radius=RADIUS_SM,
        )
        icon_frame.grid(row=0, column=0, padx=(PAD_MD, PAD_SM), pady=PAD_SM)
        icon_frame.grid_propagate(False)
        icon_frame.grid_columnconfigure(0, weight=1)
        icon_frame.grid_rowconfigure(0, weight=1)

        ctk.CTkLabel(
            icon_frame, text=letter, font=FONT_SUBHEAD,
            text_color=TEXT_ON_ACCENT, fg_color="transparent",
        ).grid(row=0, column=0)

        # ── Title + website ────────────────────────────────────────────────────
        info_frame = ctk.CTkFrame(self, fg_color="transparent")
        info_frame.grid(row=0, column=1, sticky="ew", padx=(0, PAD_SM), pady=PAD_SM)

        ctk.CTkLabel(
            info_frame, text=self._cred.title,
            font=FONT_SUBHEAD, text_color=TEXT_PRIMARY,
            anchor="w",
        ).grid(row=0, column=0, sticky="w")

        website_text = self._cred.display_website or self._cred.category
        ctk.CTkLabel(
            info_frame, text=website_text,
            font=FONT_CAPTION, text_color=TEXT_MUTED,
            anchor="w",
        ).grid(row=1, column=0, sticky="w")

        # ── Username ──────────────────────────────────────────────────────────
        ctk.CTkLabel(
            self, text=self._cred.display_username,
            font=FONT_BODY, text_color=TEXT_SECONDARY,
            anchor="w",
        ).grid(row=0, column=2, sticky="ew", padx=(0, PAD_SM), pady=PAD_SM)

        # ── Actions ───────────────────────────────────────────────────────────
        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.grid(row=0, column=3, sticky="e", padx=(0, PAD_SM), pady=PAD_SM)

        # Password visibility toggle + masked label
        self._pw_label = ctk.CTkLabel(
            actions, text=_MASKED, font=FONT_BODY,
            text_color=TEXT_MUTED, width=90, anchor="w",
        )
        self._pw_label.grid(row=0, column=0, padx=(0, PAD_XS))

        self._eye_btn = ctk.CTkButton(
            actions, text="👁", width=30, height=28,
            **ghost_btn_kw(font=FONT_BODY),
            command=self._toggle_password,
        )
        self._eye_btn.grid(row=0, column=1, padx=(0, PAD_XS))

        # Copy username
        self._copy_user_btn = ctk.CTkButton(
            actions, text="Copy User", width=80, height=28,
            **ghost_btn_kw(),
            command=self._copy_username,
        )
        self._copy_user_btn.grid(row=0, column=2, padx=(0, PAD_XS))

        # Copy password
        self._copy_pass_btn = ctk.CTkButton(
            actions, text="Copy Pass", width=80, height=28,
            **ghost_btn_kw(),
            command=self._copy_password,
        )
        self._copy_pass_btn.grid(row=0, column=3, padx=(0, PAD_SM))

        # Favourite star
        star = "★" if self._cred.is_favourite else "☆"
        star_colour = WARNING if self._cred.is_favourite else TEXT_MUTED
        self._fav_btn = ctk.CTkButton(
            actions, text=star, width=28, height=28,
            **ghost_btn_kw(text_color=star_colour),
            command=self._toggle_favourite,
        )
        self._fav_btn.grid(row=0, column=4, padx=(0, PAD_XS))

        # Edit
        ctk.CTkButton(
            actions, text="Edit", width=44, height=28,
            **ghost_btn_kw(text_color=ACCENT),
            command=self._edit,
        ).grid(row=0, column=5, padx=(0, PAD_XS))

        # Delete
        self._del_btn = ctk.CTkButton(
            actions, text="Delete", width=54, height=28,
            **ghost_btn_kw(text_color=DANGER),
            command=self._delete_step,
        )
        self._del_btn.grid(row=0, column=6, padx=(0, PAD_XS))

    # ── Interaction ───────────────────────────────────────────────────────────

    def _bind_hover(self) -> None:
        """Attach hover highlight to the card frame (not child widgets)."""
        self.bind("<Enter>", lambda _: self.configure(fg_color=HOVER_OVERLAY))
        self.bind("<Leave>", lambda _: self.configure(fg_color=BG_CARD))

    def _toggle_password(self) -> None:
        if self._password_visible:
            self._pw_label.configure(text=_MASKED, text_color=TEXT_MUTED)
            self._eye_btn.configure(text="👁")
            self._password_visible = False
        else:
            self._pw_label.configure(text=self._cred.password, text_color=TEXT_PRIMARY)
            self._eye_btn.configure(text="🙈")
            self._password_visible = True

    def _copy_username(self) -> None:
        copy_with_autoclean(self._cred.username, self._clear_secs)
        self._flash(self._copy_user_btn, "✓ Copied!", "Copy User")

    def _copy_password(self) -> None:
        copy_with_autoclean(self._cred.password, self._clear_secs)
        self._flash(self._copy_pass_btn, "✓ Copied!", "Copy Pass")

    def _flash(self, btn: ctk.CTkButton, flash_text: str, original_text: str) -> None:
        """Briefly show *flash_text* on *btn* then restore *original_text*."""
        btn.configure(text=flash_text, text_color=SUCCESS)
        btn.after(1500, lambda: btn.configure(text=original_text, text_color=TEXT_SECONDARY))

    def _toggle_favourite(self) -> None:
        new_val = not self._cred.is_favourite
        self._cred.is_favourite = new_val
        self._fav_btn.configure(
            text="★" if new_val else "☆",
            text_color=WARNING if new_val else TEXT_MUTED,
        )
        if self._on_toggle_fav and self._cred.id is not None:
            self._on_toggle_fav(self._cred.id, new_val)

    def _edit(self) -> None:
        if self._on_edit:
            self._on_edit(self._cred)

    def _delete_step(self) -> None:
        """Two-step delete: first click asks for confirmation."""
        if not self._delete_confirm:
            self._delete_confirm = True
            self._del_btn.configure(text="Confirm?", text_color=TEXT_ON_ACCENT, fg_color=DANGER)
            # Auto-reset confirmation after 3 seconds
            self._del_btn.after(3000, self._reset_delete_btn)
        else:
            if self._on_delete and self._cred.id is not None:
                self._on_delete(self._cred.id)

    def _reset_delete_btn(self) -> None:
        self._delete_confirm = False
        try:
            self._del_btn.configure(text="Delete", text_color=DANGER, fg_color="transparent")
        except Exception:
            pass
