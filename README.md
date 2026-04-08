# KeyVault — A-Level CS NEA Credential Manager

A modern, secure desktop password manager built with Python and CustomTkinter.

> **Disclaimer:** This is an educational A-Level coursework project.
> Do not use it to store production or irreplaceable credentials.

---

## What it does

- **Secure vault** — All credential fields are encrypted at rest with Fernet (AES-128-CBC).
  The encryption key is derived from your master password using PBKDF2-HMAC-SHA256
  (600 000 iterations) — no key file is stored on disk.
- **Master password auth** — Login and first-run setup screens.  Master password can be changed
  at any time from Settings; the vault re-wraps the key without re-encrypting every entry.
- **Add / Edit / Delete credentials** — Service name, username, password, website, notes, category.
- **Password strength meter** — Live 5-segment colour bar as you type.
- **Password generator** — Configurable length (8–64), character sets, exclude-ambiguous toggle.
  Guarantees at least one character from every selected set.
- **Search & filter** — Live search across title, username, and website.
  Category filter dropdown and Favourites-only toggle.
- **Copy to clipboard** — Separate buttons for username and password with a brief "✓ Copied!" flash.
  Clipboard is automatically overwritten after a configurable timeout (default 30 s).
- **Favourites** — Star any credential; filter to starred only.
- **Last-modified timestamp** — Every credential records `created_at` and `updated_at`.
- **Settings** — Clipboard auto-clear duration; change master password with strength feedback.

---

## Project layout

```
src/
├── main.py                        # Entry point
├── config.py                      # Paths / data directory
├── models/
│   └── credential.py              # Credential dataclass
├── database/
│   └── db_manager.py              # Single SQLite vault.db, schema init
├── services/
│   ├── crypto_service.py          # PBKDF2 key derivation, Fernet wrap/unwrap
│   ├── auth_service.py            # Master password setup, login, rotation
│   └── vault_service.py           # CRUD, search, settings
├── utils/
│   ├── clipboard.py               # Copy + auto-clear timer
│   └── password_strength.py       # Score 0–4, label, colour
└── ui/
    ├── theme.py                   # Design system constants
    ├── app.py                     # Root CTk window, auth↔vault transition
    ├── components/
    │   ├── strength_meter.py      # Reusable strength bar widget
    │   └── credential_card.py     # Single credential row card
    ├── screens/
    │   ├── auth_screen.py         # Login and first-run setup
    │   ├── vault_screen.py        # Credential list, search, filter
    │   ├── generator_screen.py    # Password generator panel
    │   └── settings_screen.py     # Settings panel
    └── dialogs/
        └── credential_dialog.py   # Add / Edit modal (CTkToplevel)

data/
└── vault.db                       # Created automatically on first run
```

---

## Requirements

- Python 3.10 or newer
- `tk` system package (Tcl/Tk — see platform notes below)
- Python dependencies in `requirements.txt`:
  - `customtkinter >= 5.2.0`
  - `cryptography >= 41.0.0`
  - `pyperclip >= 1.8.0`
  - `pillow >= 10.0.0`

### Installing Tk

| Platform | Command |
|----------|---------|
| Arch / Manjaro | `sudo pacman -S tk` |
| Ubuntu / Debian | `sudo apt install python3-tk` |
| Fedora | `sudo dnf install python3-tkinter` |
| Windows / macOS | Tk is bundled with the official Python installer |

---

## Installation

```bash
# 1. Clone the repo
git clone <repo-url>
cd Credential-Manager-NEA

# 2. (Recommended) Create a virtual environment
python -m venv .venv
source .venv/bin/activate      # Linux / macOS
# .venv\Scripts\activate       # Windows PowerShell

# 3. Install Python dependencies
pip install -r requirements.txt
```

---

## Running

```bash
python src/main.py
```

On first run, a setup screen asks you to create a master password.
Subsequent runs show the login screen.

The vault database is stored at `src/data/vault.db`.

---

## Security design

| Concern | Approach |
|---------|----------|
| Master password storage | Never stored — only PBKDF2-derived wrapping key used |
| KDF | PBKDF2-HMAC-SHA256, 600 000 iterations, 32-byte random salt |
| Vault encryption | Fernet (AES-128-CBC + HMAC-SHA256) per credential field |
| Key protection | Fernet key wrapped with derived key; only the wrapped form in DB |
| Password change | Only rewraps the key — no re-encryption of credential data needed |
| Clipboard | Auto-cleared after configurable timeout (default 30 s) |

---

## Resetting the vault

Delete `src/data/vault.db` to wipe all credentials and start fresh.

> ⚠ This is irreversible. All credentials will be permanently lost.

```bash
rm src/data/vault.db
```

---

## License

MIT — see `LICENSE`.
