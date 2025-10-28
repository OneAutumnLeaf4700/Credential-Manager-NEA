# Credential Manager NEA

Short, updated README for the credential manager GUI project created as an A-Level NEA.

## Important safety notice

THIS PROJECT IS A SCHOOL/LEARNING PROJECT AND IS NOT READY FOR PRODUCTION.

- There are likely security issues and design limitations. Do NOT store highly sensitive or irreplaceable credentials in this vault.
- You use this software at your own risk. The author is not responsible for data loss or compromise.

If you want a production-ready password manager, consider using a well-maintained project (Bitwarden, KeePassXC, 1Password, etc.).

## What this project is

Credential Manager NEA is a desktop GUI application (Tkinter / CustomTkinter) that demonstrates:

- A simple encrypted credential store (Fernet symmetric encryption)
- A master password protecting the vault
- Add / Edit / Delete credentials
- Favourites, import/export (JSON/CSV), and a random password generator
- Basic user settings persisted to SQLite

The codebase is intentionally educational and was written as an A-Level coursework project.

## Repo layout (important files)

- `src/` – application Python source
  - `main.py` – main GUI and application logic (entry point)
  - `config.py` – paths and data directory creation
  - `database.py` – SQLite DB initialization and exported paths
  - `settings.py` – UI theme / colors (visual constants)
- `gui/` – (empty __init__.py present)
- `data/` – SQLite files and encryption key (created at runtime under `src/data`)
- `requirements.txt` – Python dependencies
- `LICENSE` – MIT license

## Requirements

- Python 3.8 or newer (3.10+ recommended)
- OS: Windows / macOS / Linux (UI tested on desktop environments)
- Dependencies (see `requirements.txt`):
  - customtkinter
  - pyperclip
  - pillow
  - cryptography

Create and activate a virtual environment before installing packages (example for PowerShell on Windows):

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Running the application

From the repository root run:

```powershell
python src/main.py
```

On first run the app will ask you to create a master password. That master password unlocks the vault and is used indirectly with the Fernet key stored in `src/data/encryption.key`.

## Where data is stored

By default the project stores its SQLite databases and the encryption key in `src/data/` (the path is defined by `src/config.py` and `src/database.py`):

- `MPasswords.db` – master password table
- `AllItems.db` – main credential table
- `Favourites.db` – starred credentials
- `UserSettings.db` – persisted UI settings
- `encryption.key` – symmetric key used by cryptography.Fernet

If you want to reset the vault (for testing), you can remove the master password and key files. Example (PowerShell):

```powershell
del src\data\MPasswords.db; del src\data\encryption.key
```

WARNING: Deleting those files will permanently lose access to any encrypted credentials.

## Import / Export

Use the built-in Import/Export window to import credentials from JSON or CSV or export your vault to JSON/CSV.

CSV expected columns: id, title, username, password, website, notes

## Development notes

- The main GUI is implemented in `src/main.py`. Styles and constants live in `src/settings.py`.
- Database paths are created automatically by `src/config.py` if the `src/data` folder or files do not exist.
- Passwords are encrypted with Fernet. The encryption key is stored in `src/data/encryption.key`.

Known limitations / TODOs:

- This project is not hardened for production use (no secure key storage, no PBKDF2/Argon2 KDF for master password, no OS-level keyring integration).
- Error handling and unit tests are limited. Consider adding tests before expanding features.
- Consider using a proper packaging layout (console script entry point) for easier distribution.

## Troubleshooting

- If the GUI does not appear, ensure `customtkinter` and `pillow` are installed and you have a desktop environment.
- On Windows PowerShell, if clipboard copy fails, ensure `pyperclip` dependencies are met; installing `pywin32` may help.
- If the app complains about missing DB files, run Python from the repo root so `src/config.py` can create `src/data`.

If you encounter specific errors, open an issue with the traceback and steps to reproduce.

## Contributing

This repository is primarily a personal/educational project. If you'd like to suggest improvements or fixes:

1. Fork the repo
2. Create a topic branch
3. Open a pull request describing your changes

Small contributions that improve documentation, add tests, or fix obvious bugs are welcome.

## License

This project is distributed under the MIT License. See `LICENSE` for details.

---

If you'd like, I can also:

- add a short developer README with commands to run and debug the GUI
- add a CONTRIBUTING.md template
- add a small test harness to validate DB initialization
