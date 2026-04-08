"""
main.py — Application entry point.

Run from the project root:

    python src/main.py

Or, if your shell is already inside src/:

    python main.py
"""
from __future__ import annotations

import os
import sys

# Ensure src/ is on the path regardless of the working directory
_SRC_DIR = os.path.dirname(os.path.abspath(__file__))
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from ui.app import App


def main() -> None:
    """Create and run the application."""
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
