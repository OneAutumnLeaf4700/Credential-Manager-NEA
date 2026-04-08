"""
config.py — single source of truth for all paths.
"""
import os

# Absolute path to src/ directory
BASE_DIR: str = os.path.dirname(os.path.abspath(__file__))

# Data directory lives inside src/
DATA_DIR: str = os.path.join(BASE_DIR, "data")

# Single vault database (replaces the four legacy .db files)
DB_PATH: str = os.path.join(DATA_DIR, "vault.db")

# Create data directory on import — no side-effects beyond this
os.makedirs(DATA_DIR, exist_ok=True)
