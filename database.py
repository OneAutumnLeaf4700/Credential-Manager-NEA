import sqlite3
from config import DB_PATHS
import os

# Export database paths
MASTER_PASSWORD_DB = DB_PATHS['master_password']
ALL_ITEMS_DB = DB_PATHS['all_items']
FAVOURITES_DB = DB_PATHS['favourites']
USER_SETTINGS_DB = DB_PATHS['user_settings']
KEY_FILE = os.path.join(os.path.dirname(DB_PATHS['master_password']), 'encryption.key')

def get_db_path(db_name):
    """Get the path for a database by its name."""
    db_name = db_name.lower()
    if db_name == 'mpasswords':
        return DB_PATHS['master_password']
    elif db_name == 'allitems':
        return DB_PATHS['all_items']
    elif db_name == 'favourites':
        return DB_PATHS['favourites']
    else:
        raise ValueError(f"Unknown database name: {db_name}")

# Master Password Database
with sqlite3.connect(DB_PATHS['master_password']) as db:
    cursor = db.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS master_password (id INTEGER PRIMARY KEY, password TEXT);")

# All Items Database
with sqlite3.connect(DB_PATHS['all_items']) as db:
    cursor = db.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS all_items (id INTEGER PRIMARY KEY, title TEXT, username TEXT, password TEXT, website TEXT, notes TEXT);")

# Favourites Database
with sqlite3.connect(DB_PATHS['favourites']) as db:
    cursor = db.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS favourites (id INTEGER PRIMARY KEY, title TEXT, username TEXT, password TEXT, website TEXT, notes TEXT);")

# User Settings Database
with sqlite3.connect(DB_PATHS['user_settings']) as db:
    cursor = db.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY, theme TEXT, widget_theme TEXT, text_size INTEGER, text_color TEXT, font_family TEXT);")
    # Insert default values if the table is empty
    cursor.execute("INSERT OR IGNORE INTO settings (id, theme, widget_theme, text_size, text_color, font_family) VALUES (1, 'system', 'dark-blue', 16, 'White', 'Arial');")
    db.commit()

