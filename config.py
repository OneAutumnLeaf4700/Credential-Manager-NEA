import os

# Get the directory where the script is located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Create a data directory if it doesn't exist
DATA_DIR = os.path.join(BASE_DIR, 'data')
os.makedirs(DATA_DIR, exist_ok=True)

# Database file paths
DB_PATHS = {
    'master_password': os.path.join(DATA_DIR, 'MPasswords.db'),
    'all_items': os.path.join(DATA_DIR, 'AllItems.db'),
    'favourites': os.path.join(DATA_DIR, 'Favourites.db'),
    'user_settings': os.path.join(DATA_DIR, 'UserSettings.db')
}

# Ensure all database files exist
for db_path in DB_PATHS.values():
    if not os.path.exists(db_path):
        with open(db_path, 'w') as f:
            pass  # Create empty file 