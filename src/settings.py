#settings.py
import customtkinter as ctk
import sqlite3
from config import DB_PATHS

root = ctk.CTk()
# Dictionary to store the user settings
# Values loaded from database
user_settings = {}
# Loading the settings database contents into the user_settings dictionary
with sqlite3.connect(DB_PATHS['user_settings']) as db:
    cursor = db.cursor()
    cursor.execute("SELECT * FROM settings")
    data = cursor.fetchone()

# If no data is found, use default values
if not data:
    settings = {
        'theme': 'system',
        'widget_theme': 'dark-blue',
        'text_size': 16,
        'text_color': 'White',
        'font_family': 'Arial'
    }
else:
    settings = {
        'theme': data[1],
        'widget_theme': data[2],
        'text_size': data[3],
        'text_color': data[4],
        'font_family': data[5]
    }

# Assigning variables based on the user_settings dictionary
program_theme = settings["theme"]
widget_theme = settings["widget_theme"]
text_size = settings["text_size"]
text_color = settings["text_color"]
font_name = settings["font_family"]

# Numerical Assignments
subtitle_size = text_size + 2
title_size = text_size + 4
button_border_width = 2
# Alphabetical Assignments
txt_entry_fg_color = "black"
button_fg_color = "#0f0f0f"
button_border_color = "black"
frame_bg_color = "transparent"
window_bg_color = "transparent"
title_fg_color = "transparent"
# Font Assignments
text_type = ctk.CTkFont(family = font_name, size = text_size)
subtitle_type = ctk.CTkFont(family = font_name, size = subtitle_size)
title_type = ctk.CTkFont(family=font_name, size=title_size)
ctk.set_appearance_mode(program_theme)
ctk.set_default_color_theme(widget_theme)
entry_style = {"font": text_type, "text_color": text_color, "fg_color": txt_entry_fg_color}
label_style = {"font": subtitle_type, "text_color": text_color}
button_style = {"font": subtitle_type, "fg_color": button_fg_color, "border_width":
button_border_width, "border_color": button_border_color}