# Final Code:
# Main.py:
import customtkinter as ctk
import hashlib
import string
import secrets
import pyperclip
import sqlite3
import re
import json
import csv
import threading
import time
from tkinter import messagebox, filedialog, IntVar, StringVar
from PIL import Image
from cryptography.fernet import Fernet
from database import MASTER_PASSWORD_DB, ALL_ITEMS_DB, FAVOURITES_DB, KEY_FILE, USER_SETTINGS_DB, get_db_path
from settings import *
import sys  # Add this with the other imports at the top

# Add at the top of the file, after imports
def initialize_user_settings():
    try:
        with sqlite3.connect(USER_SETTINGS_DB) as db:
            cursor = db.cursor()
            # Create settings table if it doesn't exist
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    id INTEGER PRIMARY KEY,
                    theme TEXT DEFAULT 'system',
                    widget_theme TEXT DEFAULT 'blue',
                    text_size INTEGER DEFAULT 14,
                    text_color TEXT DEFAULT 'white',
                    font_family TEXT DEFAULT 'Arial'
                )
            """)
            
            # Check if settings exist
            cursor.execute("SELECT COUNT(*) FROM settings")
            if cursor.fetchone()[0] == 0:
                # Insert default settings
                cursor.execute("""
                    INSERT INTO settings (id, theme, widget_theme, text_size, text_color, font_family)
                    VALUES (1, 'system', 'blue', 14, 'white', 'Arial')
                """)
            db.commit()
            
            # Load settings
            cursor.execute("SELECT * FROM settings WHERE id = 1")
            settings = cursor.fetchone()
            return {
                "theme": settings[1],
                "widget_theme": settings[2],
                "text_size": settings[3],
                "text_color": settings[4],
                "font_family": settings[5]
            }
    except Exception as e:
        print(f"Error initializing user settings: {e}")
        # Return default settings if there's an error
        return {
            "theme": "system",
            "widget_theme": "blue",
            "text_size": 14,
            "text_color": "white",
            "font_family": "Arial"
        }

# Initialize user settings
user_settings = initialize_user_settings()

class CredentialManager:
    entry_style = {"font": text_type, "text_color": text_color, "fg_color": txt_entry_fg_color}
    label_style = {"font": subtitle_type, "text_color": text_color}
    button_style = {"font": subtitle_type, "fg_color": button_fg_color, "border_width":
                    button_border_width, "border_color": button_border_color, "text_color": text_color}
    
    def __init__(self, root):
        self.root = root
        self.key = None
        self.password_file = None
        self.password_dict = {}
        self.load_or_create_key()
    
    def load_or_create_key(self):
        # Use the KEY_FILE from database.py
        KEY_PATH = KEY_FILE
        
        # Check if the master password exists in the database
        with sqlite3.connect(MASTER_PASSWORD_DB) as db:
            cursor = db.cursor()
            cursor.execute("SELECT * FROM master_password")
            stored_password = cursor.fetchone()
            if stored_password:
                # Master password exists, load the encryption key
                self.load_key(KEY_PATH)
            else:
                # Master password doesn't exist, create a new key
                self.create_key(KEY_PATH)
                self.load_key(KEY_PATH)
    
    def check_master_password(self):
        try:
            # Connect to the database using MASTER_PASSWORD_DB
            with sqlite3.connect(MASTER_PASSWORD_DB) as db:
                cursor = db.cursor()
                # Execute a query to check if any records exist
                cursor.execute("SELECT * FROM master_password")
                count = cursor.fetchone()
                if count:
                    return True
                return False
        except sqlite3.Error as e:
            print(f"SQLite error: {e}")
            return False
    
    def run_login_screen(self):
        app = LoginScreen(self.root)
        app.run()
    
    def run_create_master_password(self):
        app = CreateMasterPassword(self.root)
        app.run()
    
    def create_key(self, path):
        self.key = Fernet.generate_key()
        with open(path, "wb") as key_file:
            key_file.write(self.key)
    
    def load_key(self, path):
        with open(path, "rb") as key_file:
            self.key = key_file.read()
    
    def get_key(self):
        return self.key
    
    def create_password_file(self, path):
        self.password_file = path
        with open(self.password_file, "w") as file:
            json.dump(self.password_dict, file)
    
    def load_password_file(self, path):
        self.password_file = path
        with open(self.password_file, "r") as file:
            self.password_dict = json.load(file)
    
    def encrypt_password(self, password):
        self.password = password.encode("utf-8")
        self.fernet = Fernet(self.key)
        self.encrypted_password = self.fernet.encrypt(self.password)
        return self.encrypted_password
    
    def decrypt_password(self, encrypted_password):
        self.encrypted_password = encrypted_password
        self.fernet = Fernet(self.key)
        decrypted_bytes = self.fernet.decrypt(self.encrypted_password)
        decrypted_string = decrypted_bytes.decode("utf-8")
        return decrypted_string
    
    def add_password(self, website, username, password):
        self.website = website
        self.username = username
        self.password = password
        self.password_dict[self.website] = {"username": self.username, "password":
                                            self.encrypt_password(self.password)}
        with open(self.password_file, "w") as file:
            json.dump(self.password_dict, file)
    
    def delete_password(self, website):
        self.website = website
        self.password_dict.pop(self.website)
        with open(self.password_file, "w") as file:
            json.dump(self.password_dict, file)
    
    def update_password(self, website, username, password):
        self.website = website
        self.username = username
        self.password = password
        self.password_dict[self.website] = {"username": self.username, "password":
                                            self.encrypt_password(self.password)}
        with open(self.password_file, "w") as file:
            json.dump(self.password_dict, file)
    
    def get_password(self, website):
        self.website = website
        return self.decrypt_password(self.password_dict[self.website]["password"])
    
    def get_all_passwords(self):
        return self.password_dict
    
    def hash_text(self, text):
        self.text = text
        self.hash = hashlib.sha256(self.text)
        self.hash = self.hash.hexdigest()
        return self.hash
    
    @staticmethod
    def popup(parent, text):
        messagebox.showinfo("Popup Message", text, parent=parent)
    
    def run_mainvault(self):
        app = MainVault(self.root, "All Items", "AllItems", "all_items")
        app.run()
    
    def run(self):
        self.root.mainloop()

class CreateMasterPassword(CredentialManager):
    def __init__(self, root):
        self.root = root
        super().__init__(root)  # Call parent's __init__ after setting root
        self.setup_window()
        self.create_widgets()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def setup_window(self):
        self.root.title("Credential Manager - Create Master Password")
        
        # Get screen dimensions
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        
        # Set window size to 40% of screen size
        window_width = int(screen_width * 0.4)
        window_height = int(screen_height * 0.4)
        
        # Calculate window position for center placement
        x_position = (screen_width - window_width) // 2
        y_position = (screen_height - window_height) // 2
        
        # Set window geometry
        self.root.geometry(f"{window_width}x{window_height}+{x_position}+{y_position}")
        
        # Make window resizable
        self.root.resizable(True, True)
        
        # Configure grid weights
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(0, weight=1)
    
    def create_widgets(self):
        # Create main container
        main_container = ctk.CTkFrame(self.root, fg_color="#1a1a1a")
        main_container.grid(row=0, column=0, sticky="nsew", padx=40, pady=40)
        main_container.grid_columnconfigure(0, weight=1)
        main_container.grid_rowconfigure(1, weight=1)  # Make scrollable frame expandable
        
        # Style definitions
        title_style = {"font": title_type, "text_color": text_color}
        subtitle_style = {"font": subtitle_type, "text_color": text_color}
        entry_style = {
            "font": text_type,
            "text_color": text_color,
            "fg_color": txt_entry_fg_color,
            "height": 45,
            "width": 300
        }
        button_style = {
            "font": subtitle_type,
            "fg_color": button_fg_color,
            "text_color": text_color,
            "height": 45,
            "width": 200
        }
        
        # Title
        title = ctk.CTkLabel(
            main_container,
            text="Create Master Password",
            **title_style
        )
        title.grid(row=0, column=0, pady=(0, 20))
        
        # Create scrollable frame
        scroll_frame = ctk.CTkScrollableFrame(main_container, fg_color="transparent")
        scroll_frame.grid(row=1, column=0, sticky="nsew")
        scroll_frame.grid_columnconfigure(0, weight=1)
        
        # Create content frame inside scrollable frame
        content_frame = ctk.CTkFrame(scroll_frame, fg_color="transparent")
        content_frame.grid(row=0, column=0, sticky="nsew", pady=(0, 20))
        content_frame.grid_columnconfigure(0, weight=1)
        
        # Subtitle
        subtitle = ctk.CTkLabel(
            content_frame,
            text="Create a strong master password to secure your vault",
            **subtitle_style
        )
        subtitle.grid(row=0, column=0, pady=(0, 30))
        
        # Password requirements frame
        requirements_frame = ctk.CTkFrame(content_frame, fg_color="#242424")
        requirements_frame.grid(row=1, column=0, pady=(0, 20), padx=20, sticky="ew")
        
        requirements_text = (
            "Password Requirements:\n"
            "• At least 7 characters long\n"
            "• At least 1 number\n"
            "• At least 1 special character"
        )
        requirements_label = ctk.CTkLabel(
            requirements_frame,
            text=requirements_text,
            font=text_type,
            text_color=text_color,
            justify="left"
        )
        requirements_label.grid(row=0, column=0, padx=20, pady=15, sticky="w")
        
        # Entry frame
        entry_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        entry_frame.grid(row=2, column=0, pady=(0, 20))
        
        # Password entry
        password_label = ctk.CTkLabel(
            entry_frame,
            text="Enter Master Password:",
            **subtitle_style
        )
        password_label.grid(row=0, column=0, pady=(0, 10))
        
        self.password_entry = ctk.CTkEntry(
            entry_frame,
            placeholder_text="Enter password",
            show="•",
            **entry_style
        )
        self.password_entry.grid(row=1, column=0, pady=(0, 20))
        
        # Confirm password entry
        confirm_label = ctk.CTkLabel(
            entry_frame,
            text="Confirm Master Password:",
            **subtitle_style
        )
        confirm_label.grid(row=2, column=0, pady=(0, 10))
        
        self.confirm_password_entry = ctk.CTkEntry(
            entry_frame,
            placeholder_text="Confirm password",
            show="•",
            **entry_style
        )
        self.confirm_password_entry.grid(row=3, column=0, pady=(0, 20))
        
        # Submit button
        self.submit_button = ctk.CTkButton(
            entry_frame,
            text="Create Password",
            command=self.save_master_password,
            **button_style
        )
        self.submit_button.grid(row=4, column=0)
        
        # Status label (initially empty)
        self.status_label = ctk.CTkLabel(
            content_frame,
            text="",
            font=text_type,
            text_color="red"
        )
        self.status_label.grid(row=3, column=0, pady=(10, 0))
    
    def save_master_password(self):
        password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        
        # Reset status label
        self.status_label.configure(text="")
        
        # Password validation
        if not password or not confirm_password:
            self.status_label.configure(text="Please fill in all fields")
            return
        
        if password != confirm_password:
            self.status_label.configure(text="Passwords do not match")
            self.password_entry.delete(0, "end")
            self.confirm_password_entry.delete(0, "end")
            return
        
        if len(password) < 7:
            self.status_label.configure(text="Password must be at least 7 characters long")
            self.password_entry.delete(0, "end")
            self.confirm_password_entry.delete(0, "end")
            return
        
        if not re.search(r'\d', password):
            self.status_label.configure(text="Password must contain at least 1 number")
            self.password_entry.delete(0, "end")
            self.confirm_password_entry.delete(0, "end")
            return
        
        if not re.search(r'\W', password):
            self.status_label.configure(text="Password must contain at least 1 special character")
            self.password_entry.delete(0, "end")
            self.confirm_password_entry.delete(0, "end")
            return
        
        try:
            # If all validations pass, save the password
            hashed_password = self.hash_text(password.encode("utf-8"))
            encrypted_hashed_password = self.encrypt_password(hashed_password)
            
            with sqlite3.connect(MASTER_PASSWORD_DB) as db:
                cursor = db.cursor()
                cursor.execute("INSERT INTO master_password (password) VALUES (?)", (encrypted_hashed_password,))
                db.commit()
            
            self.status_label.configure(text="Master password created successfully!", text_color="green")
            self.root.after(1000, self.destroy_and_create_mainvault)
            
        except Exception as e:
            self.status_label.configure(text=f"Error creating password: {str(e)}")
    
    def destroy_and_create_mainvault(self):
        # Create MainVault instance first
        app = MainVault(parent=self.root)
        app.initialize_right_frame("All Items", "AllItems", "all_items")
        # Destroy the current window
        self.root.destroy()
        # Run the main vault
        app.run()
    
    def on_close(self):
        self.root.destroy()
        sys.exit()  # Add this to properly exit the program
    
    def run(self):
        self.root.mainloop()

class LoginScreen(CredentialManager):
    def __init__(self, root):
        self.root = root
        super().__init__(root)  # Call parent's __init__ after setting root
        self.setup_window()
        self.create_widgets()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def setup_window(self):
        self.root.title("Credential Manager - Login")
        
        # Get screen dimensions
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        
        # Set window size to 40% of screen size
        window_width = int(screen_width * 0.4)
        window_height = int(screen_height * 0.4)
        
        # Calculate window position for center placement
        x_position = (screen_width - window_width) // 2
        y_position = (screen_height - window_height) // 2
        
        # Set window geometry
        self.root.geometry(f"{window_width}x{window_height}+{x_position}+{y_position}")
        
        # Make window resizable
        self.root.resizable(True, True)
        
        # Configure grid weights
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(0, weight=1)
    
    def create_widgets(self):
        # Create main container
        main_container = ctk.CTkFrame(self.root, fg_color="#1a1a1a")
        main_container.grid(row=0, column=0, sticky="nsew", padx=40, pady=40)
        main_container.grid_columnconfigure(0, weight=1)
        main_container.grid_rowconfigure(1, weight=1)
        
        # Style definitions
        title_style = {"font": title_type, "text_color": text_color}
        subtitle_style = {"font": subtitle_type, "text_color": text_color}
        entry_style = {
            "font": text_type,
            "text_color": text_color,
            "fg_color": txt_entry_fg_color,
            "height": 45,
            "width": 300
        }
        button_style = {
            "font": subtitle_type,
            "fg_color": button_fg_color,
            "text_color": text_color,
            "height": 45,
            "width": 200
        }
        
        # Create content frame
        content_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        content_frame.grid(row=0, column=0, sticky="nsew", pady=(40, 0))
        content_frame.grid_columnconfigure(0, weight=1)
        
        # Title
        title = ctk.CTkLabel(
            content_frame,
            text="Welcome Back",
            **title_style
        )
        title.grid(row=0, column=0, pady=(0, 10))
        
        # Subtitle
        subtitle = ctk.CTkLabel(
            content_frame,
            text="Your vault is locked. Please verify your master password to continue.",
            **subtitle_style
        )
        subtitle.grid(row=1, column=0, pady=(0, 30))
        
        # Password entry frame
        entry_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        entry_frame.grid(row=2, column=0, pady=(0, 20))
        
        # Password entry
        self.password = ctk.CTkEntry(
            entry_frame,
            placeholder_text="Enter Master Password",
            show="•",
            **entry_style
        )
        self.password.grid(row=0, column=0, pady=(0, 20))
        
        # Unlock button
        self.unlock = ctk.CTkButton(
            entry_frame,
            text="Unlock Vault",
            command=self.verify_master_password,
            **button_style
        )
        self.unlock.grid(row=1, column=0)
        
        # Status label (initially empty)
        self.status_label = ctk.CTkLabel(
            content_frame,
            text="",
            font=text_type,
            text_color="red"
        )
        self.status_label.grid(row=3, column=0, pady=(10, 0))
    
    def is_master_password_present(self):
        pass  # Override parent's method to prevent recursion
    
    def get_master_password(self):
        try:
            # Get the entered password
            entered_password = self.password.get()
            if not entered_password:
                return False
            
            # Hash the entered password
            hashed_entered_password = self.hash_text(entered_password.encode("utf-8"))
            
            # Get the stored password from the database
            with sqlite3.connect(MASTER_PASSWORD_DB) as db:
                cursor = db.cursor()
                cursor.execute("SELECT password FROM master_password")
                stored_encrypted_password = cursor.fetchone()
                
                if stored_encrypted_password:
                    # Decrypt the stored password
                    stored_password = self.decrypt_password(stored_encrypted_password[0])
                    # Compare the hashed passwords
                    return hashed_entered_password == stored_password
            
            return False
            
        except Exception as e:
            print(f"Error verifying master password: {e}")
            return False
    
    def verify_master_password(self):
        # Verify if the entered password matches the stored password
        match = self.get_master_password()
        if match:
            # Create MainVault instance first
            app = MainVault(parent=self.root)
            app.initialize_right_frame("All Items", "AllItems", "all_items")
            # Destroy the login screen window
            self.root.destroy()
            # Run the main vault
            app.run()
        else:
            self.status_label.configure(text="Incorrect password. Please try again.")
            self.password.delete(0, 'end')
            self.root.after(3000, lambda: self.status_label.configure(text=""))  # Clear after 3 seconds
    
    def destroy_and_create_mainvault(self):
        self.cleanup_widgets()
        app = MainVault(parent=self.root)  # Only pass parent parameter
        app.initialize_right_frame("All Items", "AllItems", "all_items")  # Initialize with default view
        app.run()
    
    def cleanup_widgets(self):
        for widget in self.root.winfo_children():
            widget.destroy()
    
    def on_close(self):
        self.cleanup_widgets()
        self.root.destroy()
        sys.exit()  # Add this to properly exit the program
    
    def run_after_lock(self):
        self.root.mainloop()
    
    def run(self):
        self.root.mainloop()

class MainVault(CredentialManager):
    _instance = None
    
    def __new__(cls, parent=None):
        if cls._instance is None:
            cls._instance = super(MainVault, cls).__new__(cls)
        return cls._instance
    
    def __init__(self, parent=None):
        if hasattr(self, 'root'):
            return
        self.parent = parent
        self.root = ctk.CTk()
        super().__init__(self.root)
        
        # Initialize pagination attributes
        self.current_page = 1
        self.items_per_page = 10  # Number of items to display per page
        
        self.initialize_root_window()
        self.initialize_left_frame()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def refresh_theme(self):
        """Refresh the theme of all widgets in the main vault."""
        try:
            # Update button styles
            button_style = {
                "font": subtitle_type,
                "fg_color": button_fg_color,
                "text_color": text_color,
                "height": 40
            }
            
            # Update left frame buttons
            for button in self.left_frame.winfo_children():
                if isinstance(button, ctk.CTkButton):
                    button.configure(**button_style)
            
            # Update right frame widgets
            # Header frame
            self.header_title.configure(font=title_type, text_color=text_color)
            self.search_entry.configure(font=text_type, text_color=text_color)
            self.search_button.configure(**button_style)
            
            # Column headers
            for label in self.header_bar.winfo_children():
                if isinstance(label, ctk.CTkLabel):
                    label.configure(font=subtitle_type, text_color=text_color)
            
            # Credential entries
            for entry in self.credentials_canvas.winfo_children():
                if isinstance(entry, ctk.CTkFrame):
                    for widget in entry.winfo_children():
                        if isinstance(widget, ctk.CTkLabel):
                            widget.configure(font=text_type, text_color=text_color)
                        elif isinstance(widget, ctk.CTkButton):
                            widget.configure(**button_style)
            
            # Pagination controls
            for button in self.pagination_frame.winfo_children():
                if isinstance(button, ctk.CTkButton):
                    button.configure(**button_style)
            
            # Update canvas background
            self.credentials_canvas.configure(fg_color="#1a1a1a")
            
            # Update frames
            self.left_frame.configure(fg_color="#242424")
            self.right_frame.configure(fg_color="#1a1a1a")
            self.header_frame.configure(fg_color="#242424")
            self.header_bar.configure(fg_color="#242424")
            
            # Refresh the canvas
            self.credentials_canvas.update_idletasks()
            
        except Exception as e:
            print(f"Error refreshing theme: {e}")
    
    def edit_credential(self, record):
        """Open the edit credential window for the selected record."""
        try:
            # Determine which database and table to use based on current view
            database = "AllItems" if self.window_title == "All Items" else "Favourites"
            table = "all_items" if database == "AllItems" else "favourites"
            
            # Create and run the edit window
            edit_window = EditCredential(
                parent=self,
                database=database,
                table=table,
                record=record
            )
            edit_window.run()
            
            # Refresh the credentials display after editing
            self.load_credentials("website", database, table)
            
        except Exception as e:
            print(f"Error opening edit window: {e}")
            self.popup(self.root, f"Error opening edit window: {str(e)}")

    def clear_credentials(self):
        # Clear all widgets from the scrollable frame
        if hasattr(self, 'scrollable_frame'):
            for widget in self.scrollable_frame.winfo_children():
                widget.destroy()

    def load_credentials(self, sort_by, database, table):
        # Clear previous credentials displayed
        self.clear_credentials()
        
        # Determine which database to use
        db_path = ALL_ITEMS_DB if database == "AllItems" else FAVOURITES_DB
        
        # Calculate offset for pagination
        offset = (self.current_page - 1) * self.items_per_page
        
        try:
            # Fetch credentials from database with pagination
            with sqlite3.connect(db_path) as db:
                cursor = db.cursor()
                cursor.execute(f"SELECT * FROM {table} ORDER BY {sort_by} LIMIT {self.items_per_page} OFFSET {offset}")
                rows = cursor.fetchall()
                
                # Create a frame for each credential
                for row_idx, row in enumerate(rows):
                    # Create a frame for each row with alternating background
                    frame = ctk.CTkFrame(
                        self.scrollable_frame,
                        fg_color="#242424" if row_idx % 2 == 0 else "#1a1a1a",
                        height=50  # Fixed height for consistent row size
                    )
                    frame.grid(row=row_idx, column=0, sticky="ew", padx=0, pady=1)
                    frame.grid_propagate(False)  # Prevent frame from shrinking
                    
                    # Configure column weights for consistent spacing
                    frame.grid_columnconfigure(0, weight=3)  # Website (30%)
                    frame.grid_columnconfigure(1, weight=3)  # Username (30%)
                    frame.grid_columnconfigure(2, weight=2)  # Password (20%)
                    frame.grid_columnconfigure(3, weight=2)  # Actions (20%)
                    
                    # Website column
                    website_label = ctk.CTkLabel(
                        frame,
                        text=row[1],  # Website
                        font=text_type,
                        text_color=text_color,
                        anchor="w"
                    )
                    website_label.grid(row=0, column=0, sticky="ew", padx=(20, 10), pady=5)
                    
                    # Username column
                    username_label = ctk.CTkLabel(
                        frame,
                        text=row[2],  # Username
                        font=text_type,
                        text_color=text_color,
                        anchor="w"
                    )
                    username_label.grid(row=0, column=1, sticky="ew", padx=10, pady=5)
                    
                    # Password column with show/hide functionality
                    password_var = ctk.StringVar(value="********")
                    password_label = ctk.CTkLabel(
                        frame,
                        textvariable=password_var,
                        font=text_type,
                        text_color=text_color,
                        anchor="w"
                    )
                    password_label.grid(row=0, column=2, sticky="ew", padx=10, pady=5)
                    
                    show_password_btn = ctk.CTkButton(
                        frame,
                        text="👁",
                        width=30,
                        height=25,
                        command=lambda p=row[3], v=password_var: self.toggle_password_visibility(p, v),
                        font=text_type,
                        fg_color=button_fg_color,
                        text_color=text_color
                    )
                    show_password_btn.grid(row=0, column=2, sticky="e", padx=(0, 10), pady=5)
                    
                    # Actions column
                    actions_frame = ctk.CTkFrame(frame, fg_color="transparent")
                    actions_frame.grid(row=0, column=3, sticky="e", padx=(10, 20), pady=5)
                    
                    # Action buttons with consistent sizing
                    button_style = {
                        "font": text_type,
                        "fg_color": button_fg_color,
                        "text_color": text_color,
                        "height": 25  # Smaller height for better alignment
                    }
                    
                    edit_button = ctk.CTkButton(
                        actions_frame,
                        text="Edit",
                        width=60,
                        command=lambda r=row: self.edit_credential(r),
                        **button_style
                    )
                    edit_button.pack(side="left", padx=5)
                    
                    delete_button = ctk.CTkButton(
                        actions_frame,
                        text="Delete",
                        width=60,
                        command=lambda r=row: self.delete_record(r[0], database, table),
                        **button_style
                    )
                    delete_button.pack(side="left", padx=5)
                    
                    if database == "AllItems":
                        favorite_button = ctk.CTkButton(
                            actions_frame,
                            text="★",
                            width=35,
                            command=lambda r=row: self.favorite_record(r),
                            **button_style
                        )
                        favorite_button.pack(side="left", padx=5)
        
        except Exception as e:
            print(f"Error in load_credentials: {e}")
            self.popup(self.root, f"Error loading credentials: {str(e)}")

    def favorite_record(self, record_array):
        try:
            # Check if record already exists in favorites
            with sqlite3.connect(FAVOURITES_DB) as db:
                cursor = db.cursor()
                cursor.execute("""
                    SELECT COUNT(*) FROM favourites 
                    WHERE website = ? AND username = ? AND password = ?
                """, (record_array[1], record_array[2], record_array[3]))
                exists = cursor.fetchone()[0] > 0
                
                if exists:
                    self.popup(self.root, "This credential is already in favorites")
                    return
                
                # If not in favorites, add it
                cursor.execute("""
                    INSERT INTO favourites (title, username, password, website, notes) 
                    VALUES (?, ?, ?, ?, ?)
                """, (record_array[1], record_array[2], record_array[3], record_array[4], record_array[5]))
                db.commit()
                self.popup(self.root, "Added to Favorites")
                
        except Exception as e:
            print(f"Error in favorite_record: {e}")
            self.popup(self.root, f"Error adding to favorites: {str(e)}")

    def delete_record(self, row_value, database, table):
        # Determine which database to use
        db_path = ALL_ITEMS_DB if database == "AllItems" else FAVOURITES_DB
        
        # Delete record from database
        with sqlite3.connect(db_path) as db:
            cursor = db.cursor()
            cursor.execute(f"DELETE FROM {table} WHERE id = ?", (row_value,))
            db.commit()
        self.load_credentials("id", database, table)

    def show_login_screen(self):
        # This method creates a new root window for the LoginScreen and displays it
        new_root = ctk.CTk()
        login_screen = LoginScreen(new_root)
        login_screen.run_after_lock()

    def on_close(self):
        MainVault._instance = None
        self.root.destroy()
        sys.exit()  # Add this to properly exit the program

    def run(self):
        # Start the mainloop
        self.root.mainloop()

    def initialize_root_window(self):
        # Clearing the root window
        for widget in self.root.winfo_children():
            widget.destroy()
            
        self.root.title("Credential Manager")
        
        # Get screen dimensions
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        
        # Set window size to 90% of screen size
        self.root_width = int(screen_width * 0.9)
        self.root_height = int(screen_height * 0.9)
        
        # Calculate window position for center placement
        x_position = (screen_width - self.root_width) // 2
        y_position = (screen_height - self.root_height) // 2
        
        # Set window geometry
        self.root.geometry(f"{self.root_width}x{self.root_height}+{x_position}+{y_position}")
        
        # Make window resizable
        self.root.resizable(True, True)
        
        # Configure grid weights for root window
        self.root.grid_columnconfigure(1, weight=1)  # Make right frame expandable
        self.root.grid_rowconfigure(0, weight=1)     # Make row expandable
        
        # Bind resize event
        self.root.bind("<Configure>", self.on_window_resize)

    def on_window_resize(self, event):
        # Only handle root window resize events
        if event.widget == self.root:
            # Update dimensions
            self.root_width = event.width
            self.root_height = event.height
            
            # Update left frame width (20% of window width)
            self.left_frame_width = int(self.root_width * 0.2)
            self.left_frame.configure(width=self.left_frame_width)
            
            # Update right frame width
            self.right_frame_width = self.root_width - self.left_frame_width
            self.right_frame.configure(width=self.right_frame_width)
            
            # Update canvas width
            if hasattr(self, 'canvas'):
                self.canvas.configure(width=self.right_frame_width - 40)  # 40px for padding
                self.canvas.itemconfig(self.canvas_frame, width=self.right_frame_width - 60)  # 60px for scrollbar

    def initialize_left_frame(self):
        # Calculate left frame width as 20% of window width
        self.left_frame_width = int(self.root_width * 0.2)
        self.left_frame_height = self.root_height
        
        left_frame_color = "#0f0f0f"
        button_style = {
            "font": subtitle_type,
            "fg_color": left_frame_color,
            "border_width": button_border_width,
            "border_color": left_frame_color,
            "text_color": text_color,
            "height": 40  # Fixed height for buttons
        }
        
        frame_style = {"fg_color": left_frame_color}
        
        # Create and configure left frame
        self.left_frame = ctk.CTkFrame(
            self.root,
            width=self.left_frame_width,
            height=self.left_frame_height,
            **frame_style
        )
        self.left_frame.grid(row=0, column=0, sticky="nsew")
        self.left_frame.grid_propagate(False)
        
        # Configure grid weights for left frame
        self.left_frame.grid_columnconfigure(0, weight=1)  # Make column expandable
        
        # Create buttons with consistent spacing
        buttons = [
            ("All Items", lambda: self.initialize_right_frame("All Items", "AllItems", "all_items")),
            ("Favourites", lambda: self.initialize_right_frame("Favourites", "Favourites", "Favourites")),
            ("Random Password Generator", self.run_random_password_generator),
            ("Settings", self.run_settings),
            ("Import/Export", self.run_filemanager),
            ("Help", self.run_additional_information)
        ]
        
        for idx, (text, command) in enumerate(buttons):
            btn = ctk.CTkButton(
                self.left_frame,
                text=text,
                command=command,
                **button_style
            )
            btn.grid(row=idx, column=0, padx=10, pady=10, sticky="ew")

    def initialize_right_frame(self, window_title, database, table):
        # Clear everything in the root window except the left frame
        self.clear_right_widgets()
        
        # Calculate right frame dimensions
        self.right_frame_width = self.root_width - self.left_frame_width
        self.right_frame_height = self.root_height
        self.window_title = window_title

        # Initialize the right frame with a consistent background color
        self.right_frame = ctk.CTkFrame(
            self.root,
            width=self.right_frame_width,
            height=self.right_frame_height,
            fg_color="#1a1a1a"
        )
        self.right_frame.grid(row=0, column=1, sticky="nsew")
        self.right_frame.grid_propagate(False)
        
        # Configure grid for right frame
        self.right_frame.grid_columnconfigure(0, weight=1)
        self.right_frame.grid_rowconfigure(2, weight=1)  # Make scrollable area expandable
        
        # Create header frame with dynamic sizing
        header_frame = ctk.CTkFrame(self.right_frame, fg_color="transparent")
        header_frame.grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 10))
        header_frame.grid_columnconfigure(1, weight=1)  # Make search bar expandable
        
        # Create title and add button container
        title_container = ctk.CTkFrame(header_frame, fg_color="transparent")
        title_container.grid(row=0, column=0, sticky="w")
        title_container.grid_columnconfigure(1, weight=1)
        
        # Create title label
        self.title_label = ctk.CTkLabel(
            title_container,
            text=window_title,
            font=title_type,
            text_color=text_color,
            fg_color="transparent"
        )
        self.title_label.grid(row=0, column=0, sticky="w", padx=(0, 20))
        
        # Add Credential button
        add_button = ctk.CTkButton(
            title_container,
            text="+ Add Credential",
            width=120,
            height=35,
            command=lambda: self.run_add_credentials(),
            font=text_type,
            fg_color=button_fg_color,
            text_color=text_color
        )
        add_button.grid(row=0, column=1, sticky="w")
        
        # Create search frame with dynamic sizing
        search_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        search_frame.grid(row=0, column=1, sticky="e")
        search_frame.grid_columnconfigure(0, weight=1)
        
        # Create search entry
        self.search_entry = ctk.CTkEntry(
            search_frame,
            placeholder_text="Search credentials...",
            width=200,
            height=35,
            font=text_type,
            text_color=text_color,
            fg_color=txt_entry_fg_color
        )
        self.search_entry.grid(row=0, column=0, sticky="e", padx=(0, 10))
        
        # Create search button
        search_button = ctk.CTkButton(
            search_frame,
            text="Search",
            width=80,
            height=35,
            command=lambda: self.search_credentials(database, table),
            font=text_type,
            fg_color=button_fg_color,
            text_color=text_color
        )
        search_button.grid(row=0, column=1, sticky="e")
        
        # Bind Enter key to search
        self.search_entry.bind("<Return>", lambda e: self.search_credentials(database, table))
        
        # Create header bar with dynamic sizing
        header_bar = ctk.CTkFrame(self.right_frame, fg_color="#242424", height=40)
        header_bar.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 10))
        header_bar.grid_propagate(False)  # Prevent header from shrinking
        
        # Configure header bar columns with dynamic weights
        header_bar.grid_columnconfigure(0, weight=3)  # Website (30%)
        header_bar.grid_columnconfigure(1, weight=3)  # Username (30%)
        header_bar.grid_columnconfigure(2, weight=2)  # Password (20%)
        header_bar.grid_columnconfigure(3, weight=2)  # Actions (20%)
        
        # Add column headers with consistent styling and padding
        header_style = {"font": subtitle_type, "text_color": text_color}
        
        # Create headers with dynamic sizing and consistent padding
        headers = [
            ("Website", lambda: self.load_credentials("website", database, table)),
            ("Username", lambda: self.load_credentials("username", database, table)),
            ("Password", None),
            ("Actions", None)
        ]
        
        for idx, (text, command) in enumerate(headers):
            header_frame = ctk.CTkFrame(header_bar, fg_color="transparent")
            header_frame.grid(row=0, column=idx, sticky="ew", padx=20 if idx == 0 else (10, 20 if idx == 3 else 10))
            header_frame.grid_columnconfigure(0, weight=1)
            
            if command:  # Clickable header
                header = ctk.CTkButton(
                    header_frame,
                    text=text,
                    fg_color="transparent",
                    border_width=0,
                    command=command,
                    **header_style
                )
            else:  # Static header
                header = ctk.CTkLabel(
                    header_frame,
                    text=text,
                    **header_style
                )
            header.grid(row=0, column=0, sticky="w")
        
        # Initialize scrollable frame
        self.initialize_scrollable_frame(database, table)
        
        # Initialize pagination controls
        self.initialize_lifted_widgets(database, table)

    def initialize_scrollable_frame(self, database, table):
        # Create a container frame for the scrollable area
        scroll_container = ctk.CTkFrame(self.right_frame, fg_color="transparent")
        scroll_container.grid(row=2, column=0, sticky="nsew", padx=20)
        scroll_container.grid_columnconfigure(0, weight=1)
        scroll_container.grid_rowconfigure(0, weight=1)
        
        # Create a canvas with scrollbar
        self.canvas = ctk.CTkCanvas(
            scroll_container,
            bg="#1a1a1a",
            highlightthickness=0,
            width=self.right_frame_width - 40  # Set initial width
        )
        self.canvas.grid(row=0, column=0, sticky="nsew")
        
        # Create scrollbar
        self.scrollbar = ctk.CTkScrollbar(
            scroll_container,
            orientation="vertical",
            command=self.canvas.yview
        )
        self.scrollbar.grid(row=0, column=1, sticky="ns")
        
        # Configure canvas
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        
        # Create scrollable frame with proper width
        self.scrollable_frame = ctk.CTkFrame(self.canvas, fg_color="transparent")
        self.canvas_frame = self.canvas.create_window(
            (0, 0),
            window=self.scrollable_frame,
            anchor="nw",
            width=self.right_frame_width - 60  # Account for scrollbar and padding
        )
        
        # Configure grid weights for scrollable frame
        self.scrollable_frame.grid_columnconfigure(0, weight=2)  # Website
        self.scrollable_frame.grid_columnconfigure(1, weight=2)  # Username
        self.scrollable_frame.grid_columnconfigure(2, weight=1)  # Password
        self.scrollable_frame.grid_columnconfigure(3, weight=1)  # Actions
        
        # Bind events
        self.scrollable_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", self.on_canvas_configure)
        self.canvas.bind_all("<MouseWheel>", self.on_mousewheel)
        
        # Load initial credentials
        self.load_credentials("website", database, table)

    def initialize_lifted_widgets(self, database, table):
        # Create a frame for pagination controls
        pagination_frame = ctk.CTkFrame(self.right_frame, fg_color="transparent")
        pagination_frame.grid(row=3, column=0, sticky="ew", padx=20, pady=10)
        pagination_frame.grid_columnconfigure(1, weight=1)  # Make middle column expandable
        
        # Add pagination buttons with consistent styling
        button_style = {
            "font": text_type,
            "fg_color": button_fg_color,
            "text_color": text_color,
            "width": 100
        }
        
        prev_button = ctk.CTkButton(
            pagination_frame,
            text="Previous",
            command=lambda: self.change_page(-1, database, table),
            **button_style
        )
        prev_button.grid(row=0, column=0, padx=5)
        
        # Add page indicator label
        self.page_indicator = ctk.CTkLabel(
            pagination_frame,
            text=f"Page {self.current_page}",
            font=text_type,
            text_color=text_color
        )
        self.page_indicator.grid(row=0, column=1, padx=10)
        
        next_button = ctk.CTkButton(
            pagination_frame,
            text="Next",
            command=lambda: self.change_page(1, database, table),
            **button_style
        )
        next_button.grid(row=0, column=2, padx=5)

    def on_canvas_configure(self, event):
        # Update the scroll region to encompass the inner frame
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        # Update the canvas window width to match the canvas width
        self.canvas.itemconfig(self.canvas_frame, width=event.width)

    def on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def change_page(self, direction, database, table):
        # Update current page
        self.current_page += direction
        if self.current_page < 1:
            self.current_page = 1
        # Update page indicator
        self.page_indicator.configure(text=f"Page {self.current_page}")
        # Reload credentials with new page number
        self.load_credentials("website", database, table)

    def clear_right_widgets(self):
        # Iterate over all children widgets of the root window
        for widget in self.root.winfo_children():
            # Check if the widget is not the left frame
            if widget != self.left_frame:
                # Destroy the widget
                widget.destroy()

    def is_master_password_present(self):
        pass

    def run_add_credentials(self):
        app = AddCredential(parent=self)
        app.run()

    def run_settings(self):
        app = Settings(parent=self.root)
        app.run()

    def run_filemanager(self):
        app = FileManager(parent=self)
        app.run()

    def run_random_password_generator(self):
        app = RandomPasswordGenerator(parent=self.root)
        app.run()

    def run_additional_information(self):
        app = AdditionalInformation()
        app.run()

    def lock_vault(self):
        self.root.destroy()
        self.show_login_screen()

    def search_credentials(self, database, table):
        """Search credentials based on the search entry text."""
        search_text = self.search_entry.get().lower()
        if not search_text:
            # If search is empty, reload all credentials
            self.load_credentials("website", database, table)
            return
        
        # Clear previous credentials
        self.clear_credentials()
        
        # Determine which database to use
        db_path = ALL_ITEMS_DB if database == "AllItems" else FAVOURITES_DB
        
        try:
            # Search in database
            with sqlite3.connect(db_path) as db:
                cursor = db.cursor()
                cursor.execute(f"""
                    SELECT * FROM {table}
                    WHERE LOWER(website) LIKE ? OR LOWER(username) LIKE ?
                    ORDER BY website
                """, (f"%{search_text}%", f"%{search_text}%"))
                rows = cursor.fetchall()
                
                # Display search results
                for row_idx, row in enumerate(rows):
                    # Create a frame for each row with alternating background
                    frame = ctk.CTkFrame(
                        self.scrollable_frame,
                        fg_color="#242424" if row_idx % 2 == 0 else "#1a1a1a",
                        height=50  # Fixed height for consistent row size
                    )
                    frame.grid(row=row_idx, column=0, sticky="ew", padx=0, pady=1)
                    frame.grid_propagate(False)  # Prevent frame from shrinking
                    
                    # Configure column weights for consistent spacing
                    frame.grid_columnconfigure(0, weight=3)  # Website (30%)
                    frame.grid_columnconfigure(1, weight=3)  # Username (30%)
                    frame.grid_columnconfigure(2, weight=2)  # Password (20%)
                    frame.grid_columnconfigure(3, weight=2)  # Actions (20%)
                    
                    # Website column
                    website_label = ctk.CTkLabel(
                        frame,
                        text=row[1],  # Website
                        font=text_type,
                        text_color=text_color,
                        anchor="w"
                    )
                    website_label.grid(row=0, column=0, sticky="ew", padx=(20, 10), pady=5)
                    
                    # Username column
                    username_label = ctk.CTkLabel(
                        frame,
                        text=row[2],  # Username
                        font=text_type,
                        text_color=text_color,
                        anchor="w"
                    )
                    username_label.grid(row=0, column=1, sticky="ew", padx=10, pady=5)
                    
                    # Password column with show/hide functionality
                    password_var = ctk.StringVar(value="********")
                    password_label = ctk.CTkLabel(
                        frame,
                        textvariable=password_var,
                        font=text_type,
                        text_color=text_color,
                        anchor="w"
                    )
                    password_label.grid(row=0, column=2, sticky="ew", padx=10, pady=5)
                    
                    show_password_btn = ctk.CTkButton(
                        frame,
                        text="👁",
                        width=30,
                        height=25,
                        command=lambda p=row[3], v=password_var: self.toggle_password_visibility(p, v),
                        font=text_type,
                        fg_color=button_fg_color,
                        text_color=text_color
                    )
                    show_password_btn.grid(row=0, column=2, sticky="e", padx=(0, 10), pady=5)
                    
                    # Actions column
                    actions_frame = ctk.CTkFrame(frame, fg_color="transparent")
                    actions_frame.grid(row=0, column=3, sticky="e", padx=(10, 20), pady=5)
                    
                    # Action buttons with consistent sizing
                    button_style = {
                        "font": text_type,
                        "fg_color": button_fg_color,
                        "text_color": text_color,
                        "height": 25  # Smaller height for better alignment
                    }
                    
                    edit_button = ctk.CTkButton(
                        actions_frame,
                        text="Edit",
                        width=60,
                        command=lambda r=row: self.edit_credential(r),
                        **button_style
                    )
                    edit_button.pack(side="left", padx=5)
                    
                    delete_button = ctk.CTkButton(
                        actions_frame,
                        text="Delete",
                        width=60,
                        command=lambda r=row: self.delete_record(r[0], database, table),
                        **button_style
                    )
                    delete_button.pack(side="left", padx=5)
                    
                    if database == "AllItems":
                        favorite_button = ctk.CTkButton(
                            actions_frame,
                            text="★",
                            width=35,
                            command=lambda r=row: self.favorite_record(r),
                            **button_style
                        )
                        favorite_button.pack(side="left", padx=5)
        
        except Exception as e:
            self.popup(self.root, f"Error searching credentials: {str(e)}")

    def toggle_password_visibility(self, encrypted_password, password_var):
        """Toggle password visibility between asterisks and actual password."""
        current_text = password_var.get()
        if current_text == "********":
            try:
                # Decrypt and show password
                decrypted_password = self.decrypt_password(encrypted_password)
                password_var.set(decrypted_password)
            except Exception as e:
                print(f"Error decrypting password: {e}")
                self.popup(self.root, "Error decrypting password")
        else:
            # Hide password
            password_var.set("********")

class RandomPasswordGenerator(CredentialManager):
    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(RandomPasswordGenerator, cls).__new__(cls)
        return cls._instance
    
    def __init__(self, parent=None):
        if hasattr(self, 'root'):
            return
        self.parent = parent
        self.root = ctk.CTk()
        super().__init__(self.root)
        self.setup_window()
        self.create_widgets()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def setup_window(self):
        self.root.title("Credential Manager - Password Generator")
        self.root.attributes('-topmost', True)
        
        # Get screen dimensions
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        
        # Set window size to 50% of screen size
        window_width = int(screen_width * 0.5)
        window_height = int(screen_height * 0.5)
        
        # Calculate window position for center placement
        x_position = (screen_width - window_width) // 2
        y_position = (screen_height - window_height) // 2
        
        # Set window geometry
        self.root.geometry(f"{window_width}x{window_height}+{x_position}+{y_position}")
        
        # Make window resizable
        self.root.resizable(True, True)
        
        # Configure grid weights
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(0, weight=1)
    
    def create_widgets(self):
        # Create main container
        main_container = ctk.CTkFrame(self.root, fg_color="#1a1a1a")
        main_container.grid(row=0, column=0, sticky="nsew", padx=40, pady=40)
        main_container.grid_columnconfigure(0, weight=3)  # Generator section
        main_container.grid_columnconfigure(1, weight=1)  # Options section
        main_container.grid_rowconfigure(0, weight=1)
        
        # Style definitions
        title_style = {"font": title_type, "text_color": text_color}
        subtitle_style = {"font": subtitle_type, "text_color": text_color}
        text_style = {"font": text_type, "text_color": text_color}
        button_style = {
            "font": subtitle_type,
            "fg_color": button_fg_color,
            "text_color": text_color,
            "height": 40
        }
        checkbox_style = {
            "font": text_type,
            "text_color": text_color,
            "fg_color": "#242424",
            "hover_color": button_fg_color
        }
        
        # Left frame for password generator
        generator_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        generator_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 20))
        generator_frame.grid_columnconfigure(0, weight=1)
        
        # Title
        title = ctk.CTkLabel(
            generator_frame,
            text="Password Generator",
            **title_style
        )
        title.grid(row=0, column=0, sticky="w", pady=(0, 20))
        
        # Password length section
        length_frame = ctk.CTkFrame(generator_frame, fg_color="#242424")
        length_frame.grid(row=1, column=0, sticky="ew", pady=(0, 20))
        length_frame.grid_columnconfigure(0, weight=1)
        
        self.slider_label = ctk.CTkLabel(
            length_frame,
            text="Password Length: 25",
            **subtitle_style
        )
        self.slider_label.grid(row=0, column=0, sticky="w", padx=20, pady=(15, 10))
        
        self.slider = ctk.CTkSlider(
            length_frame,
            from_=1,
            to=50,
            number_of_steps=50,
            command=self.slider_event,
            fg_color=button_fg_color,
            button_color=button_fg_color,
            button_hover_color=button_fg_color,
            width=400
        )
        self.slider.grid(row=1, column=0, padx=20, pady=(0, 15))
        
        # Generated password section
        password_frame = ctk.CTkFrame(generator_frame, fg_color="#242424")
        password_frame.grid(row=2, column=0, sticky="ew", pady=(0, 20))
        password_frame.grid_columnconfigure(0, weight=1)
        
        self.generated_password_label = ctk.CTkLabel(
            password_frame,
            text="Generated Password:",
            **subtitle_style
        )
        self.generated_password_label.grid(row=0, column=0, sticky="w", padx=20, pady=(15, 10))
        
        # Buttons frame
        buttons_frame = ctk.CTkFrame(generator_frame, fg_color="transparent")
        buttons_frame.grid(row=3, column=0, sticky="ew", pady=(0, 20))
        buttons_frame.grid_columnconfigure(0, weight=1)
        buttons_frame.grid_columnconfigure(1, weight=1)
        
        generate_btn = ctk.CTkButton(
            buttons_frame,
            text="Generate Password",
            command=self.update_random_password,
            **button_style
        )
        generate_btn.grid(row=0, column=0, padx=(0, 10))
        
        copy_password_btn = ctk.CTkButton(
            buttons_frame,
            text="Copy to Clipboard",
            command=self.copytext,
            **button_style
        )
        copy_password_btn.grid(row=0, column=1, padx=(10, 0))
        
        # Right frame for options
        options_frame = ctk.CTkFrame(main_container, fg_color="#242424")
        options_frame.grid(row=0, column=1, sticky="nsew")
        options_frame.grid_columnconfigure(0, weight=1)
        
        # Options title
        options_title = ctk.CTkLabel(
            options_frame,
            text="Password Options",
            **subtitle_style
        )
        options_title.grid(row=0, column=0, sticky="w", padx=20, pady=(20, 20))
        
        # Checkboxes
        self.uppercase_var = IntVar(value=1)
        self.lowercase_var = IntVar(value=1)
        self.numbers_var = IntVar(value=1)
        self.symbols_var = IntVar(value=1)
        
        uppercase_btn = ctk.CTkCheckBox(
            options_frame,
            text="Uppercase Letters (A-Z)",
            variable=self.uppercase_var,
            **checkbox_style
        )
        uppercase_btn.grid(row=1, column=0, sticky="w", padx=20, pady=10)
        
        lowercase_btn = ctk.CTkCheckBox(
            options_frame,
            text="Lowercase Letters (a-z)",
            variable=self.lowercase_var,
            **checkbox_style
        )
        lowercase_btn.grid(row=2, column=0, sticky="w", padx=20, pady=10)
        
        numbers_btn = ctk.CTkCheckBox(
            options_frame,
            text="Numbers (0-9)",
            variable=self.numbers_var,
            **checkbox_style
        )
        numbers_btn.grid(row=3, column=0, sticky="w", padx=20, pady=10)
        
        symbols_btn = ctk.CTkCheckBox(
            options_frame,
            text="Special Characters (!@#$%^&*)",
            variable=self.symbols_var,
            **checkbox_style
        )
        symbols_btn.grid(row=4, column=0, sticky="w", padx=20, pady=10)
        
        # Status label
        self.status_label = ctk.CTkLabel(
            generator_frame,
            text="",
            font=text_type,
            text_color="red"
        )
        self.status_label.grid(row=4, column=0, sticky="w", pady=(10, 0))
    
    def slider_event(self, value):
        value_int = int(value)
        formatted_value = f"{value_int:02d}"
        self.slider_label.configure(text=f"Password Length: {formatted_value}")
    
    def update_random_password(self):
        length = int(self.slider.get())
        character_sets = []
        
        if self.uppercase_var.get():
            character_sets.append(string.ascii_uppercase)
        if self.lowercase_var.get():
            character_sets.append(string.ascii_lowercase)
        if self.numbers_var.get():
            character_sets.append(string.digits)
        if self.symbols_var.get():
            character_sets.append(string.punctuation)
        
        if character_sets:
            alphabet = ''.join(character_sets)
            generated_password = ''.join(secrets.choice(alphabet) for _ in range(length))
            self.generated_password_label.configure(text=f"Generated Password:\n{generated_password}")
            self.status_label.configure(text="")
        else:
            self.status_label.configure(text="Please select at least one character set")
    
    def copytext(self):
        generated_password = self.generated_password_label.cget("text")
        lines = generated_password.split('\n')
        if len(lines) >= 2:
            password = lines[1]
            pyperclip.copy(password)
            self.status_label.configure(text="Password copied to clipboard!", text_color="green")
            self.root.after(2000, lambda: self.status_label.configure(text=""))
        else:
            self.status_label.configure(text="No password generated yet")
    
    def on_close(self):
        RandomPasswordGenerator._instance = None
        self.root.destroy()
    
    def run(self):
        self.root.mainloop()

class Settings(CredentialManager):
    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(Settings, cls).__new__(cls)
        return cls._instance
    
    def __init__(self, parent=None):
        if hasattr(self, 'root'):
            return
        self.parent = parent
        self.root = ctk.CTk()
        super().__init__(self.root)
        self.setup_window()
        self.create_widgets()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def setup_window(self):
        self.root.title("Credential Manager - Settings")
        self.root.attributes('-topmost', True)
        
        # Get screen dimensions
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        
        # Set window size to 40% of screen size
        window_width = int(screen_width * 0.4)
        window_height = int(screen_height * 0.4)
        
        # Calculate window position for center placement
        x_position = (screen_width - window_width) // 2
        y_position = (screen_height - window_height) // 2
        
        # Set window geometry
        self.root.geometry(f"{window_width}x{window_height}+{x_position}+{y_position}")
        
        # Make window resizable
        self.root.resizable(True, True)
        
        # Configure grid weights
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(0, weight=1)
    
    def create_widgets(self):
        # Create main container
        main_container = ctk.CTkFrame(self.root, fg_color="#1a1a1a")
        main_container.grid(row=0, column=0, sticky="nsew", padx=40, pady=40)
        main_container.grid_columnconfigure(0, weight=1)
        main_container.grid_rowconfigure(1, weight=1)  # Make scrollable frame expandable
        
        # Style definitions
        title_style = {"font": title_type, "text_color": text_color}
        subtitle_style = {"font": subtitle_type, "text_color": text_color}
        text_style = {"font": text_type, "text_color": text_color}
        button_style = {
            "font": subtitle_type,
            "fg_color": button_fg_color,
            "text_color": text_color,
            "height": 40
        }
        radio_style = {
            "font": text_type,
            "text_color": text_color,
            "fg_color": "#242424",
            "hover_color": button_fg_color
        }
        
        # Title
        title = ctk.CTkLabel(main_container, text="Settings", **title_style)
        title.grid(row=0, column=0, sticky="w", pady=(0, 20))
        
        # Create scrollable frame
        scroll_frame = ctk.CTkScrollableFrame(main_container, fg_color="transparent")
        scroll_frame.grid(row=1, column=0, sticky="nsew")
        scroll_frame.grid_columnconfigure(0, weight=1)
        
        # Theme section
        theme_frame = ctk.CTkFrame(scroll_frame, fg_color="#242424")
        theme_frame.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        theme_frame.grid_columnconfigure(0, weight=1)
        
        theme_label = ctk.CTkLabel(theme_frame, text="Theme", **subtitle_style)
        theme_label.grid(row=0, column=0, sticky="w", padx=20, pady=(15, 10))
        
        # Create a frame for radio buttons
        theme_radio_frame = ctk.CTkFrame(theme_frame, fg_color="transparent")
        theme_radio_frame.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 15))
        theme_radio_frame.grid_columnconfigure(0, weight=1)
        theme_radio_frame.grid_columnconfigure(1, weight=1)
        theme_radio_frame.grid_columnconfigure(2, weight=1)
        
        self.theme_var = StringVar(value=user_settings["theme"])
        themes = [
            ("System", "system"),
            ("Light", "light"),
            ("Dark", "dark")
        ]
        
        for idx, (text, value) in enumerate(themes):
            radio = ctk.CTkRadioButton(
                theme_radio_frame,
                text=text,
                variable=self.theme_var,
                value=value,
                **radio_style
            )
            radio.grid(row=0, column=idx, padx=10, pady=5)
        
        # Widget theme section
        widget_frame = ctk.CTkFrame(scroll_frame, fg_color="#242424")
        widget_frame.grid(row=1, column=0, sticky="ew", pady=(0, 20))
        widget_frame.grid_columnconfigure(0, weight=1)
        
        widget_label = ctk.CTkLabel(widget_frame, text="Widget Theme", **subtitle_style)
        widget_label.grid(row=0, column=0, sticky="w", padx=20, pady=(15, 10))
        
        # Create a frame for widget theme radio buttons
        widget_radio_frame = ctk.CTkFrame(widget_frame, fg_color="transparent")
        widget_radio_frame.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 15))
        widget_radio_frame.grid_columnconfigure(0, weight=1)
        widget_radio_frame.grid_columnconfigure(1, weight=1)
        widget_radio_frame.grid_columnconfigure(2, weight=1)
        
        self.widget_theme_var = StringVar(value=user_settings["widget_theme"])
        widget_themes = [
            ("Blue", "blue"),
            ("Dark Blue", "dark-blue"),
            ("Green", "green")
        ]
        
        for idx, (text, value) in enumerate(widget_themes):
            radio = ctk.CTkRadioButton(
                widget_radio_frame,
                text=text,
                variable=self.widget_theme_var,
                value=value,
                **radio_style
            )
            radio.grid(row=0, column=idx, padx=10, pady=5)
        
        # Text settings section
        text_frame = ctk.CTkFrame(scroll_frame, fg_color="#242424")
        text_frame.grid(row=2, column=0, sticky="ew", pady=(0, 20))
        text_frame.grid_columnconfigure(0, weight=1)
        
        text_label = ctk.CTkLabel(text_frame, text="Text Settings", **subtitle_style)
        text_label.grid(row=0, column=0, sticky="w", padx=20, pady=(15, 10))
        
        # Create a frame for text size radio buttons
        text_size_frame = ctk.CTkFrame(text_frame, fg_color="transparent")
        text_size_frame.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 15))
        text_size_frame.grid_columnconfigure(0, weight=1)
        text_size_frame.grid_columnconfigure(1, weight=1)
        text_size_frame.grid_columnconfigure(2, weight=1)
        
        size_label = ctk.CTkLabel(text_size_frame, text="Text Size:", **text_style)
        size_label.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 5))
        
        self.text_size_var = IntVar(value=user_settings["text_size"])
        sizes = [(14, "Small"), (16, "Medium"), (18, "Large")]
        
        for idx, (size, text) in enumerate(sizes):
            radio = ctk.CTkRadioButton(
                text_size_frame,
                text=text,
                variable=self.text_size_var,
                value=size,
                **radio_style
            )
            radio.grid(row=1, column=idx, padx=10, pady=5)
        
        # Text color and font family in a separate frame
        text_options_frame = ctk.CTkFrame(text_frame, fg_color="transparent")
        text_options_frame.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 15))
        text_options_frame.grid_columnconfigure(0, weight=1)
        text_options_frame.grid_columnconfigure(1, weight=1)
        
        # Text color
        color_label = ctk.CTkLabel(text_options_frame, text="Text Color:", **text_style)
        color_label.grid(row=0, column=0, sticky="w", pady=(0, 5))
        
        self.text_color_var = StringVar(value=user_settings["text_color"])
        colors = ["White", "Black", "Grey"]
        
        color_menu = ctk.CTkOptionMenu(
            text_options_frame,
            values=colors,
            variable=self.text_color_var,
            fg_color=button_fg_color,
            button_color=button_fg_color,
            button_hover_color=button_fg_color,
            font=text_type,
            width=120
        )
        color_menu.grid(row=1, column=0, sticky="w", padx=(0, 10))
        
        # Font family
        font_label = ctk.CTkLabel(text_options_frame, text="Font Family:", **text_style)
        font_label.grid(row=0, column=1, sticky="w", pady=(0, 5))
        
        self.font_family_var = StringVar(value=user_settings["font_family"])
        fonts = ["Arial", "IMPACT", "Times New Roman"]
        
        font_menu = ctk.CTkOptionMenu(
            text_options_frame,
            values=fonts,
            variable=self.font_family_var,
            fg_color=button_fg_color,
            button_color=button_fg_color,
            button_hover_color=button_fg_color,
            font=text_type,
            width=120
        )
        font_menu.grid(row=1, column=1, sticky="w")
        
        # Apply button
        apply_button = ctk.CTkButton(
            scroll_frame,
            text="Apply Settings",
            command=self.apply_settings,
            **button_style
        )
        apply_button.grid(row=3, column=0, pady=(20, 0))
        
        # Status label
        self.status_label = ctk.CTkLabel(
            scroll_frame,
            text="",
            font=text_type,
            text_color="red"
        )
        self.status_label.grid(row=4, column=0, pady=(10, 0))
    
    def apply_settings(self):
        try:
            # Get current settings
            settings = {
                "theme": self.theme_var.get(),
                "widget_theme": self.widget_theme_var.get(),
                "text_size": self.text_size_var.get(),
                "text_color": self.text_color_var.get(),
                "font_family": self.font_family_var.get()
            }
            
            # Save to database
            with sqlite3.connect("UserSettings.db") as db:
                cursor = db.cursor()
                cursor.execute("""
                    UPDATE settings
                    SET theme = ?, widget_theme = ?, text_size = ?, text_color = ?, font_family = ?
                    WHERE id = 1
                """, (
                    settings["theme"],
                    settings["widget_theme"],
                    settings["text_size"],
                    settings["text_color"],
                    settings["font_family"]
                ))
                db.commit()
            
            # Update global settings
            global user_settings
            user_settings = settings
            
            # Update theme
            if settings["theme"] == "system":
                ctk.set_appearance_mode("system")
            else:
                ctk.set_appearance_mode(settings["theme"])
            
            # Update widget theme
            global button_fg_color, button_border_color, button_border_width
            if settings["widget_theme"] == "blue":
                button_fg_color = "#1f538d"
                button_border_color = "#1f538d"
            elif settings["widget_theme"] == "dark-blue":
                button_fg_color = "#0d47a1"
                button_border_color = "#0d47a1"
            else:  # green
                button_fg_color = "#2e7d32"
                button_border_color = "#2e7d32"
            
            # Update text settings
            global text_type, subtitle_type, title_type, text_color
            text_size = settings["text_size"]
            text_type = ctk.CTkFont(family=settings["font_family"], size=text_size)
            subtitle_type = ctk.CTkFont(family=settings["font_family"], size=text_size + 2, weight="bold")
            title_type = ctk.CTkFont(family=settings["font_family"], size=text_size + 4, weight="bold")
            text_color = settings["text_color"].lower()
            
            # Show success message
            self.status_label.configure(text="Settings applied successfully!", text_color="green")
            
            # Clear status message after 2 seconds
            self.root.after(2000, lambda: self.status_label.configure(text=""))
            
            # Refresh parent window if it exists
            if self.parent:
                self.parent.refresh_theme()
                
        except Exception as e:
            self.status_label.configure(text=f"Error applying settings: {str(e)}", text_color="red")
            # Clear error message after 3 seconds
            self.root.after(3000, lambda: self.status_label.configure(text=""))
    
    def on_close(self):
        Settings._instance = None
        if self.parent and hasattr(self.parent, 'focus_force'):
            self.parent.focus_force()  # Return focus to parent window
        self.root.destroy()

class FileManager(CredentialManager):
    _instance = None
    
    def __new__(cls, parent=None):
        if cls._instance is not None:
            cls.popup(cls._instance.root, "Import/Export window is already open")
            return cls._instance
        cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self, parent=None):
        if hasattr(self, 'root'):
            return
        self.parent = parent
        self.root = ctk.CTk()
        super().__init__(self.root)
        self.setup_window()
        self.create_widgets()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def setup_window(self):
        self.root.title("Import/Export Credentials")
        self.root.attributes('-topmost', True)
        
        # Get screen dimensions
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        
        # Set window size to 40% of screen size
        window_width = int(screen_width * 0.4)
        window_height = int(screen_height * 0.4)
        
        # Calculate window position for center placement
        x_position = (screen_width - window_width) // 2
        y_position = (screen_height - window_height) // 2
        
        # Set window geometry
        self.root.geometry(f"{window_width}x{window_height}+{x_position}+{y_position}")
        
        # Make window resizable
        self.root.resizable(True, True)
        
        # Configure grid weights
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(0, weight=1)

    def create_widgets(self):
        # Create main container
        main_container = ctk.CTkFrame(self.root, fg_color="#1a1a1a")
        main_container.grid(row=0, column=0, sticky="nsew", padx=40, pady=40)
        main_container.grid_columnconfigure(0, weight=1)
        main_container.grid_rowconfigure(1, weight=1)
        
        # Style definitions
        title_style = {"font": title_type, "text_color": text_color}
        subtitle_style = {"font": subtitle_type, "text_color": text_color}
        text_style = {"font": text_type, "text_color": text_color}
        button_style = {
            "font": subtitle_type,
            "fg_color": button_fg_color,
            "text_color": text_color,
            "height": 40,
            "width": 200
        }
        
        # Title
        title = ctk.CTkLabel(main_container, text="Import/Export Credentials", **title_style)
        title.grid(row=0, column=0, sticky="w", pady=(0, 20))
        
        # Create scrollable frame
        scrollable_frame = ctk.CTkScrollableFrame(main_container, fg_color="transparent")
        scrollable_frame.grid(row=1, column=0, sticky="nsew")
        scrollable_frame.grid_columnconfigure(0, weight=1)
        
        # Database selection frame
        db_frame = ctk.CTkFrame(scrollable_frame, fg_color="transparent")
        db_frame.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        db_frame.grid_columnconfigure(0, weight=1)
        
        db_label = ctk.CTkLabel(db_frame, text="Select Database:", **subtitle_style)
        db_label.grid(row=0, column=0, sticky="w", pady=(0, 10))
        
        db_radio_frame = ctk.CTkFrame(db_frame, fg_color="transparent")
        db_radio_frame.grid(row=1, column=0, sticky="ew")
        
        self.db_var = ctk.StringVar(value="all_items")
        all_items_radio = ctk.CTkRadioButton(
            db_radio_frame,
            text="All Items",
            variable=self.db_var,
            value="all_items",
            font=text_type,
            text_color=text_color
        )
        all_items_radio.grid(row=0, column=0, padx=(0, 20))
        
        favourites_radio = ctk.CTkRadioButton(
            db_radio_frame,
            text="Favourites",
            variable=self.db_var,
            value="favourites",
            font=text_type,
            text_color=text_color
        )
        favourites_radio.grid(row=0, column=1)
        
        # Import/Export buttons frame
        buttons_frame = ctk.CTkFrame(scrollable_frame, fg_color="transparent")
        buttons_frame.grid(row=1, column=0, sticky="ew", pady=(0, 20))
        buttons_frame.grid_columnconfigure((0, 1), weight=1)
        
        # Import buttons
        import_frame = ctk.CTkFrame(buttons_frame, fg_color="transparent")
        import_frame.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        import_frame.grid_columnconfigure(0, weight=1)
        
        import_label = ctk.CTkLabel(import_frame, text="Import From:", **subtitle_style)
        import_label.grid(row=0, column=0, sticky="w", pady=(0, 10))
        
        import_json_btn = ctk.CTkButton(
            import_frame,
            text="Import from JSON",
            command=self.import_from_json,
            **button_style
        )
        import_json_btn.grid(row=1, column=0, pady=(0, 10))
        
        import_csv_btn = ctk.CTkButton(
            import_frame,
            text="Import from CSV",
            command=self.import_from_csv,
            **button_style
        )
        import_csv_btn.grid(row=2, column=0)
        
        # Export buttons
        export_frame = ctk.CTkFrame(buttons_frame, fg_color="transparent")
        export_frame.grid(row=0, column=1, sticky="ew", padx=(10, 0))
        export_frame.grid_columnconfigure(0, weight=1)
        
        export_label = ctk.CTkLabel(export_frame, text="Export To:", **subtitle_style)
        export_label.grid(row=0, column=0, sticky="w", pady=(0, 10))
        
        export_json_btn = ctk.CTkButton(
            export_frame,
            text="Export to JSON",
            command=self.export_to_json,
            **button_style
        )
        export_json_btn.grid(row=1, column=0, pady=(0, 10))
        
        export_csv_btn = ctk.CTkButton(
            export_frame,
            text="Export to CSV",
            command=self.export_to_csv,
            **button_style
        )
        export_csv_btn.grid(row=2, column=0)
        
        # Status label
        self.status_label = ctk.CTkLabel(
            scrollable_frame,
            text="",
            font=text_type,
            text_color="red"
        )
        self.status_label.grid(row=2, column=0, pady=(20, 0))

    def on_close(self):
        FileManager._instance = None
        if self.parent and hasattr(self.parent, 'refresh_theme'):
            self.parent.refresh_theme()  # Refresh parent window
        self.root.destroy()

    def run(self):
        self.root.mainloop()

    def import_from_json(self):
        try:
            db_path, table = self.determine_database()
            self.import_data_from_json(db_path, table)
            self.update_status("Import successful!")
        except Exception as e:
            self.update_status(f"Import failed: {str(e)}", True)

    def import_from_csv(self):
        try:
            db_path, table = self.determine_database()
            self.import_data_from_csv(db_path, table)
            self.update_status("Import successful!")
        except Exception as e:
            self.update_status(f"Import failed: {str(e)}", True)

    def export_to_json(self):
        """Export data from the selected database to a JSON file."""
        try:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json")],
                title="Export as JSON"
            )
            if not file_path:
                return

            db_path = ALL_ITEMS_DB if self.db_var.get() == "all_items" else FAVOURITES_DB

            with sqlite3.connect(db_path) as db:
                cursor = db.cursor()
                cursor.execute(f"SELECT * FROM {self.db_var.get().lower()}")
                rows = cursor.fetchall()

                data = [{
                    'id': row[0],
                    'title': row[1],
                    'username': row[2],
                    'password': row[3],
                    'website': row[4],
                    'notes': row[5]
                } for row in rows]

                with open(file_path, 'w') as f:
                    json.dump(data, f, indent=4)

                self.update_status("Export successful!")
        except Exception as e:
            self.update_status(f"Export failed: {str(e)}", True)

    def export_to_csv(self):
        """Export data from the selected database to a CSV file."""
        try:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv")],
                title="Export as CSV"
            )
            if not file_path:
                return

            db_path = ALL_ITEMS_DB if self.db_var.get() == "all_items" else FAVOURITES_DB

            with sqlite3.connect(db_path) as db:
                cursor = db.cursor()
                cursor.execute(f"SELECT * FROM {self.db_var.get().lower()}")
                rows = cursor.fetchall()

                with open(file_path, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['id', 'title', 'username', 'password', 'website', 'notes'])
                    writer.writerows(rows)

                self.update_status("Export successful!")
        except Exception as e:
            self.update_status(f"Export failed: {str(e)}", True)

    def determine_database(self):
        """Determine which database and table to use based on selection."""
        database = self.db_var.get()
        if database == "all_items":
            return ALL_ITEMS_DB, "all_items"
        else:
            return FAVOURITES_DB, "favourites"

    def import_data_from_json(self, db_path, table):
        """Import data from a JSON file into the selected database."""
        file_path = filedialog.askopenfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
            title="Import from JSON"
        )
        if not file_path:
            return

        try:
            with open(file_path, 'r') as f:
                data = json.load(f)

            with sqlite3.connect(db_path) as db:
                cursor = db.cursor()
                for item in data:
                    cursor.execute(
                        f"INSERT INTO {table} (title, username, password, website, notes) VALUES (?, ?, ?, ?, ?)",
                        (item['title'], item['username'], item['password'], item['website'], item['notes'])
                    )
                db.commit()
            self.update_status("Import successful!")
        except Exception as e:
            self.update_status(f"Import failed: {str(e)}", True)

    def import_data_from_csv(self, db_path, table):
        """Import data from a CSV file into the selected database."""
        file_path = filedialog.askopenfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            title="Import from CSV"
        )
        if not file_path:
            return

        try:
            with open(file_path, 'r', newline='') as f:
                reader = csv.DictReader(f)
                with sqlite3.connect(db_path) as db:
                    cursor = db.cursor()
                    for row in reader:
                        cursor.execute(
                            f"INSERT INTO {table} (title, username, password, website, notes) VALUES (?, ?, ?, ?, ?)",
                            (row['title'], row['username'], row['password'], row['website'], row['notes'])
                        )
                    db.commit()
            self.update_status("Import successful!")
        except Exception as e:
            self.update_status(f"Import failed: {str(e)}", True)

    def update_status(self, message, is_error=False):
        self.status_label.configure(
            text=message,
            text_color="red" if is_error else text_color
        )
        self.root.after(3000, lambda: self.status_label.configure(text=""))  # Clear after 3 seconds

class AddCredential(CredentialManager):
    _instance = None
    
    def __new__(cls, parent=None):
        if cls._instance is not None:
            cls.popup(cls._instance.root, "Add Credential window is already open")
            return cls._instance
        cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self, parent=None):
        if hasattr(self, 'root'):
            return
        self.parent = parent
        self.root = ctk.CTk()
        super().__init__(self.root)
        self.setup_window()
        self.create_widgets()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def setup_window(self):
        self.root.title("Add A Credential")
        self.root.attributes('-topmost', True)
        
        # Get screen dimensions
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        
        # Set window size to 40% of screen size
        window_width = int(screen_width * 0.4)
        window_height = int(screen_height * 0.4)
        
        # Calculate window position for center placement
        x_position = (screen_width - window_width) // 2
        y_position = (screen_height - window_height) // 2
        
        # Set window geometry
        self.root.geometry(f"{window_width}x{window_height}+{x_position}+{y_position}")
        
        # Make window resizable
        self.root.resizable(True, True)
        
        # Configure grid weights
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(0, weight=1)

    def create_widgets(self):
        # Create main container
        main_container = ctk.CTkFrame(self.root, fg_color="#1a1a1a")
        main_container.grid(row=0, column=0, sticky="nsew", padx=40, pady=40)
        main_container.grid_columnconfigure(0, weight=1)
        main_container.grid_rowconfigure(1, weight=1)  # Make scrollable frame expandable
        
        # Style definitions
        title_style = {"font": title_type, "text_color": text_color}
        subtitle_style = {"font": subtitle_type, "text_color": text_color}
        text_style = {"font": text_type, "text_color": text_color}
        entry_style = {
            "font": text_type,
            "text_color": text_color,
            "fg_color": txt_entry_fg_color,
            "height": 35,
            "width": 300
        }
        button_style = {
            "font": subtitle_type,
            "fg_color": button_fg_color,
            "text_color": text_color,
            "height": 40,
            "width": 200
        }
        
        # Title
        title = ctk.CTkLabel(main_container, text="Add New Credential", **title_style)
        title.grid(row=0, column=0, sticky="w", pady=(0, 20))
        
        # Create scrollable frame
        scroll_frame = ctk.CTkScrollableFrame(main_container, fg_color="transparent")
        scroll_frame.grid(row=1, column=0, sticky="nsew")
        scroll_frame.grid_columnconfigure(0, weight=1)
        
        # Create content frame inside scrollable frame
        content_frame = ctk.CTkFrame(scroll_frame, fg_color="transparent")
        content_frame.grid(row=0, column=0, sticky="nsew", pady=(0, 20))
        content_frame.grid_columnconfigure(0, weight=1)
        
        # Website
        website_label = ctk.CTkLabel(content_frame, text="Website:", **subtitle_style)
        website_label.grid(row=0, column=0, sticky="w", pady=(0, 10))
        
        self.website_entry = ctk.CTkEntry(content_frame, placeholder_text="Enter website", **entry_style)
        self.website_entry.grid(row=1, column=0, sticky="ew", pady=(0, 20))
        
        # Username
        username_label = ctk.CTkLabel(content_frame, text="Username:", **subtitle_style)
        username_label.grid(row=2, column=0, sticky="w", pady=(0, 10))
        
        self.username_entry = ctk.CTkEntry(content_frame, placeholder_text="Enter username", **entry_style)
        self.username_entry.grid(row=3, column=0, sticky="ew", pady=(0, 20))
        
        # Password
        password_label = ctk.CTkLabel(content_frame, text="Password:", **subtitle_style)
        password_label.grid(row=4, column=0, sticky="w", pady=(0, 10))
        
        self.password_entry = ctk.CTkEntry(content_frame, placeholder_text="Enter password", show="•", **entry_style)
        self.password_entry.grid(row=5, column=0, sticky="ew", pady=(0, 20))
        
        # Confirm Password
        confirm_label = ctk.CTkLabel(content_frame, text="Confirm Password:", **subtitle_style)
        confirm_label.grid(row=6, column=0, sticky="w", pady=(0, 10))
        
        self.confirm_password_entry = ctk.CTkEntry(content_frame, placeholder_text="Confirm password", show="•", **entry_style)
        self.confirm_password_entry.grid(row=7, column=0, sticky="ew", pady=(0, 20))
        
        # Add button
        add_button = ctk.CTkButton(
            content_frame,
            text="Add Credential",
            command=self.add_values,
            **button_style
        )
        add_button.grid(row=8, column=0, pady=(20, 0))
        
        # Status label
        self.status_label = ctk.CTkLabel(
            content_frame,
            text="",
            font=text_type,
            text_color="red"
        )
        self.status_label.grid(row=9, column=0, pady=(10, 0))

    def add_values(self):
        # Get the values from the text entries
        website = self.website_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        
        # Reset status label
        self.status_label.configure(text="")
        
        # Validate inputs
        if not website or not username or not password or not confirm_password:
            self.status_label.configure(text="Please fill in all fields")
            return
        
        if password != confirm_password:
            self.status_label.configure(text="Passwords do not match")
            self.password_entry.delete(0, 'end')
            self.confirm_password_entry.delete(0, 'end')
            return
        
        try:
            # Encrypt the password
            encrypted_password = self.encrypt_password(password)
            
            # Insert into database
            with sqlite3.connect(ALL_ITEMS_DB) as db:
                cursor = db.cursor()
                cursor.execute("""
                    INSERT INTO all_items (website, username, password)
                    VALUES (?, ?, ?)
                """, (website, username, encrypted_password))
                db.commit()
            
            # Show success message
            self.status_label.configure(text="Credential added successfully!", text_color="green")
            
            # Clear entries
            self.website_entry.delete(0, 'end')
            self.username_entry.delete(0, 'end')
            self.password_entry.delete(0, 'end')
            self.confirm_password_entry.delete(0, 'end')
            
            # Close window after delay
            self.root.after(1000, self.on_close)
            
        except Exception as e:
            self.status_label.configure(text=f"Error adding credential: {str(e)}")

    def on_close(self):
        AddCredential._instance = None
        if self.parent and hasattr(self.parent, 'refresh_theme'):
            self.parent.refresh_theme()  # Refresh parent window
        self.root.destroy()

    def run(self):
        self.root.mainloop()

    def run_add_credentials(self):
        app = AddCredential(parent=self)
        app.run()

class EditCredential(CredentialManager):
    _instance = None

    def __new__(cls, parent, database, table, record):
        if cls._instance is not None:
            cls.popup(cls._instance.root, "Edit Credential window is already open")
            return cls._instance
        cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, parent, database, table, record):
        if hasattr(self, 'root'):
            return
        self.root = ctk.CTk()
        super().__init__(self.root)
        self.parent = parent
        self.database = database
        self.table = table
        self.record_id = record[0]  # Store the record ID
        self.previous_website = record[1]
        self.previous_username = record[2]
        self.previous_password = record[3]
        self.setup_window()
        self.create_widgets()
        self.assign_values()  # Call this after creating widgets
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def assign_values(self):
        try:
            # Populate the entries with the current values
            self.website_entry.delete(0, 'end')
            self.website_entry.insert(0, self.previous_website)
            
            self.username_entry.delete(0, 'end')
            self.username_entry.insert(0, self.previous_username)
            
            self.password_entry.delete(0, 'end')
            try:
                decrypted_password = self.decrypt_password(self.previous_password)
                self.password_entry.insert(0, decrypted_password)
            except Exception as e:
                print(f"Error decrypting password: {e}")
                self.status_label.configure(text="Error loading password")
            
        except Exception as e:
            print(f"Error in assign_values: {e}")
            self.status_label.configure(text=f"Error loading credential: {str(e)}")

    def apply_values(self):
        # Get the updated values
        new_website = self.website_entry.get().strip()
        new_username = self.username_entry.get().strip()
        new_password = self.password_entry.get()
        
        # Validate inputs
        if not all([new_website, new_username, new_password]):
            self.status_label.configure(text="Please fill in all fields")
            return
        
        try:
            # Encrypt the new password
            encrypted_password = self.encrypt_password(new_password)
            
            # Update the database using the record ID
            db_path = ALL_ITEMS_DB if self.database == "AllItems" else FAVOURITES_DB
            with sqlite3.connect(db_path) as db:
                cursor = db.cursor()
                cursor.execute(f"""
                    UPDATE {self.table}
                    SET website = ?, username = ?, password = ?
                    WHERE id = ?
                """, (new_website, new_username, encrypted_password, self.record_id))
                db.commit()
            
            self.status_label.configure(text="Changes saved successfully!", text_color="green")
            self.root.after(1000, self.on_close)
            
        except Exception as e:
            print(f"Error in apply_values: {e}")
            self.status_label.configure(text=f"Error saving changes: {str(e)}")

    def on_close(self):
        EditCredential._instance = None
        if self.parent and hasattr(self.parent, 'refresh_theme'):
            self.parent.refresh_theme()  # Refresh parent window
        self.root.destroy()

    def run(self):
        self.root.mainloop()

class AdditionalInformation(CredentialManager):
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is not None:
            cls.popup(cls._instance.root, "Help window is already open")
            return cls._instance
        cls._instance = super(AdditionalInformation, cls).__new__(cls)
        return cls._instance

    def __init__(self, parent=None):
        if hasattr(self, 'root'):
            return
        super().__init__(None)
        self.parent = parent
        self.root = ctk.CTk()
        self.setup_window()
        self.create_widgets()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def setup_window(self):
        self.root.title("Help & Information")
        self.root.attributes('-topmost', True)
        
        # Get screen dimensions
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        
        # Set window size to 60% of screen size
        window_width = int(screen_width * 0.6)
        window_height = int(screen_height * 0.6)
        
        # Calculate window position for center placement
        x_position = (screen_width - window_width) // 2
        y_position = (screen_height - window_height) // 2
        
        # Set window geometry
        self.root.geometry(f"{window_width}x{window_height}+{x_position}+{y_position}")
        
        # Make window resizable
        self.root.resizable(True, True)
        
        # Configure grid weights
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(0, weight=1)

    def create_widgets(self):
        # Create main container with scrollable frame
        main_container = ctk.CTkFrame(self.root)
        main_container.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        main_container.grid_columnconfigure(0, weight=1)
        main_container.grid_rowconfigure(0, weight=1)
        
        # Create scrollable frame
        scroll_frame = ctk.CTkScrollableFrame(main_container)
        scroll_frame.grid(row=0, column=0, sticky="nsew")
        scroll_frame.grid_columnconfigure(0, weight=1)
        
        # Style definitions
        title_style = {"font": title_type, "text_color": text_color}
        subtitle_style = {"font": subtitle_type, "text_color": text_color}
        text_style = {"font": text_type, "text_color": text_color}
        
        # Create sections
        sections = [
            ("Getting Started", [
                "Welcome to the Credential Manager!",
                "• Use the left sidebar to navigate between different views",
                "• 'All Items' shows all your stored credentials",
                "• 'Favourites' displays your starred credentials",
                "• Use the search bar to quickly find credentials"
            ]),
            ("Managing Credentials", [
                "Adding Credentials:",
                "• Click the '+' button to add new credentials",
                "• Fill in the website, username, and password",
                "• Use the Random Password Generator for secure passwords",
                "",
                "Editing Credentials:",
                "• Click the 'Edit' button on any credential",
                "• Update the information as needed",
                "• Changes are saved automatically"
            ]),
            ("Security Features", [
                "• All passwords are encrypted using Fernet encryption",
                "• Master password is required to access the vault",
                "• Passwords are never stored in plain text",
                "• Automatic session timeout for security",
                "• Export your credentials securely using the Import/Export feature"
            ]),
            ("Tips & Best Practices", [
                "• Use strong, unique passwords for each account",
                "• Regularly update your master password",
                "• Keep your master password secure and never share it",
                "• Use the Random Password Generator for maximum security",
                "• Regularly backup your credentials using the Export feature"
            ]),
            ("Troubleshooting", [
                "Common Issues:",
                "• If you forget your master password, you'll need to reset the vault",
                "• Make sure to backup your credentials regularly",
                "• If the application freezes, try restarting it",
                "• For any other issues, contact support"
            ])
        ]
        
        # Create each section
        for section_idx, (section_title, content) in enumerate(sections):
            # Section container
            section_frame = ctk.CTkFrame(scroll_frame, fg_color="#242424")
            section_frame.grid(row=section_idx, column=0, sticky="ew", padx=10, pady=10)
            section_frame.grid_columnconfigure(0, weight=1)
            
            # Section title
            title = ctk.CTkLabel(section_frame, text=section_title, **title_style)
            title.grid(row=0, column=0, sticky="w", padx=20, pady=(15, 10))
            
            # Section content
            for idx, line in enumerate(content):
                if line.startswith("•"):
                    # Bullet point
                    content_label = ctk.CTkLabel(
                        section_frame,
                        text=line,
                        **text_style,
                        justify="left"
                    )
                else:
                    # Regular text or subtitle
                    style = subtitle_style if idx == 0 else text_style
                    content_label = ctk.CTkLabel(
                        section_frame,
                        text=line,
                        **style,
                        justify="left"
                    )
                content_label.grid(
                    row=idx + 1,
                    column=0,
                    sticky="w",
                    padx=40,
                    pady=(0, 5 if idx < len(content) - 1 else 15)
                )

    def on_close(self):
        AdditionalInformation._instance = None
        self.root.destroy()

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    root = ctk.CTk()
    credential_manager = CredentialManager(root)
    
    # Check master password after initialization
    if credential_manager.check_master_password():
        credential_manager.run_login_screen()
    else:
        credential_manager.run_create_master_password()
    
    root.mainloop()
