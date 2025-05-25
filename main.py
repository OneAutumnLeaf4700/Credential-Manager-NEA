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
from database import MASTER_PASSWORD_DB, ALL_ITEMS_DB, FAVOURITES_DB, KEY_FILE, get_db_path
from settings import *

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
        from main_vault import MainVault
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
            text="Create Master Password",
            **title_style
        )
        title.grid(row=0, column=0, pady=(0, 10))
        
        # Subtitle
        subtitle = ctk.CTkLabel(
            content_frame,
            text="Create a strong master password to secure your vault",
            **subtitle_style
        )
        subtitle.grid(row=1, column=0, pady=(0, 30))
        
        # Password requirements frame
        requirements_frame = ctk.CTkFrame(content_frame, fg_color="#242424")
        requirements_frame.grid(row=2, column=0, pady=(0, 20), padx=20, sticky="ew")
        
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
        entry_frame.grid(row=3, column=0, pady=(0, 20))
        
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
        self.status_label.grid(row=4, column=0, pady=(10, 0))
    
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
        app = MainVault(self.root, "All Items", "AllItems", "all_items")
        app.run()
    
    def on_close(self):
        self.root.destroy()
    
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
            self.root.after(100, self.destroy_and_create_mainvault)
        else:
            self.status_label.configure(text="Incorrect password. Please try again.")
            self.password.delete(0, 'end')
            self.root.after(3000, lambda: self.status_label.configure(text=""))  # Clear after 3 seconds
    
    def destroy_and_create_mainvault(self):
        self.cleanup_widgets()
        app = MainVault(self.root, "All Items", "AllItems", "all_items")
        app.run()
    
    def cleanup_widgets(self):
        for widget in self.root.winfo_children():
            widget.destroy()
    
    def on_close(self):
        self.cleanup_widgets()
        self.root.destroy()
    
    def run_after_lock(self):
        self.root.mainloop()
    
    def run(self):
        self.root.mainloop()

class MainVault(CredentialManager):
    _instance = None
    
    def __new__(cls, root, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(MainVault, cls).__new__(cls)
        return cls._instance
    
    def __init__(self, root, title, database, table):
        super().__init__(root)
        self.root = root
        self.title = title
        self.database = database
        self.table = table
        self.current_page = 1
        self.items_per_page = 10
        self.initialize_root_window()
        self.initialize_left_frame()
        self.initialize_right_frame(title, database, table)
        self.initialize_search_frame(database, table)
        self.initialize_scrollable_frame(database, table)
        self.initialize_lifted_widgets(database, table)
        self.load_credentials("id", database, table)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        
    def edit_credential(self, record):
        # Create a popup window for editing
        edit_window = ctk.CTkToplevel(self.root)
        edit_window.title("Edit Credential")
        edit_window.geometry("400x300")
        
        # Create labels and entry fields
        title_label = ctk.CTkLabel(
            edit_window, 
            text="Title:", 
            font=subtitle_type,
            text_color=text_color
        )
        title_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        
        # Create username label with explicit styling
        username_label = ctk.CTkLabel(
            edit_window, 
            text="Username:", 
            font=subtitle_type,
            text_color=text_color
        )
        username_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")
        
        # Create password label with explicit styling
        password_label = ctk.CTkLabel(
            edit_window, 
            text="Password:", 
            font=subtitle_type,
            text_color=text_color
        )
        password_label.grid(row=2, column=0, padx=10, pady=5, sticky="w")

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
                        fg_color="#242424" if row_idx % 2 == 0 else "#1a1a1a"
                    )
                    frame.grid(row=row_idx, column=0, columnspan=4, sticky="ew", padx=0, pady=1)
                    frame.grid_columnconfigure(0, weight=2)  # Website
                    frame.grid_columnconfigure(1, weight=2)  # Username
                    frame.grid_columnconfigure(2, weight=1)  # Password
                    frame.grid_columnconfigure(3, weight=1)  # Actions
                    
                    # Add website
                    website_label = ctk.CTkLabel(
                        frame,
                        text=row[1],  # Website
                        font=text_type,
                        text_color=text_color
                    )
                    website_label.grid(row=0, column=0, padx=20, pady=10, sticky="w")
                    
                    # Add username
                    username_label = ctk.CTkLabel(
                        frame,
                        text=row[2],  # Username
                        font=text_type,
                        text_color=text_color
                    )
                    username_label.grid(row=0, column=1, padx=20, pady=10, sticky="w")
                    
                    # Add password (masked)
                    password_label = ctk.CTkLabel(
                        frame,
                        text="••••••••",
                        font=text_type,
                        text_color=text_color
                    )
                    password_label.grid(row=0, column=2, padx=20, pady=10, sticky="w")
                    
                    # Create actions frame
                    actions_frame = ctk.CTkFrame(frame, fg_color="transparent")
                    actions_frame.grid(row=0, column=3, padx=20, pady=10, sticky="e")
                    
                    # Add action buttons
                    edit_button = ctk.CTkButton(
                        actions_frame,
                        text="Edit",
                        width=60,
                        command=lambda r=row: self.edit_credential(r),
                        font=text_type,
                        fg_color=button_fg_color,
                        text_color=text_color
                    )
                    edit_button.pack(side="left", padx=5)
                    
                    delete_button = ctk.CTkButton(
                        actions_frame,
                        text="Delete",
                        width=60,
                        command=lambda r=row: self.delete_record(r[0], database, table),
                        font=text_type,
                        fg_color=button_fg_color,
                        text_color=text_color
                    )
                    delete_button.pack(side="left", padx=5)
                    
                    if database == "AllItems":
                        favorite_button = ctk.CTkButton(
                            actions_frame,
                            text="★",
                            width=40,
                            command=lambda r=row: self.favorite_record(r),
                            font=text_type,
                            fg_color=button_fg_color,
                            text_color=text_color
                        )
                        favorite_button.pack(side="left", padx=5)
        
        except Exception as e:
            self.popup(self.root, f"Error loading credentials: {str(e)}")

    def favorite_record(self, record_array):
        # Add record to favorites database
        with sqlite3.connect(FAVOURITES_DB) as db:
            cursor = db.cursor()
            cursor.execute("INSERT INTO favourites (title, username, password, website, notes) VALUES (?, ?, ?, ?, ?)",
                         (record_array[1], record_array[2], record_array[3], record_array[4], record_array[5]))
            db.commit()
        self.popup(self.root, "Added to Favorites")
    
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
        import customtkinter as ctk
        from login_screen import LoginScreen
        new_root = ctk.CTk()
        login_screen = LoginScreen(new_root)
        login_screen.run_after_lock()

    def on_close(self):
        MainVault._instance = None
        self.root.destroy()

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
        
        # Set window size to 80% of screen size
        self.root_width = int(screen_width * 0.8)
        self.root_height = int(screen_height * 0.8)
        
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
        
        # Create title label
        self.title_label = ctk.CTkLabel(
            header_frame,
            text=window_title,
            font=title_type,
            text_color=text_color,
            fg_color="transparent"
        )
        self.title_label.grid(row=0, column=0, sticky="w")
        
        # Create search frame with dynamic sizing
        search_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        search_frame.grid(row=0, column=1, sticky="e")
        search_frame.grid_columnconfigure(0, weight=1)  # Make search bar expandable
        
        # Add search bar with dynamic width
        self.search_bar = ctk.CTkEntry(
            search_frame,
            placeholder_text="Search...",
            font=text_type,
            text_color=text_color,
            fg_color=txt_entry_fg_color,
            height=35
        )
        self.search_bar.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        
        # Add search button
        search_button = ctk.CTkButton(
            search_frame,
            text="Search",
            width=100,
            height=35,
            command=lambda: self.load_credentials(self.search_bar.get(), database, table),
            font=text_type,
            fg_color=button_fg_color,
            text_color=text_color
        )
        search_button.grid(row=0, column=1)
        
        # Create header bar with dynamic sizing
        header_bar = ctk.CTkFrame(self.right_frame, fg_color="#242424", height=40)
        header_bar.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 10))
        header_bar.grid_propagate(False)
        
        # Configure header bar columns with dynamic weights
        header_bar.grid_columnconfigure(0, weight=3)  # Website column
        header_bar.grid_columnconfigure(1, weight=3)  # Username column
        header_bar.grid_columnconfigure(2, weight=2)  # Password column
        header_bar.grid_columnconfigure(3, weight=2)  # Actions column
        
        # Add column headers with consistent styling
        header_style = {"font": subtitle_type, "text_color": text_color}
        
        # Create headers with dynamic sizing
        headers = [
            ("Website", lambda: self.load_credentials("website", database, table)),
            ("Username", lambda: self.load_credentials("username", database, table)),
            ("Password", None),
            ("Actions", None)
        ]
        
        for idx, (text, command) in enumerate(headers):
            if command:  # Clickable header
                header = ctk.CTkButton(
                    header_bar,
                    text=text,
                    fg_color="transparent",
                    border_width=0,
                    command=command,
                    **header_style
                )
            else:  # Static header
                header = ctk.CTkLabel(
                    header_bar,
                    text=text,
                    **header_style
                )
            header.grid(row=0, column=idx, padx=20, sticky="w")
        
        # Initialize scrollable frame
        self.initialize_scrollable_frame(database, table)
        
        # Initialize pagination controls
        self.initialize_lifted_widgets(database, table)

    def initialize_search_frame(self, database, table):
        button_style = {"font": text_type, "fg_color": "#0f0f0f", "border_width":
                       button_border_width, "border_color": button_border_color, "text_color": text_color}
        entry_style = {"font": subtitle_type, "text_color": text_color, "fg_color":
                      txt_entry_fg_color}
        search_bar_frame = ctk.CTkFrame(self.right_frame, width=600, height=40,
                                        fg_color="transparent")
        search_bar_frame.place(relx=1, rely=0, anchor="ne")

        # Store a reference to the search_bar widget as an instance variable
        self.search_bar = ctk.CTkEntry(search_bar_frame, width=300,
                                       placeholder_text="Search", **entry_style)
        self.search_bar.grid(row=0, column=0, sticky="ne", padx=5, pady=10)

        # Define a lambda function to call load_credentials with the search query
        search_button = ctk.CTkButton(search_bar_frame, text="Search",
                                      command=lambda: self.load_credentials(self.search_bar.get(), database, table),
                                      **button_style)
        search_button.grid(row=0, column=1, padx=5)

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
            highlightthickness=0
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
        
        # Create scrollable frame
        self.scrollable_frame = ctk.CTkFrame(self.canvas, fg_color="transparent")
        self.canvas_frame = self.canvas.create_window(
            (0, 0),
            window=self.scrollable_frame,
            anchor="nw",
            width=self.canvas.winfo_reqwidth()
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
        prev_button.pack(side="left", padx=5)
        
        next_button = ctk.CTkButton(
            pagination_frame,
            text="Next",
            command=lambda: self.change_page(1, database, table),
            **button_style
        )
        next_button.pack(side="left", padx=5)

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
        app = AddCredential(self.root)
        app.run()

    def run_settings(self):
        app = Settings(parent=self.root)
        app.run()

    def run_filemanager(self):
        app = FileManager()
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
        if hasattr(self, 'root'):  # Check if already initialized
            return
        self.parent = parent
        self.root = ctk.CTk()
        super().__init__(self.root)  # Pass the new root window to parent
        self.setup_window()
        self.create_widgets()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def is_master_password_present(self):
        pass

    def setup_window(self):
        self.root.title("Settings")
        self.root.attributes('-topmost', True)  # Make window stay on top
        root_width = 700
        root_height = 350
        self.root.geometry(f"{root_width}x{root_height}")
        self.root.resizable(False, False)

    def create_widgets(self):
        button_style = {"font": text_type, "fg_color": button_fg_color, "border_width":
                       button_border_width, "border_color": button_border_color, "text_color": text_color}
        radio_button_style = {"fg_color": button_fg_color}
        label_style = {"font": title_type, "text_color": text_color, "fg_color": title_fg_color}
        
        # Create a main frame to hold all widgets
        main_frame = ctk.CTkFrame(self.root)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Theme Widgets
        theme_label = ctk.CTkLabel(main_frame, text="Theme:", **label_style)
        theme_label.grid(row=0, column=0, padx=20, pady=10, sticky="w")
        self.theme_var = StringVar()
        self.theme_var.set(user_settings["theme"])
        theme_button = ctk.CTkRadioButton(main_frame, text="Automatic",
                                        variable=self.theme_var, value="system",
                                        command=None, **radio_button_style)
        theme_button.grid(row=0, column=1, padx=20, pady=10, sticky="w")
        theme_button = ctk.CTkRadioButton(main_frame, text="Light",
                                        variable=self.theme_var, value="light",
                                        command=None, **radio_button_style)
        theme_button.grid(row=0, column=2, padx=20, pady=10, sticky="w")
        theme_button = ctk.CTkRadioButton(main_frame, text="Dark",
                                        variable=self.theme_var, value="dark",
                                        command=None, **radio_button_style)
        theme_button.grid(row=0, column=3, padx=20, pady=10, sticky="w")
        
        # Widget Theme Options
        widget_theme_label = ctk.CTkLabel(main_frame, text="Widget Theme:", **label_style)
        widget_theme_label.grid(row=1, column=0, padx=20, pady=10, sticky="w")
        self.widget_theme_var = StringVar()
        self.widget_theme_var.set(user_settings["widget_theme"])
        widget_theme_button = ctk.CTkRadioButton(main_frame, text="Blue",
                                                variable=self.widget_theme_var, value="blue",
                                                command=None, **radio_button_style)
        widget_theme_button.grid(row=1, column=1, padx=20, pady=10, sticky="w")
        widget_theme_button = ctk.CTkRadioButton(main_frame, text="Dark Blue",
                                                variable=self.widget_theme_var, value="dark-blue",
                                                command=None, **radio_button_style)
        widget_theme_button.grid(row=1, column=2, padx=20, pady=10, sticky="w")
        widget_theme_button = ctk.CTkRadioButton(main_frame, text="Green",
                                                variable=self.widget_theme_var, value="green",
                                                command=None, **radio_button_style)
        widget_theme_button.grid(row=1, column=3, padx=20, pady=10, sticky="w")
        
        # Text Size Option
        text_size_label = ctk.CTkLabel(main_frame, text="Text Size:", **label_style)
        text_size_label.grid(row=2, column=0, padx=20, pady=10, sticky="w")
        self.text_size_var = IntVar()
        self.text_size_var.set(user_settings["text_size"])
        text_size_btn = ctk.CTkRadioButton(main_frame, text="Small",
                                           variable=self.text_size_var, value=14,
                                           command=None, **radio_button_style)
        text_size_btn.grid(row=2, column=1, columnspan=2, padx=20, pady=10, sticky="w")
        text_size_btn = ctk.CTkRadioButton(main_frame, text="Medium",
                                           variable=self.text_size_var, value=16,
                                           command=None, **radio_button_style)
        text_size_btn.grid(row=2, column=2, columnspan=2, padx=20, pady=10, sticky="w")
        text_size_btn = ctk.CTkRadioButton(main_frame, text="Large",
                                           variable=self.text_size_var, value=18,
                                           command=None, **radio_button_style)
        text_size_btn.grid(row=2, column=3, columnspan=2, padx=20, pady=10, sticky="w")
        
        # Text Color Option
        text_color_label = ctk.CTkLabel(main_frame, text="Text Color:", **label_style)
        text_color_label.grid(row=3, column=0, padx=20, pady=10, sticky="w")
        self.text_color_var = StringVar()
        self.text_color_var.set(user_settings["text_color"])
        text_color_options = ctk.CTkOptionMenu(main_frame, values=["White", "Black", "Grey"],
                                               command=None,
                                               variable=self.text_color_var, fg_color=button_fg_color)
        text_color_options.grid(row=3, column=1, columnspan=2, padx=20, pady=10, sticky="w")
        
        # Font Family Option
        font_family_label = ctk.CTkLabel(main_frame, text="Font Family:", **label_style)
        font_family_label.grid(row=4, column=0, padx=20, pady=10, sticky="w")
        self.font_family_var = StringVar()
        self.font_family_var.set(user_settings["font_family"])
        font_family_options = ctk.CTkOptionMenu(
            main_frame,
            values=["Arial", "IMPACT", "Times New Roman"],
            command=None,
            variable=self.font_family_var,
            fg_color=button_fg_color
        )
        font_family_options.grid(row=4, column=1, columnspan=2, padx=20, pady=10, sticky="w")
        
        # Apply Button
        apply_button = ctk.CTkButton(main_frame, text="Apply Settings",
                                    command=self.apply_settings, **button_style)
        apply_button.grid(row=5, column=1, columnspan=2, padx=20, pady=10)

    def apply_settings(self):
        try:
            # Getting Theme
            self.current_theme = self.theme_var.get()
            # Getting Widget theme
            self.current_widget_theme = self.widget_theme_var.get()
            # Getting the text size
            self.current_text_size = self.text_size_var.get()
            # Getting the text color
            self.current_text_color = self.text_color_var.get()
            # Getting the font type
            self.current_font_family = self.font_family_var.get()
            
            # Connecting to the UserSettings Database
            with sqlite3.connect("UserSettings.db") as db:
                cursor = db.cursor()
                # Update the settings in the database
                self.update_database(cursor, db)
                # Fetch and print the updated values
                cursor.execute("SELECT * FROM settings WHERE id = 1;")
                updated_values = cursor.fetchone()
                # Update the user_settings dictionary
                self.update_user_settings(updated_values)
            
            self.refresh_ui()
            self.popup(self.root, "Settings applied successfully!")
            self.on_close()
        except Exception as e:
            self.popup(self.root, f"Error applying settings: {str(e)}")

    def refresh_ui(self):
        # Set New Appearance Mode
        ctk.set_appearance_mode(user_settings["theme"])
        ctk.set_default_color_theme(user_settings["widget_theme"])
        text_type.configure(family=user_settings["font_family"], size=user_settings["text_size"])
        subtitle_type.configure(family=user_settings["font_family"],
                               size=user_settings["text_size"] + 2)
        title_type.configure(family=user_settings["font_family"], size=user_settings["text_size"] + 4)
        self.update_text_color()

    def update_database(self, cursor, db):
        # Update values in the settings table
        cursor.execute("""
        UPDATE settings
        SET
        theme = ?,
        widget_theme = ?,
        text_size = ?,
        text_color = ?,
        font_family = ?
        WHERE id = 1;
        """, (self.current_theme,
              self.current_widget_theme,
              self.current_text_size,
              self.current_text_color,
              self.current_font_family))
        db.commit()

    def update_user_settings(self, values):
        # Update the user_settings dictionary
        user_settings["theme"] = values[1]
        user_settings["widget_theme"] = values[2]
        user_settings["text_size"] = values[3]
        user_settings["text_color"] = values[4]
        user_settings["font_family"] = values[5]

    def update_text_color(self):
        global text_color
        text_color = user_settings["text_color"]

    def on_close(self):
        Settings._instance = None
        self.root.destroy()

    def run(self):
        self.root.mainloop()

class FileManager(CredentialManager):
    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is not None:
            cls.popup(cls._instance.root, "Import/Export window is already open")
            return cls._instance
        cls._instance = super(FileManager, cls).__new__(cls)
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
        self.root.title("Import/Export Manager")
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
        main_container = ctk.CTkFrame(self.root)
        main_container.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        main_container.grid_columnconfigure(0, weight=1)
        main_container.grid_rowconfigure(1, weight=1)
        
        # Style definitions
        title_style = {"font": title_type, "text_color": text_color}
        subtitle_style = {"font": subtitle_type, "text_color": text_color}
        button_style = {
            "font": text_type,
            "fg_color": button_fg_color,
            "text_color": text_color,
            "height": 35
        }
        
        # Title
        title = ctk.CTkLabel(main_container, text="Import/Export Credentials", **title_style)
        title.grid(row=0, column=0, sticky="w", pady=(0, 20))
        
        # Create content frame
        content_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        content_frame.grid(row=1, column=0, sticky="nsew")
        content_frame.grid_columnconfigure(0, weight=1)
        content_frame.grid_columnconfigure(1, weight=1)
        
        # Left frame for database selection
        left_frame = ctk.CTkFrame(content_frame, fg_color="#242424")
        left_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        left_frame.grid_columnconfigure(0, weight=1)
        
        # Database selection title
        db_title = ctk.CTkLabel(left_frame, text="Select Database", **subtitle_style)
        db_title.grid(row=0, column=0, sticky="w", padx=20, pady=(20, 10))
        
        # Database selection radio buttons
        self.db_var = StringVar(value="AllItems")
        radio_style = {"font": text_type, "text_color": text_color}
        
        all_items_radio = ctk.CTkRadioButton(
            left_frame,
            text="All Items",
            variable=self.db_var,
            value="AllItems",
            **radio_style
        )
        all_items_radio.grid(row=1, column=0, sticky="w", padx=40, pady=5)
        
        favourites_radio = ctk.CTkRadioButton(
            left_frame,
            text="Favourites",
            variable=self.db_var,
            value="Favourites",
            **radio_style
        )
        favourites_radio.grid(row=2, column=0, sticky="w", padx=40, pady=5)
        
        # Right frame for import/export options
        right_frame = ctk.CTkFrame(content_frame, fg_color="#242424")
        right_frame.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        right_frame.grid_columnconfigure(0, weight=1)
        
        # Import/Export title
        action_title = ctk.CTkLabel(right_frame, text="Available Actions", **subtitle_style)
        action_title.grid(row=0, column=0, sticky="w", padx=20, pady=(20, 10))
        
        # Create buttons frame
        buttons_frame = ctk.CTkFrame(right_frame, fg_color="transparent")
        buttons_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=10)
        buttons_frame.grid_columnconfigure(0, weight=1)
        
        # Import buttons
        import_label = ctk.CTkLabel(buttons_frame, text="Import From:", **text_style)
        import_label.grid(row=0, column=0, sticky="w", pady=(0, 10))
        
        import_json_btn = ctk.CTkButton(
            buttons_frame,
            text="Import from JSON",
            command=self.import_from_json,
            **button_style
        )
        import_json_btn.grid(row=1, column=0, sticky="ew", pady=5)
        
        import_csv_btn = ctk.CTkButton(
            buttons_frame,
            text="Import from CSV",
            command=self.import_from_csv,
            **button_style
        )
        import_csv_btn.grid(row=2, column=0, sticky="ew", pady=5)
        
        # Export buttons
        export_label = ctk.CTkLabel(buttons_frame, text="Export As:", **text_style)
        export_label.grid(row=3, column=0, sticky="w", pady=(20, 10))
        
        export_json_btn = ctk.CTkButton(
            buttons_frame,
            text="Export as JSON",
            command=lambda: self.export_as_json(self.db_var.get(), self.db_var.get()),
            **button_style
        )
        export_json_btn.grid(row=4, column=0, sticky="ew", pady=5)
        
        export_csv_btn = ctk.CTkButton(
            buttons_frame,
            text="Export as CSV",
            command=lambda: self.export_as_csv(self.db_var.get(), self.db_var.get()),
            **button_style
        )
        export_csv_btn.grid(row=5, column=0, sticky="ew", pady=5)
        
        # Status label
        self.status_label = ctk.CTkLabel(
            main_container,
            text="",
            font=text_type,
            text_color=text_color
        )
        self.status_label.grid(row=2, column=0, sticky="w", pady=(20, 0))
    
    def update_status(self, message, is_error=False):
        self.status_label.configure(
            text=message,
            text_color="red" if is_error else text_color
        )
        self.root.after(3000, lambda: self.status_label.configure(text=""))  # Clear after 3 seconds
    
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
    
    def export_as_json(self, database, table):
        try:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json")],
                title="Export as JSON"
            )
            if not file_path:
                return
            
            db_path = ALL_ITEMS_DB if database == "AllItems" else FAVOURITES_DB
            
            with sqlite3.connect(db_path) as db:
                cursor = db.cursor()
                cursor.execute(f"SELECT * FROM {table}")
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
    
    def export_as_csv(self, database, table):
        try:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv")],
                title="Export as CSV"
            )
            if not file_path:
                return
            
            db_path = ALL_ITEMS_DB if database == "AllItems" else FAVOURITES_DB
            
            with sqlite3.connect(db_path) as db:
                cursor = db.cursor()
                cursor.execute(f"SELECT * FROM {table}")
                rows = cursor.fetchall()
                
                with open(file_path, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['id', 'title', 'username', 'password', 'website', 'notes'])
                    writer.writerows(rows)
            
            self.update_status("Export successful!")
        except Exception as e:
            self.update_status(f"Export failed: {str(e)}", True)
    
    def on_close(self):
        FileManager._instance = None
        self.root.destroy()
    
    def run(self):
        self.root.mainloop()

class AddCredential(CredentialManager):
    _instance = None

    def __new__(cls, database, table, credential_array):
        if cls._instance is not None:
            cls.popup(cls._instance.root, "Add Credential window is already open")
            return cls._instance
        cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, database, table, credential_array):
        if hasattr(self, 'root'):
            return
        super().__init__(root)
        self.root = ctk.CTk()
        self.database = database
        self.table = table
        self.credentialArray = credential_array
        self.setup_window()
        self.create_widgets()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def setup_window(self):
        self.root.title("Add A Credential")
        self.root.attributes('-topmost', True)
        root_width = 600
        root_height = 600
        self.root.geometry(f"{root_width}x{root_height}")
        self.root.resizable(False, False)

    def create_widgets(self):
        heading1 = ctk.CTkLabel(self.root, text="Website:", **label_style)
        heading1.pack(pady=(20, 10))
        self.website_entry = ctk.CTkEntry(self.root, width=300, **entry_style)
        self.website_entry.pack(pady=(0, 10))
        heading2 = ctk.CTkLabel(self.root, text="Username:", **label_style)
        heading2.pack(pady=(20, 10))
        self.username_entry = ctk.CTkEntry(self.root, width=300, **entry_style)
        self.username_entry.pack(pady=(0, 10))
        heading3 = ctk.CTkLabel(self.root, text="Password:", **label_style)
        heading3.pack(pady=(20, 10))
        self.password_entry = ctk.CTkEntry(self.root, width=300, show="*", **entry_style)
        self.password_entry.pack(pady=(0, 10))
        heading4 = ctk.CTkLabel(self.root, text="Confirm Password:", **label_style)
        heading4.pack(pady=(20, 10))
        self.confirm_password_entry = ctk.CTkEntry(self.root, width=300, show="*",
                                                   **entry_style)
        self.confirm_password_entry.pack(pady=(0, 10))
        add_button = ctk.CTkButton(self.root, text="Add", width=200,
                                   command=self.add_values, **button_style)
        add_button.pack(pady=(20, 10))

    def is_master_password_present(self):
        pass # do nothing

    def add_values(self):
        # Get the values from the text entries
        website = self.website_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()

        # Check if any of the fields are empty
        if not website or not username or not password or not confirm_password:
            # If any field is empty, show a message to the user
            self.popup(self.root, "Please fill in all the fields")
            # Clear the text entries
            self.website_entry.delete(0, 'end')
            self.username_entry.delete(0, 'end')
            self.password_entry.delete(0, 'end')
            self.confirm_password_entry.delete(0, 'end')
        elif password != confirm_password:
            # If passwords don't match, show an error message
            self.popup(self.root, "Passwords do not match")
            # Clear the password fields
            self.password_entry.delete(0, 'end')
            self.confirm_password_entry.delete(0, 'end')
        else:
            try:
                # Check if the credential already exists
                for credential in self.credentialArray:
                    if credential[1] == website and credential[2] == username:
                        self.popup(self.root, "Credential already exists")
                        return # Exit the function if credential already exists
                # If all entries are filled, passwords match, and credential doesn't exist, proceed to encrypt the password
                encrypted_password = self.encrypt_password(password)
                # Insert the encrypted password into the database
                insert_values = f"""INSERT INTO {self.table}(website, username, password)
                VALUES (?, ?, ?) """
                with sqlite3.connect(f"D:/Credential Manager/test/PasswordManager/{self.database}.db") as db:
                    cursor = db.cursor()
                    cursor.execute(insert_values, (website, username, encrypted_password))
                    db.commit()
                # Destroy the current window after a short delay and create a new instance of
                MainVault
                self.root.after(100, self.destroy_window_and_create_main_vault)
            except Exception as e:
                self.popup(self.root, f"An error occurred: {e}")

    def destroy_window_and_create_main_vault(self):
        self.popup(self.root, "Credential Added Successfully")
        AddCredential._instance = None
        self.root.destroy()
        """
        # First, check if `self.root` is not destroyed already
        if self.root:
            # Now you need to initialize the new MainVault before destroying the old root
            if self.database == "AllItems":
                app = MainVault(ctk.CTk(), "All Items", "AllItems", "all_items")
            else:
                app = MainVault(ctk.CTk(), "Favourites", "Favourites", "Favourites")
            self.root.destroy() # Destroy the root after initializing MainVault
            app.run()
        else:
            # Handle cases where the root might already be destroyed
            print("Window is already destroyed.")
        """

    def on_close(self):
        # Reset the _instance attribute of AddCredential
        AddCredential._instance = None
        # Destroy the current instance
        self.root.destroy()

    def run(self):
        self.root.mainloop()

class EditCredential(CredentialManager):
    _instance = None

    def __new__(cls, database, table, record):
        if cls._instance is not None:
            cls.popup(cls._instance.root, "Edit Credential window is already open")
            return cls._instance
        cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, database, table, record):
        if hasattr(self, 'root'):
            return
        self.root = ctk.CTk()
        super().__init__(self.root)
        self.database = database
        self.table = table
        self.previous_website = record[1]
        self.previous_username = record[2]
        self.previous_password = record[3]
        self.setup_window()
        self.create_widgets()
        self.assign_values()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def setup_window(self):
        self.root.title("Edit A Credential")
        self.root.attributes('-topmost', True)
        root_width = 600
        root_height = 400
        self.root.geometry(f"{root_width}x{root_height}")
        self.root.resizable(False, False)

    def create_widgets(self):
        heading1 = ctk.CTkLabel(self.root, text="Website:", **self.label_style)
        heading1.pack(pady=(20, 10))
        self.website_entry = ctk.CTkEntry(self.root, width=300, **self.entry_style)
        self.website_entry.pack(pady=(0, 10))
        heading2 = ctk.CTkLabel(self.root, text="Username:", **self.label_style)
        heading2.pack(pady=(20, 10))
        self.username_entry = ctk.CTkEntry(self.root, width=300, **self.entry_style)
        self.username_entry.pack(pady=(0, 10))
        heading3 = ctk.CTkLabel(self.root, text="Password:", **self.label_style)
        heading3.pack(pady=(20, 10))
        self.password_entry = ctk.CTkEntry(self.root, width=300, **self.entry_style)
        self.password_entry.pack(pady=(0, 10))
        add_button = ctk.CTkButton(self.root, text="Apply", width=200,
                                   command=self.apply_values, **self.button_style)
        add_button.pack(pady=(20, 10))

    def is_master_password_present(self):
        pass

    def assign_values(self):
        # Get the website from the entry
        website = self.previous_website
        username = self.previous_username
        password = self.previous_password
        print(website, username, password, self.decrypt_password(password))
        # Connect to the database and retrieve the credential details
        with sqlite3.connect(f"D:/Credential Manager/test/PasswordManager/{self.database}.db") as db:
            cursor = db.cursor()
            cursor.execute(f"SELECT * FROM {self.table} WHERE website = ? AND username = ? AND password = ?", (website, username, password))
            credential = cursor.fetchone()
            if credential:
                # Populate the text entries with the retrieved credential details
                self.website_entry.delete(0, 'end')
                self.website_entry.insert(0, credential[1])
                self.username_entry.delete(0, 'end')
                self.username_entry.insert(0, credential[2])
                # Decrypt the password and insert it into the password entry
                decrypted_password = self.decrypt_password(credential[3]) # Assuming password is the third column
                self.password_entry.delete(0, 'end')
                self.password_entry.insert(0, decrypted_password)
            else:
                # If credential not found, show an error message
                self.popup(self.root, f"No credential found for website: {website}")

    def apply_values(self):
        # Get the updated values from the text entries
        new_website = self.website_entry.get()
        new_username = self.username_entry.get()
        new_password = self.password_entry.get()
        # Check if any of the fields are empty
        if not all((new_website, new_username, new_password)):
            # If any field is empty, show an error message and return
            self.popup(self.root, "Please fill in all fields.")
            return
        # Check if the values have actually changed
        if new_website != self.previous_website or new_username != self.previous_username or new_password != self.previous_password:
            # Check to see if the credential exists
            with sqlite3.connect(f"D:/Credential Manager/test/PasswordManager/{self.database}.db") as db:
                cursor = db.cursor()
                cursor.execute(f"SELECT * FROM {self.table} WHERE website = ? AND username = ?", (self.previous_website, self.previous_username))
                credential = cursor.fetchone()
                if credential:
                    # Update the database with the new values
                    update_query = f"UPDATE {self.table} SET website = ?, username = ?, password = ? WHERE website = ? AND username = ? AND password = ?"
                    encrypted_password = self.encrypt_password(new_password)
                    with sqlite3.connect(f"D:/Credential Manager/test/PasswordManager/{self.database}.db") as db:
                        cursor = db.cursor()
                        cursor.execute(update_query, (new_website, new_username,
                        encrypted_password, self.previous_website, self.previous_username,
                        self.previous_password))
                    db.commit()
                    self.root.after(100, self.destroy_window_and_create_main_vault)
                else:
                    # If credential not found, show an error message
                    self.popup(self.root, f"No credential found for website: {self.previous_website} and username: {self.previous_username}")
        else:
            # No changes were made, so inform the user
            self.popup(self.root, "No changes made.")

    def destroy_window_and_create_main_vault(self):
        self.popup(self.root, "Change Successfull")
        EditCredential._instance = None
        self.root.destroy()
        """EditCredential._instance = None
        if self.database == "AllItems":
            self.root.destroy()
            app = MainVault(root, "All Items", "AllItems", "all_items")
        else:
            self.root.destroy()
            app = MainVault(root, "Favourites", "Favourites", "Favourites")
        app.run()"""

    def on_close(self):
        EditCredential._instance = None
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
