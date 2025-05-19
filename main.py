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
        self.is_master_password_present()
    
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
    
    def is_master_password_present(self):
        try:
            # Connect to the database using MASTER_PASSWORD_DB
            with sqlite3.connect(MASTER_PASSWORD_DB) as db:
                cursor = db.cursor()
                # Execute a query to check if any records exist
                cursor.execute("SELECT * FROM master_password")
                count = cursor.fetchone()
                if count:
                    self.run_login_screen()
                else:
                    self.run_create_master_password()
        except sqlite3.Error as e:
            print(f"SQLite error: {e}")
    
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
        super().__init__(root)
        self.root = root
        self.setup_window()
        self.create_widgets()
        # Register the close icon as a valid method of termination
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def setup_window(self):
        self.root.title("Create Master Password")
        root_width = 600
        root_height = 300
        self.root.geometry(f"{root_width}x{root_height}")
        self.root.resizable(False, False)
    
    def create_widgets(self):
        heading1 = ctk.CTkLabel(self.root, text="Enter A Master Password", **self.label_style)
        heading1.pack(pady=(20, 10))
        self.password_entry = ctk.CTkEntry(self.root, width=200, **self.entry_style)
        self.password_entry.pack(pady=(0, 20))
        heading2 = ctk.CTkLabel(self.root, text="Re-Enter Master Password", **self.label_style)
        heading2.pack(pady=(20, 10))
        self.confirm_password_entry = ctk.CTkEntry(self.root, width=200, **self.entry_style)
        self.confirm_password_entry.pack(pady=(0, 20))
        self.submit_button = ctk.CTkButton(self.root, text="Submit", width=120,
                                           command=self.save_master_password, **self.button_style)
        self.submit_button.pack(pady=(0, 20))
    
    def is_master_password_present(self):
        pass
    
    def save_master_password(self):
        password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()
    
        # Checking for at least one number and one symbol
        has_number = re.search(r'\d', password)
        has_symbol = re.search(r'\W', password)
    
        # Checking if passwords are not identical
        if password != confirm_password:
            self.popup(self.root, "Save Failed. Passwords are not identical")
            self.password_entry.delete(0, "end")
            self.confirm_password_entry.delete(0, "end")
        # Checking if password length is less than 7 characters
        elif len(password) < 7:
            self.popup(self.root, "Save Failed. Password must be greater than 7 characters")
            self.password_entry.delete(0, "end")
            self.confirm_password_entry.delete(0, "end")
        # Checking for at least one number in the password
        elif not has_number:
            self.popup(self.root, "Save Failed. Password must contain at least 1 number")
            self.password_entry.delete(0, "end")
            self.confirm_password_entry.delete(0, "end")
        # Checking for at least one symbol in the password
        elif not has_symbol:
            self.popup(self.root, "Save Failed. Passwords must contain at least 1 symbol")
            self.password_entry.delete(0, "end")
            self.confirm_password_entry.delete(0, "end")
        else:
            # If all conditions are met, encrypt and hash the password
            hashed_password = self.hash_text(password.encode("utf-8"))
            encrypted_hashed_password = self.encrypt_password(hashed_password)
            insert_password = "INSERT INTO master_password (password) VALUES (?)"
            with sqlite3.connect(MASTER_PASSWORD_DB) as db:
                cursor = db.cursor()
                cursor.execute(insert_password, (encrypted_hashed_password,))
                db.commit()
            self.popup(self.root, "Save Successful")
            app = MainVault(self.root, "All Items", "AllItems", "all_items")
            app.run()
    
    def on_close(self):
        self.root.destroy()
    
    def run(self):
        self.root.mainloop()

class LoginScreen(CredentialManager):
    def __init__(self, root):
        super().__init__(root)
        self.root = root
        self.setup_window()
        self.create_widgets()
        # Register the close icon as a valid method of termination
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def setup_window(self):
        self.root.title("Login Screen")
        self.root_width = 700
        self.root_height = 300
        self.root.geometry(f"{self.root_width}x{self.root_height}")
        self.root.resizable(False, False)
    
    def create_widgets(self):
        self.heading1 = ctk.CTkLabel(self.root, text="Your vault is locked. Please verify your master password to continue.", **self.label_style)
        self.heading1.grid(row=0, column=0, pady=10)
        self.password = ctk.CTkEntry(self.root, width=300, height=45,
                                     placeholder_text="Master Password", show="*", **self.entry_style)
        self.password.grid(row=1, column=0, pady=5)
        self.unlock = ctk.CTkButton(self.root, text="Unlock",
                                    command=self.verify_master_password, **self.button_style)
        self.unlock.grid(row=2, column=0, pady=10)
    
    def is_master_password_present(self):
        pass
    
    def get_master_password(self):
        # Hash the password entered
        hashed_entered_password = self.hash_text(self.password.get().encode("utf-8"))
        # Connect to the database and retrieve the master password
        db_path = get_db_path("MPasswords")
        with sqlite3.connect(db_path) as db:
            cursor = db.cursor()
            cursor.execute("SELECT * FROM master_password WHERE id = 1")
            stored_password = cursor.fetchone()
            if stored_password:
                # Get the encrypted stored password from the database
                encrypted_stored_password = stored_password[1]
                # Decrypt the stored encrypted password
                decrypted_stored_password = self.decrypt_password(encrypted_stored_password)
                # Verify if the entered password matches the stored password
                if hashed_entered_password == decrypted_stored_password:
                    return True
        return False
    
    def verify_master_password(self):
        # Verify if the entered password matches the stored password
        match = self.get_master_password()
        if match:
            self.root.after(100, self.destroy_and_create_mainvault)
        else:
            self.popup(self.root, "Incorrect Password")
            self.password.delete(0, 'end')
    
    def destroy_and_create_mainvault(self):
        self.root.destroy()
        import customtkinter as ctk
        app = MainVault(ctk.CTk(), "All Items", "AllItems", "all_items")
        app.run()
    
    def cleanup_widgets(self):
        # Cleanup canvas elements if they exist
        if hasattr(self, 'heading1'):
            self.heading1.destroy()
        if hasattr(self, 'password'):
            self.password.destroy()
        if hasattr(self, 'unlock'):
            self.unlock.destroy()
    
    def on_close(self):
        self.cleanup_widgets()  # Clean up canvas elements
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
        
        # Fetch credentials from database with pagination
        with sqlite3.connect(db_path) as db:
            cursor = db.cursor()
            cursor.execute(f"SELECT * FROM {table} ORDER BY {sort_by} LIMIT {self.items_per_page} OFFSET {offset}")
            rows = cursor.fetchall()
            
            # Create a frame for each credential
            for row in rows:
                frame = ctk.CTkFrame(self.scrollable_frame)
                frame.pack(fill="x", padx=10, pady=5)
                
                # Create labels for each field
                for col, value in enumerate(row):
                    if col == 0:  # Skip ID column
                        continue
                    label = ctk.CTkLabel(frame, text=str(value), **self.label_style)
                    label.pack(side="left", padx=5)
                
                # Create edit and delete buttons
                edit_button = ctk.CTkButton(frame, text="Edit", command=lambda r=row: self.edit_credential(r), **self.button_style)
                edit_button.pack(side="right", padx=5)
                
                delete_button = ctk.CTkButton(frame, text="Delete", command=lambda r=row: self.delete_record(r[0], database, table), **self.button_style)
                delete_button.pack(side="right", padx=5)
                
                if database == "AllItems":
                    favorite_button = ctk.CTkButton(frame, text="Favorite", command=lambda r=row: self.favorite_record(r), **self.button_style)
                    favorite_button.pack(side="right", padx=5)
    
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
        self.root.title("Main Vault")
        self.root_width = 1800
        self.root_height = 800
        self.root.geometry(f"{self.root_width}x{self.root_height}")
        self.root.resizable(False, False)

    def initialize_left_frame(self):
        left_frame_color = "#0f0f0f"
        self.left_frame_width = 300
        self.left_frame_height = self.root_height
        button_style = {"font": subtitle_type, "fg_color": left_frame_color, "border_width":
                       button_border_width, "border_color": left_frame_color, "text_color": text_color}
        frame_style = {"fg_color": left_frame_color}
        self.left_frame = ctk.CTkFrame(self.root, width=self.left_frame_width,
                                       height=self.left_frame_height, **frame_style)
        self.left_frame.grid(row=0, column=0, sticky="nse")
        self.left_frame.grid_propagate(False)

        # Define a lambda function to call initialize_right_frame with the "Favourites" argument
        initialize_all_items_func = lambda: self.initialize_right_frame("All Items", "AllItems", "all_items")
        btn = ctk.CTkButton(self.left_frame,
                            text="All items",
                            command=initialize_all_items_func, **button_style)
        btn.grid(column=0, row=0, pady=10)

        # Define a lambda function to call initialize_right_frame with the "Favourites" argument
        initialize_favourites_func = lambda: self.initialize_right_frame("Favourites", "Favourites", "Favourites")
        favourites_button = ctk.CTkButton(self.left_frame, text="Favourites",
                                          command=initialize_favourites_func, **button_style)
        favourites_button.grid(column=0, row=1, pady=10)

        self.random_password_generator_button = ctk.CTkButton(self.left_frame,
                                                               text="Random Password Generator",
                                                               command=self.run_random_password_generator,
                                                               **button_style)
        self.random_password_generator_button.grid(column=0, row=2, pady=10)

        self.btn = ctk.CTkButton(self.left_frame,
                                 text="Settings",
                                 command=self.run_settings, **button_style)
        self.btn.grid(column=0, row=3, pady=10)

        self.btn = ctk.CTkButton(self.left_frame,
                                 text="Import/Export",
                                 command=self.run_filemanager, **button_style)
        self.btn.grid(column=0, row=4, pady=10)

        self.btn = ctk.CTkButton(self.left_frame,
                                 text="Help",
                                 command=self.run_additional_information, **button_style)
        self.btn.grid(column=0, row=5, pady=10)

    def initialize_right_frame(self, window_title, database, table):
        # Clear everything in the root window except the left frame
        self.clear_right_widgets()
        self.right_frame_width = self.root_width - self.left_frame_width
        self.right_frame_height = self.root_height
        self.window_title = window_title

        # Initialize the right frame
        self.right_frame = ctk.CTkFrame(self.root, width=self.right_frame_width, height=self.right_frame_height)
        self.right_frame.grid(row=0, column=1, sticky="nsew")
        self.right_frame.grid_propagate(False)
        
        # Configure grid for right frame
        self.right_frame.columnconfigure(0, weight=1)
        self.right_frame.rowconfigure(0, weight=0)
        self.right_frame.rowconfigure(1, weight=0)
        self.right_frame.rowconfigure(2, weight=1)
        
        # Create title label with explicit styling
        self.title_label = ctk.CTkLabel(
            self.right_frame, 
            text=window_title,
            font=title_type,
            text_color=text_color,
            fg_color="transparent"  # Make background transparent
        )
        self.title_label.grid(row=0, column=0, sticky="w", padx=20, pady=10)
        
        # Set other labels as needed
        website_label = ctk.CTkButton(self.right_frame, text="Website", font=subtitle_type,
                                      fg_color="transparent",
                                      border_width=None, border_color="Transparent",
                                      text_color=text_color,
                                      command=lambda: self.load_credentials("website", database, table))
        website_label.grid(row=1, column=0, padx=10, pady=30)

        username_label = ctk.CTkButton(self.right_frame, text="Username", font=subtitle_type,
                                       fg_color="transparent",
                                       border_width=None, border_color="Transparent",
                                       text_color=text_color,
                                       command=lambda: self.load_credentials("username", database, table))
        username_label.grid(row=1, column=1, padx=30)

        password_label = ctk.CTkLabel(self.right_frame, text="Password", font=subtitle_type, text_color=text_color)
        password_label.grid(row=1, column=2, padx=30)

        self.initialize_search_frame(database, table)
        self.initialize_scrollable_frame(database, table)
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
        # Create a canvas to hold the scrollable frame
        self.canvas = ctk.CTkCanvas(self.right_frame, width=self.right_frame_width - 20,
                                  height=self.right_frame_height - 200,
                                  bg="#242424", highlightthickness=0)
        self.canvas.grid(row=2, column=0, columnspan=4, sticky="nsew", padx=10)

        # Create a frame inside the canvas to hold the credentials
        self.scrollable_frame = ctk.CTkFrame(self.canvas)
        self.scrollable_frame.grid(row=0, column=0, sticky="nsew")

        # Create a scrollbar and associate it with the canvas
        self.scrollbar = ctk.CTkScrollbar(self.right_frame, orientation="vertical",
                                        command=self.canvas.yview)
        self.scrollbar.grid(row=2, column=4, sticky="ns")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        # Bind the scrollable frame to the canvas
        self.canvas_frame = self.canvas.create_window((0, 0),
                                                    window=self.scrollable_frame,
                                                    anchor="nw")

        # Configure grid weights
        self.scrollable_frame.grid_columnconfigure(0, weight=1)
        self.right_frame.grid_columnconfigure(0, weight=1)

        # Bind events for proper scrolling behavior
        self.scrollable_frame.bind("<Configure>",
                                 lambda e: self.canvas.configure(
                                     scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", self.on_canvas_configure)
        self.canvas.bind_all("<MouseWheel>", self.on_mousewheel)

        # Load credentials into the scrollable frame
        self.load_credentials("website", database, table)

    def initialize_lifted_widgets(self, database, table):
        # Create a frame for pagination controls
        pagination_frame = ctk.CTkFrame(self.right_frame, fg_color="transparent")
        pagination_frame.grid(row=3, column=0, columnspan=4, pady=10)

        # Add pagination buttons
        prev_button = ctk.CTkButton(pagination_frame, text="Previous",
                                  command=lambda: self.change_page(-1, database, table))
        prev_button.grid(row=0, column=0, padx=5)

        next_button = ctk.CTkButton(pagination_frame, text="Next",
                                  command=lambda: self.change_page(1, database, table))
        next_button.grid(row=0, column=1, padx=5)

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
        app = Settings()
        app.run()

    def run_filemanager(self):
        app = FileManager()
        app.run()

    def run_random_password_generator(self):
        app = RandomPasswordGenerator()
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
        super().__init__(None)
        self.parent = parent
        self.root = ctk.CTk()
        self.setup_window()
        self.create_widgets()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def setup_window(self):
        self.root.title("Random Password Generator")
        self.root.attributes('-topmost', True)
        root_width = 900
        root_height = 500
        self.root.geometry(f"{root_width}x{root_height}")
        self.root.resizable(False, False)

    def create_widgets(self):
        button_style = {"font": text_type, "fg_color": button_fg_color, "border_width":
                       button_border_width, "border_color": button_border_color}
        label_style = {"font": title_type, "text_color": text_color, "fg_color": title_fg_color}
        #Frame for the password generator
        pass_generator_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        pass_generator_frame.place(relx=0, rely=0, relwidth=0.75, relheight=1)
        #Frame for the checkboxes and position it at the top
        checkbox_frame = ctk.CTkFrame(self.root, fg_color="#0f0f0f")
        checkbox_frame.place(relx=0.75, rely=0, relwidth=0.25, relheight=1)
        #Checkbox Frame Widgets
        self.uppercase_var = IntVar()
        self.lowercase_var = IntVar()
        self.numbers_var = IntVar()
        self.symbols_var = IntVar()
        uppercase_btn = ctk.CTkCheckBox(checkbox_frame, text="Uppercase",
                                        variable=self.uppercase_var)
        uppercase_btn.grid(row=0, column=0, sticky="w")
        lowercase_btn = ctk.CTkCheckBox(checkbox_frame, text="Lowercase",
                                        variable=self.lowercase_var)
        lowercase_btn.grid(row=1, column=0, sticky="w")
        numbers_btn = ctk.CTkCheckBox(checkbox_frame, text="Numbers",
                                        variable=self.numbers_var)
        numbers_btn.grid(row=2, column=0, sticky="w")
        symbols_btn = ctk.CTkCheckBox(checkbox_frame, text="Symbols",
                                        variable=self.symbols_var)
        symbols_btn.grid(row=3, column=0, sticky="w")
        # Password Generator Frame Widgets
        title = ctk.CTkLabel(pass_generator_frame, text="Customize your password",
                             **label_style)
        title.grid(row=0, column=0, columnspan = 2, sticky="w", padx = 30)
        self.slider_label = ctk.CTkLabel(pass_generator_frame, text="Password Length: 25",
                                         **label_style)
        self.slider_label.grid(row=1, column=0, sticky="w", pady=20, padx = 30)
        self.slider = ctk.CTkSlider(pass_generator_frame, from_=1, to=50,
                                    number_of_steps=50, command=self.slider_event,
                                    fg_color = button_fg_color, button_color = button_fg_color,
                                    button_hover_color=button_fg_color, width = 400)
        self.slider.grid(sticky="w", row=2, column=0, columnspan = 2, pady = 20, padx = 30)
        self.generated_password_label = ctk.CTkLabel(pass_generator_frame,
                                                     text="Generated Password: ", **label_style)
        self.generated_password_label.grid(row=3, column=0, columnspan = 2, padx = 30)
        generate_btn = ctk.CTkButton(master=pass_generator_frame, text="Generate Password",
                                     command=self.update_random_password, **button_style)
        generate_btn.grid(row=4, column=0, pady=30, padx=30, sticky="e")
        copy_password_btn = ctk.CTkButton(master=pass_generator_frame, text="Copy To Clipboard",
                                          command=self.copytext, **button_style)
        copy_password_btn.grid(row=4, column=1, pady=30, sticky = "w")

    def slider_event(self, value):
        value_int = int(value) # Convert the float value to an integer
        formatted_value = f"{value_int:02}"
        self.slider_label.configure(text=f"Password Length: {formatted_value}")

    def update_random_password(self):
        length = int(self.slider.get()) #Sets length of the password to the value of the slider
        character_sets = [] #Creates a character set that will be appended to by the required character types
        if self.uppercase_var.get():
            character_sets.append(string.ascii_uppercase)
        if self.lowercase_var.get():
            character_sets.append(string.ascii_lowercase)
        if self.numbers_var.get():
            character_sets.append(string.digits)
        if self.symbols_var.get():
            character_sets.append(string.punctuation)
        if character_sets:
            alphabet = ''.join(character_sets) # Combine selected character sets
            # Takes a random character from the character set
            # Creates a randomly generated password
            # Repeats this process as many times as the users required length to fill the password length requirement
            generated_password = ''.join(secrets.choice(alphabet) for _ in range(length))
            # Displays the generated password on a new line
            self.generated_password_label.configure(text=f"Generated Password:\n{generated_password}")
        else:
            # Displays a popup to tell the user to select a checkbox if none are selected
            self.popup(self.root, "Please select at least one character set")

    def copytext(self):
        generated_password = self.generated_password_label.cget("text") # Get the password from the generated password label
        lines = generated_password.split('\n') # Split the text into lines
        if len(lines) >= 2:
            # Get the password from the second second line as the first line is occupied by
            "Generated Password:"
            password = lines[1]
            pyperclip.copy(password)
            self.popup(self.root, "Password Copied to Clipboard")
        else:
            self.popup(self.root, "No Password Found")

    def on_close(self):
        RandomPasswordGenerator._instance = None
        self.root.destroy()

class Settings(CredentialManager):
    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(Settings, cls).__new__(cls)
        return cls._instance
    
    def __init__(self, parent=None):
        super().__init__(None)
        self.parent = parent
        self.root = ctk.CTk()
        self.setup_window()
        self.create_widgets()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def setup_window(self):
        self.root.title("Settings")
        root_width = 700
        root_height = 350
        self.root.geometry(f"{root_width}x{root_height}")
        self.root.resizable(False, False)

    def create_widgets(self):
        button_style = {"font": text_type, "fg_color": button_fg_color, "border_width":
                       button_border_width, "border_color": button_border_color, "text_color": text_color}
        radio_button_style = {"fg_color": button_fg_color}
        label_style = {"font": title_type, "text_color": text_color, "fg_color": title_fg_color}
        # Theme Widgets
        theme_label = ctk.CTkLabel(self.root, text="Theme:", **label_style)
        theme_label.grid(row=0, column=0, padx=20, pady=10, sticky="w")
        self.theme_var = StringVar()
        self.theme_var.set(user_settings["theme"])
        theme_button = ctk.CTkRadioButton(self.root, text="Automatic",
                                        variable=self.theme_var, value="system",
                                        command=None, **radio_button_style)
        theme_button.grid(row=0, column=1, padx=20, pady=10, sticky="w")
        theme_button = ctk.CTkRadioButton(self.root, text="Light",
                                        variable=self.theme_var, value="light",
                                        command=None, **radio_button_style)
        theme_button.grid(row=0, column=2, padx=20, pady=10, sticky="w")
        theme_button = ctk.CTkRadioButton(self.root, text="Dark",
                                        variable=self.theme_var, value="dark",
                                        command=None, **radio_button_style)
        theme_button.grid(row=0, column=3, padx=20, pady=10, sticky="w")
        # Widget Theme Options
        widget_theme_label = ctk.CTkLabel(self.root, text="Widget Theme:", **label_style)
        widget_theme_label.grid(row=1, column=0, padx=20, pady=10, sticky="w")
        self.widget_theme_var = StringVar()
        self.widget_theme_var.set(user_settings["widget_theme"])
        widget_theme_button = ctk.CTkRadioButton(self.root, text="Blue",
                                                variable=self.widget_theme_var, value="blue",
                                                command=None, **radio_button_style)
        widget_theme_button.grid(row=1, column=1, padx=20, pady=10, sticky="w")
        widget_theme_button = ctk.CTkRadioButton(self.root, text="Dark Blue",
                                                variable=self.widget_theme_var, value="dark-blue",
                                                command=None, **radio_button_style)
        widget_theme_button.grid(row=1, column=2, padx=20, pady=10, sticky="w")
        widget_theme_button = ctk.CTkRadioButton(self.root, text="Green",
                                                variable=self.widget_theme_var, value="green",
                                                command=None, **radio_button_style)
        widget_theme_button.grid(row=1, column=3, padx=20, pady=10, sticky="w")
        # Text Size Option
        text_size_label = ctk.CTkLabel(self.root, text="Text Size:", **label_style)
        text_size_label.grid(row=2, column=0, padx=20, pady=10, sticky="w")
        self.text_size_var = IntVar()
        self.text_size_var.set(user_settings["text_size"])
        text_size_btn = ctk.CTkRadioButton(self.root, text="Small",
                                           variable=self.text_size_var, value=14,
                                           command=None, **radio_button_style)
        text_size_btn.grid(row=2, column=1, columnspan=2, padx=20, pady=10, sticky="w")
        text_size_btn = ctk.CTkRadioButton(self.root, text="Medium",
                                           variable=self.text_size_var, value=16,
                                           command=None, **radio_button_style)
        text_size_btn.grid(row=2, column=2, columnspan=2, padx=20, pady=10, sticky="w")
        text_size_btn = ctk.CTkRadioButton(self.root, text="Large",
                                           variable=self.text_size_var, value=18,
                                           command=None, **radio_button_style)
        text_size_btn.grid(row=2, column=3, columnspan=2, padx=20, pady=10, sticky="w")
        # Text Color Option
        text_color_label = ctk.CTkLabel(self.root, text="Text Color:", **label_style)
        text_color_label.grid(row=3, column=0, padx=20, pady=10, sticky="w")
        self.text_color_var = StringVar()
        self.text_color_var.set(user_settings["text_color"])
        text_color_options = ctk.CTkOptionMenu(self.root, values=["White", "Black", "Grey"],
                                               command=None,
                                               variable=self.text_color_var, fg_color = button_fg_color)
        text_color_options.grid(row=3, column=1, columnspan=2, padx=20, pady=10,
                               sticky="w")
        # Font Family Option
        font_family_label = ctk.CTkLabel(self.root, text="Font Family:", **label_style)
        font_family_label.grid(row=4, column=0, padx=20, pady=10, sticky="w")
        self.font_family_var = StringVar()
        self.font_family_var.set(user_settings["font_family"])
        font_family_options = ctk.CTkOptionMenu(
            self.root,
            values=["Arial", "IMPACT", "Times New Roman"],
            command=None,
            variable=self.font_family_var,
            fg_color=button_fg_color
        )
        font_family_options.grid(row=4, column=1, columnspan=2, padx=20, pady=10, sticky="w")
        # Apply Button
        apply_button = ctk.CTkButton(self.root, text="Apply Settings",
                                    command=self.apply_settings, **button_style)
        apply_button.grid(row=5, column=1, columnspan=2, padx=20, pady=10)

    def apply_settings(self):
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
        with sqlite3.connect("D:/Credential Manager/test/Password Manager/UserSettings.db") as db:
            cursor = db.cursor()
            # Update the settings in the database
            self.update_database(cursor, db)
            # Fetch and print the updated values
            cursor.execute("SELECT * FROM settings WHERE id = 1;")
            updated_values = cursor.fetchone()
            # Update the user_settings dictionary
            self.update_user_settings(updated_values)
        self.refresh_ui()
        self.on_close()

    def refresh_ui(self):
        # Set New Appearance Mode
        ctk.set_appearance_mode(user_settings["theme"])
        ctk.set_default_color_theme(user_settings["widget_theme"])
        text_type.configure(family=user_settings["font_family"], size=user_settings["text_size"])
        subtitle_type.configure(family=user_settings["font_family"],
                               size=user_settings["text_size"] + 2)
        title_type.configure(family=user_settings["font_family"], size=user_settings["text_size"]
                            + 4)
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
        # Reset the _instance attribute
        Settings._instance = None
        # Destroy the current instance
        self.root.after(50, self.root.destroy())

    def run(self):
        self.root.mainloop()

class FileManager(CredentialManager):
    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(FileManager, cls).__new__(cls)
        return cls._instance
    
    def __init__(self, parent=None):
        super().__init__(None)
        self.parent = parent
        self.root = ctk.CTk()
        self.setup_window()
        self.create_widgets()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def setup_window(self):
        self.root.title("File Manager")
        self.root.geometry("400x300")
        self.root.resizable(False, False)
    
    def create_widgets(self):
        # Create radio buttons for database selection
        self.db_var = StringVar(value="AllItems")
        all_items_radio = ctk.CTkRadioButton(self.root, text="All Items", variable=self.db_var, value="AllItems", **self.button_style)
        all_items_radio.pack(pady=10)
        favourites_radio = ctk.CTkRadioButton(self.root, text="Favourites", variable=self.db_var, value="Favourites", **self.button_style)
        favourites_radio.pack(pady=10)
        
        # Create buttons for import/export operations
        import_json_btn = ctk.CTkButton(self.root, text="Import from JSON", command=self.import_from_json, **self.button_style)
        import_json_btn.pack(pady=10)
        import_csv_btn = ctk.CTkButton(self.root, text="Import from CSV", command=self.import_from_csv, **self.button_style)
        import_csv_btn.pack(pady=10)
        export_json_btn = ctk.CTkButton(self.root, text="Export as JSON", command=lambda: self.export_as_json(self.db_var.get(), self.db_var.get()), **self.button_style)
        export_json_btn.pack(pady=10)
        export_csv_btn = ctk.CTkButton(self.root, text="Export as CSV", command=lambda: self.export_as_csv(self.db_var.get(), self.db_var.get()), **self.button_style)
        export_csv_btn.pack(pady=10)
    
    def determine_database(self):
        # Check which database radio button is selected
        if self.db_var.get() == "AllItems":
            return ALL_ITEMS_DB, "all_items"
        else:
            return FAVOURITES_DB, "favourites"
    
    def import_from_json(self):
        # Call determine_database to set database and table names
        db_path, table = self.determine_database()
        self.import_data_from_json(db_path, table)
    
    def import_from_csv(self):
        # Call determine_database to set database and table names
        db_path, table = self.determine_database()
        self.import_data_from_csv(db_path, table)
    
    def export_as_json(self, database, table):
        # Get file path from user
        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if not file_path:
            return
        
        # Determine which database to use
        db_path = ALL_ITEMS_DB if database == "AllItems" else FAVOURITES_DB
        
        # Fetch data from database
        with sqlite3.connect(db_path) as db:
            cursor = db.cursor()
            cursor.execute(f"SELECT * FROM {table}")
            rows = cursor.fetchall()
            
            # Convert to list of dictionaries
            data = []
            for row in rows:
                data.append({
                    'id': row[0],
                    'title': row[1],
                    'username': row[2],
                    'password': row[3],
                    'website': row[4],
                    'notes': row[5]
                })
            
            # Write to JSON file
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=4)
    
    def export_as_csv(self, database, table):
        # Get file path from user
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if not file_path:
            return
        
        # Determine which database to use
        db_path = ALL_ITEMS_DB if database == "AllItems" else FAVOURITES_DB
        
        # Fetch data from database
        with sqlite3.connect(db_path) as db:
            cursor = db.cursor()
            cursor.execute(f"SELECT * FROM {table}")
            rows = cursor.fetchall()
            
            # Write to CSV file
            with open(file_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['id', 'title', 'username', 'password', 'website', 'notes'])
                writer.writerows(rows)
    
    def import_data_from_json(self, database, table):
        # Get file path from user
        file_path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        if not file_path:
            return
        
        try:
            # Read JSON file
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Insert data into database
            with sqlite3.connect(database) as db:
                cursor = db.cursor()
                for item in data:
                    cursor.execute(f"INSERT INTO {table} (title, username, password, website, notes) VALUES (?, ?, ?, ?, ?)",
                                 (item['title'], item['username'], item['password'], item['website'], item['notes']))
                db.commit()
            
            self.popup(self.root, "Import successful")
        except Exception as e:
            self.popup(self.root, f"Import failed: {str(e)}")
    
    def import_data_from_csv(self, database, table):
        # Get file path from user
        file_path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if not file_path:
            return
        
        try:
            # Read CSV file
            with open(file_path, 'r') as f:
                reader = csv.DictReader(f)
                data = list(reader)
            
            # Insert data into database
            with sqlite3.connect(database) as db:
                cursor = db.cursor()
                for row in data:
                    cursor.execute(f"INSERT INTO {table} (title, username, password, website, notes) VALUES (?, ?, ?, ?, ?)",
                                 (row['title'], row['username'], row['password'], row['website'], row['notes']))
                db.commit()
            
            self.popup(self.root, "Import successful")
        except Exception as e:
            self.popup(self.root, f"Import failed: {str(e)}")
    
    def on_close(self):
        # Reset the _instance attribute
        FileManager._instance = None
        self.root.destroy()
    
    def is_master_password_present(self):
        pass
    
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
    _instance = None # Class variable to store the single instance

    def __new__(cls, *args, **kwargs):
        # If an instance of the class already exists, return it
        if cls._instance is not None:
            cls.popup(cls._instance.root, "Additional Information is already open")
            return cls._instance
        # If no instance exists, create a new one
        cls._instance = super(AdditionalInformation, cls).__new__(cls)
        return cls._instance

    def __init__(self, parent=None):
        if hasattr(self, 'root'): # Check if root attribute already exists
            return # Return without reinitializing if already initialized
        # Initialize the instance only if it's a new instance
        super().__init__(None)
        self.parent = parent
        self.root = ctk.CTk()
        self.setup_window()
        self.create_widgets()
        # Register the function to handle window closing event
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def setup_window(self):
        self.root.title("Additional Information")
        self.root.attributes('-topmost', True)
        root_width = 900
        root_height = 500
        self.root.geometry(f"{root_width}x{root_height}")
        self.root.resizable(False, False)

    def create_widgets(self):
        # Create a frame to hold the information sections
        info_frame = ctk.CTkFrame(self.root, corner_radius=10)
        info_frame.pack(padx=20, pady=20, fill='both', expand=True)
        # Metadata section
        metadata_label = ctk.CTkLabel(info_frame, text="Metadata", font=('Roboto', 16, 'bold'))
        metadata_label.grid(row=0, column=0, pady=(10, 5), sticky="w")
        created_label = ctk.CTkLabel(info_frame, text="Created On: 01/01/2022",
                                    font=('Roboto', 12))
        created_label.grid(row=1, column=0, sticky="w", padx=20)
        modified_label = ctk.CTkLabel(info_frame, text="Last Modified: 01/02/2022",
                                    font=('Roboto', 12))
        modified_label.grid(row=2, column=0, sticky="w", padx=20)
        # Security section
        security_label = ctk.CTkLabel(info_frame, text="Security Notes", font=('Roboto', 16,
                                                                            'bold'))
        security_label.grid(row=3, column=0, pady=(20, 5), sticky="w")
        note_label = ctk.CTkLabel(info_frame, text="Ensure the password is updated regularly.", font=('Roboto', 12))
        note_label.grid(row=4, column=0, sticky="w", padx=20)
        # Tags section
        tags_label = ctk.CTkLabel(info_frame, text="Tags / Categories", font=('Roboto', 16,
                                                                            'bold'))
        tags_label.grid(row=5, column=0, pady=(20, 5), sticky="w")
        tags_value_label = ctk.CTkLabel(info_frame, text="Personal, Banking", font=('Roboto',
                                                                                 12))
        tags_value_label.grid(row=6, column=0, sticky="w", padx=20)
        # Audit Log section
        audit_label = ctk.CTkLabel(info_frame, text="Audit Log", font=('Roboto', 16, 'bold'))
        audit_label.grid(row=7, column=0, pady=(20, 5), sticky="w")
        log_label = ctk.CTkLabel(info_frame, text="Last Access: 01/03/2022 by user@example.com", font=('Roboto', 12))
        log_label.grid(row=8, column=0, sticky="w", padx=20)

    def on_close(self):
        AdditionalInformation._instance = None
        self.root.destroy()

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    root = ctk.CTk()
    credential_manager = CredentialManager(root)
    root.mainloop()
