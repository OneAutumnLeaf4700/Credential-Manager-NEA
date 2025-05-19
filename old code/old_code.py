Final Code:
Main.py:
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
from PM__database import *
from PM_settings import *
class CredentialManager:
entry_style = {"font": text_type, "text_color": text_color, "fg_color": txt_entry_fg_color}
label_style = {"font": subtitle_type, "text_color": text_color}
button_style = {"font": subtitle_type, "fg_color": button_fg_color, "border_width":
button_border_width, "border_color": button_border_color, "text_color": text_color}
def __init__(self, root):
self.root = root
self.key = None
140
self.password_file = None
self.password_dict = {}
self.load_or_create_key()
self.is_master_password_present()
def load_or_create_key(self):
# Check if the master password exists in the database
with sqlite3.connect("D:/Credential Manager/test/Password Manager/MPasswords.db")
as db:
cursor = db.cursor()
cursor.execute("SELECT * FROM masterpassword")
stored_password = cursor.fetchone()
if stored_password:
# Master password exists, load the encryption key
self.load_key("D:/Credential Manager/test/Password Manager/key.key")
else:
# Master password doesn't exist, create a new key
self.create_key("D:/Credential Manager/test/Password Manager/key.key")
self.load_key("D:/Credential Manager/test/Password Manager/key.key")
def is_master_password_present(self):
try:
# Connect to the database
with sqlite3.connect("D:/Credential Manager/test/Password
Manager/MPasswords.db") as db:
cursor = db.cursor()
# Execute a query to check if any records exist
cursor.execute("SELECT * FROM masterpassword")
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
141
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
142
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
def hash_text(self,text):
self.text = text
self.hash = hashlib.sha256(self.text)
self.hash = self.hash.hexdigest()
return self.hash
@staticmethod
def popup(parent, text):
messagebox.showinfo("Popup Message", text, parent = parent)
def run_mainvault(self):
app = MainVault(self.root)
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
143
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
# Checking for atleast one number and one symbol
# Functions return a boolean value
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
self.popup(self.root, "Save Failed. Password must contain atleast 1 number")
self.password_entry.delete(0, "end")
self.confirm_password_entry.delete(0, "end")
144
# Checking for at least one symbol in the password
elif not has_symbol:
self.popup(self.root, "Save Failed. Passwords must contain atleast 1 symbol")
self.password_entry.delete(0, "end")
self.confirm_password_entry.delete(0, "end")
else:
# If all conditions are met, encrypt and hash the password
hashed_password = self.hash_text(password.encode("utf-8"))
encrypted_hashed_password = self.encrypt_password(hashed_password)
insert_password = "INSERT INTO masterpassword (password) VALUES (?)"
with sqlite3.connect("D:/Credential Manager/test/Password
Manager/MPasswords.db") as db:
cursor = db.cursor()
cursor.execute(insert_password, (encrypted_hashed_password,))
db.commit()
self.popup(self.root, "Save Successfull")
app = MainVault(self.root, "All Items", "AllItems", "AllItems")
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
#Register the close icon as a valid method of termination
self.root.protocol("WM_DELETE_WINDOW", self.on_close)
def setup_window(self):
self.root.title("Login Screen")
self.root_width = 700
self.root_height = 300
self.root.geometry(f"{self.root_width}x{self.root_height}")
self.root.resizable(False, False)
def create_widgets(self):
self.heading1 = ctk.CTkLabel(self.root, text="Your vault is locked. Please verify your
master password to continue.", **self.label_style)
self.heading1.grid(row=0, column=0, pady=10)
145
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
with sqlite3.connect("D:/Credential Manager/test/Password Manager/MPasswords.db")
as db:
cursor = db.cursor()
cursor.execute("SELECT * FROM masterpassword WHERE id = 1")
stored_password = cursor.fetchone()
if stored_password:
# Get the encrypted stored password from the database
encrypted_stored_password = stored_password[1]
# Decrypt the stored encrypted password
decrypted_stored_password =
self.decrypt_password(encrypted_stored_password)
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
app = MainVault(ctk.CTk(), "All Items", "AllItems", "AllItems")
app.run()
146
def cleanup_widgets(self):
# Cleanup canvas elements if they exist
if hasattr(self, 'heading1'):
self.heading1.destroy()
if hasattr(self, 'password'):
self.password.destroy()
if hasattr(self, 'unlock'):
self.unlock.destroy()
def on_close(self):
self.cleanup_widgets() # Clean up canvas elements
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
if hasattr(self, 'initialized') and self.initialized:
return
super().__init__(root)
self.root = root
self.title = title
self.database = database
self.table = table
self.current_page = 1 # Initialize current page to 1
self.initialize_root_window()
self.initialize_left_frame()
self.initialize_right_frame(title, database, table)
def show_login_screen(self):
# This method creates a new root window for the LoginScreen and displays it
new_root = ctk.CTk()
login_screen = LoginScreen(new_root)
147
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
initialize_all_items_func = lambda: self.initialize_right_frame("All Items", "AllItems",
"AllItems")
btn = ctk.CTkButton(self.left_frame,
text="All items",
command= initialize_all_items_func, **button_style)
btn.grid(column = 0, row = 0, pady=10 )
# Define a lambda function to call initialize_right_frame with the "Favourites" argument
148
initialize_favourites_func = lambda: self.initialize_right_frame("Favourites", "Favourites",
"Favourites")
favourites_button = ctk.CTkButton(self.left_frame, text="Favourites",
command=initialize_favourites_func, **button_style)
favourites_button.grid(column=0, row=1, pady=10)
self.random_password_generator_button = ctk.CTkButton(self.left_frame,
text="Random Password Generator",
command= self.run_random_password_generator,
**button_style)
self.random_password_generator_button.grid(column=0, row = 2, pady = 10)
self.btn = ctk.CTkButton(self.left_frame,
text="Settings",
command= self.run_settings, **button_style)
self.btn.grid(column = 0, row = 3, pady=10 )
self.btn = ctk.CTkButton(self.left_frame,
text="Import/Export",
command= self.run_filemanager, **button_style)
self.btn.grid(column = 0, row = 4, pady=10)
self.btn = ctk.CTkButton(self.left_frame,
text="Help",
command= self.run_additional_information, **button_style)
self.btn.grid(column = 0, row = 5, pady=10)
def initialize_right_frame(self, window_title, database, table):
# Clear everything in the root window except the left frame
self.clear_right_widgets()
self.right_frame_width = self.root_width - self.left_frame_width
self.right_frame_height = self.root_height
self.window_title = window_title
# Initialize the right frame
label_style = {"font": title_type, "text_color": text_color, "fg_color": title_fg_color}
self.right_frame = ctk.CTkFrame(self.root, width=self.right_frame_width,
fg_color="transparent")
self.right_frame.grid(row=0, column=1, sticky="nsew")
self.right_frame.grid_propagate(False)
self.right_frame.rowconfigure(2, weight=1)
149
# Set the title label
title_label = ctk.CTkLabel(self.right_frame, text=self.window_title, **label_style)
title_label.grid(row=0, column=0, padx=10)
# Set other labels as needed
website_label = ctk.CTkButton(self.right_frame, text="Website", font=title_type,
fg_color="transparent",
border_width=None, border_color="Transparent",
text_color=text_color,
command=lambda: self.load_credentials("website", database, table))
website_label.grid(row=1, column=0, padx=10, pady=30)
username_label = ctk.CTkButton(self.right_frame, text="Username", font=title_type,
fg_color="transparent",
border_width=None, border_color="Transparent",
text_color=text_color,
command=lambda: self.load_credentials("username", database,
table))
username_label.grid(row=1, column=1, padx=30)
password_label = ctk.CTkLabel(self.right_frame, text="Password", **label_style)
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
# Define a lambda function to call search_credentials with the appropriate table name
150
search_func = lambda: self.search_credentials(database, table)
btn = ctk.CTkButton(search_bar_frame,
text="Search",
command=search_func, **button_style)
btn.grid(row=0, column=1, sticky="ne", padx=10, pady=10)
def initialize_scrollable_frame(self, database, table):
# Scrollable frame to display credentials
self.scrollable_window = ctk.CTkScrollableFrame(self.right_frame,
fg_color="transparent", width=self.right_frame_width - 20, height=500)
self.scrollable_window.grid(row=2, column=0, columnspan=6, rowspan = 6,
sticky="nsew")
self.load_credentials("website", database, table)
def initialize_lifted_widgets(self, database, table):
button_style = {"font": subtitle_type,
"fg_color": "transparent",
"border_width": None,
"border_color": "Transparent",
"text_color": text_color}
# Create a frame for the add button
lifted_frame = ctk.CTkFrame(self.right_frame, width=self.right_frame_width,
height=100, fg_color="transparent")
lifted_frame.place(relx=0, rely=1, anchor='sw', relwidth=1)
# Create navigation buttons
prev_button = ctk.CTkButton(lifted_frame, text="Previous Page",
command=self.previous_page, **button_style)
prev_button.place(relx=0.4, rely=0.5, anchor='center')
next_button = ctk.CTkButton(lifted_frame, text="Next Page", command=self.next_page,
**button_style)
next_button.place(relx=0.5, rely=0.5, anchor='center')
add_credential_func = lambda: self.run_add_credential(database, table,
self.credentialArray)
add_button = ctk.CTkButton(lifted_frame, text="Add", command=add_credential_func,
**button_style)
add_button.place(relx=0.95, rely=0.5, anchor='e')
def clear_right_widgets(self):
# Iterate over all children widgets of the root window
151
for widget in self.root.winfo_children():
# Check if the widget is not the left frame
if widget != self.left_frame:
# Destroy the widget
widget.destroy()
def is_master_password_present(self):
pass
def load_credentials(self, sort_by, database, table):
# Clear previous credentials displayed
self.clear_credentials()
# Calculate start and end indices based on current page
start_index = (self.current_page - 1) * 6
end_index = self.current_page * 6
with sqlite3.connect(f"D:/Credential Manager/test/Password Manager/{database}.db")
as db:
cursor = db.cursor()
cursor.execute(f"SELECT * FROM {table}")
self.credentialArray = cursor.fetchall()
# Sort the credentialArray based on the specified field
if sort_by == "website":
self.credentialArray.sort(key=lambda x: x[1]) # Sort by website name
elif sort_by == "username":
self.credentialArray.sort(key=lambda x: x[2]) # Sort by username
label_style = {"font": title_type, "text_color": text_color, "fg_color": title_fg_color}
button_style = {"font": title_type, "fg_color": "transparent", "border_width": None,
"border_color": None}
def create_edit_func(row):
return lambda: self.run_edit_credential(database, table, self.credentialArray[row])
for row_value in range(start_index, min(end_index, len(self.credentialArray))):
toggle_password_func = lambda row=row_value, col=3:
self.toggle_password_visibility(row, col)
favourite_func = lambda: self.favorite_record(self.credentialArray[row_value])
edit_func = create_edit_func(row_value) # Create edit_func with captured row_value
delete_func = lambda position=row_value: self.delete_record(position, database,
table)
website_label = ctk.CTkLabel(self.scrollable_window, width=200,
text=self.credentialArray[row_value][1],
**label_style)
152
website_label.grid(column=0, row=row_value, pady=20, sticky="w")
username_label = ctk.CTkLabel(self.scrollable_window, width=200,
text=self.credentialArray[row_value][2], **label_style)
username_label.grid(column=1, row=row_value, padx=50, pady=20, sticky="w")
self.password_label = ctk.CTkLabel(self.scrollable_window, width=200,
text="********", **label_style)
self.password_label.grid(column=2, row=row_value, padx=50, pady=20, sticky="w")
self.toggle_password_btn = ctk.CTkButton(self.scrollable_window, text="Show/Hide
Password",
command=toggle_password_func, **button_style)
self.toggle_password_btn.grid(row=row_value, column=3)
if database == "AllItems":
btn = ctk.CTkButton(self.scrollable_window, text="Favourite", command=lambda
row=row_value: self.favorite_record(self.credentialArray[row]), **button_style)
btn.grid(column=4, row=row_value, pady=10)
btn = ctk.CTkButton(self.scrollable_window, text="Edit", command=edit_func,
**button_style)
btn.grid(column=5, row=row_value, pady=10)
btn = ctk.CTkButton(self.scrollable_window, text="Delete", command=lambda
position=row_value: self.delete_record(position, database, table), **button_style)
btn.grid(column=6, row=row_value, pady=10)
else:
btn = ctk.CTkButton(self.scrollable_window, text="Edit", command=lambda:
self.run_edit_credential(database, table, self.credentialArray[row_value]), **button_style)
btn.grid(column=4, row=row_value, pady=10)
btn = ctk.CTkButton(self.scrollable_window, text="Delete" , command=lambda
position=row_value: self.delete_record(position, database, table), **button_style)
btn.grid(column=5, row=row_value, pady=10)
def search_credentials(self, database, table):
query = self.search_bar.get().strip()
# Construct the SQL query based on the provided table name
sql_query = f"SELECT * FROM {table} WHERE website LIKE ? OR username LIKE ?"
with sqlite3.connect(f"D:/Credential Manager/test/Password Manager/{database}.db")
as db:
153
cursor = db.cursor()
cursor.execute(sql_query, ('%' + query + '%', '%' + query + '%'))
search_results = cursor.fetchall()
self.display_search_results(search_results)
def display_search_results(self, search_results):
# Clear previous search results
for widget in self.scrollable_window.winfo_children():
widget.destroy()
# Display the search results
for counter, result in enumerate(search_results):
self.row_value = counter
self.website_label = ctk.CTkLabel(self.scrollable_window, width=200, text=result[1],
**self.label_style)
self.website_label.grid(column=0, row=self.row_value, pady=20, sticky="w")
self.username_label = ctk.CTkLabel(self.scrollable_window, width=200,
text=result[2], **self.label_style)
self.username_label.grid(column=1, row=self.row_value, pady=20, sticky="w")
self.password_label = ctk.CTkLabel(self.scrollable_window, width=200,
text="********", **self.label_style)
self.password_label.grid(column=2, row=self.row_value, pady=20, sticky="w")
self.toggle_password_btn = ctk.CTkButton(self.scrollable_window, text="Show/Hide
Password", command=None, **self.button_style)
self.toggle_password_btn.grid(row=self.row_value, column=3)
self.toggle_password_btn = ctk.CTkButton(self.scrollable_window, text="Edit",
command=None, **self.button_style)
self.toggle_password_btn.grid(row=self.row_value, column=4, pady=10, padx=10)
self.btn = ctk.CTkButton(self.scrollable_window, text="Delete", command=None,
**self.button_style)
self.btn.grid(column=5, row=self.row_value, pady=10, padx=10)
def toggle_password_visibility(self, row, col):
# Function to toggle the visibility of password at the specified row and column
try:
displayed_password = self.credentialArray[row][col]
current_text = self.password_label.cget("text")
if current_text == "********":
# If password is hidden, show it
encrypted_password = displayed_password
154
decrypted_password = self.decrypt_password(encrypted_password)
self.password_label.configure(text=decrypted_password)
else:
# If password is shown, hide it
self.password_label.configure(text="********")
except IndexError:
print("Invalid row index provided.")
except Exception as e:
print(f"An error occurred: {e}")
def favorite_record(self, record_array):
website = record_array[1]
username = record_array[2]
encrypted_password = record_array[3]
try:
# Check if the record already exists in the favorites database
with sqlite3.connect(f"D:/Credential Manager/test/Password Manager/Favourites.db")
as db:
cursor = db.cursor()
# Execute a query to check if the record exists
cursor.execute("SELECT * FROM Favourites WHERE website = ? AND username
= ?", (website, username))
existing_record = cursor.fetchone()
if existing_record:
# If the record exists, display a message and return
self.popup(self.root, "Credential already exists in favorites")
return
# If the record does not exist, insert it into the favorites database
insert_values = """INSERT INTO Favourites(website, username, password)
VALUES (?, ?, ?) """
with sqlite3.connect(f"D:/Credential Manager/test/Password Manager/Favourites.db")
as db:
cursor = db.cursor()
cursor.execute(insert_values, (website, username, encrypted_password))
db.commit()
self.popup(self.root, "Credential added to favorites")
except Exception as e:
self.popup(self.root, f"An error occurred: {e}")
def delete_record(self, row_value, database, table):
with sqlite3.connect(f"D:/Credential Manager/test/Password Manager/{database}.db")
as db:
cursor = db.cursor()
cursor.execute(f"DELETE FROM {table} WHERE id=?",
(self.credentialArray[row_value][0],))
db.commit()
155
app = MainVault(self.root, self.title, self.database, self.table)
app.run()
def next_page(self):
# Increment current page
self.current_page += 1
# Reload credentials based on the new page
self.load_credentials("website", self.database, self.table)
def previous_page(self):
# Ensure current page doesn't go below 1
if self.current_page > 1:
# Decrement current page
self.current_page -= 1
# Reload credentials based on the new page
self.load_credentials("website", self.database, self.table)
def clear_credentials(self):
# Clear the scrollable window
for widget in self.scrollable_window.winfo_children():
widget.destroy()
def run_random_password_generator(self):
self.random_password_generator_instance = RandomPasswordGenerator()
self.random_password_generator_instance.run()
def run_settings(self):
self.settings_instance = Settings()
self.settings_instance.run()
def run_filemanager(self):
self.filemanager_instance = FileManager()
self.filemanager_instance.run()
def run_add_credential(self, database, table, array):
add_credential_instance = AddCredential(database, table, array)
add_credential_instance.run()
def run_edit_credential(self, database, table, record_array):
edit_credentials_instance = EditCredential(database, table, record_array)
edit_credentials_instance.run()
def run_additional_information(self):
additional_information_instance = AdditionalInformation()
additional_information_instance.run()
class RandomPasswordGenerator(CredentialManager):
_instance = None # Class variable to store the single instance
156
def __new__(cls):
# If an instance of the class already exists, return it
if cls._instance is not None:
cls.popup(cls._instance.root, "Random Password Generator is already open")
return cls._instance
# If no instance exists, create a new one
cls._instance = super().__new__(cls)
return cls._instance
def __init__(self):
if hasattr(self, 'root'): # Check if root attribute already exists
return # Return without reinitializing if already initialized
# Initialize the instance only if it's a new instance
self.root = ctk.CTk()
self.setup_window()
self.create_widgets()
# Register the function to handle window closing event
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
157
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
generate_btn = ctk.CTkButton(master=pass_generator_frame, text="Generate
Password",
command=self.update_random_password, **button_style)
generate_btn.grid(row=4, column=0, pady=30, padx=30, sticky="e")
copy_password_btn = ctk.CTkButton(master=pass_generator_frame, text="Copy To
Clipboard",
command=self.copytext, **button_style)
158
copy_password_btn.grid(row=4, column=1, pady=30, sticky = "w")
def slider_event(self, value):
value_int = int(value) # Convert the float value to an integer
formatted_value = f"{value_int:02}"
self.slider_label.configure(text=f"Password Length: {formatted_value}")
def update_random_password(self):
length = int(self.slider.get()) #Sets length of the password to the value of the slider
character_sets = [] #Creates a character set that will be appended to by the required
character types
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
# Repeats this process as many times as the users required length to fill the
password length requirement
generated_password = ''.join(secrets.choice(alphabet) for _ in range(length))
# Displays the generated password on a new line
self.generated_password_label.configure(text=f"Generated
Password:\n{generated_password}")
else:
# Displays a popup to tell the user to select a checkbox if none are selected
self.popup(self.root, "Please select at least one character set")
def copytext(self):
generated_password = self.generated_password_label.cget("text") # Get the password
from the generated password label
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
159
RandomPasswordGenerator._instance = None
self.root.destroy()
class Settings(CredentialManager):
_instance = None # Class variable to store the single instance
def __new__(cls):
# If an instance of the class already exists, return it
if cls._instance is not None:
cls.popup(cls._instance.root, "Settings window is already open")
return cls._instance
# If no instance exists, create a new one
cls._instance = super().__new__(cls)
return cls._instance
def __init__(self):
if hasattr(self, 'root'): # Check if root attribute already exists
return # Return without reinitializing if already initialized
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
160
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
161
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
font_family_options = ctk.CTkOptionMenu(self.root, values=["Arial", "IMPACT", "Times
New Roman"], command=None,
variable=self.font_family_var, fg_color = button_fg_color)
font_family_options.grid(row=4, column=1, columnspan=2, padx=20, pady=10,
sticky="w")
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
162
self.current_text_size = self.text_size_var.get()
# Getting the text color
self.current_text_color = self.text_color_var.get()
# Getting the font type
self.current_font_family = self.font_family_var.get()
# Connecting to the UserSettings Database
with sqlite3.connect("D:/Credential Manager/test/Password Manager/UserSettings.db")
as db:
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
163
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
app = MainVault(root, "All Items", "AllItems", "AllItems")
app.run()
def run(self):
self.root.mainloop()
class FileManager(CredentialManager):
_instance = None
def __new__(cls, *args, **kwargs):
if cls._instance is not None:
cls.popup(cls._instance.root, "File Manager is already open")
return cls._instance
cls._instance = super().__new__(cls)
return cls._instance
def __init__(self):
if hasattr(self, 'root'):
return
super().__init__(root)
self.root = ctk.CTk()
self.setup_window()
self.create_widgets()
self.root.protocol("WM_DELETE_WINDOW", self.on_close)
164
def setup_window(self):
self.root.title("Import/Export Data")
root_width = 350
root_height = 300
self.root.geometry(f"{root_width}x{root_height}")
self.root.resizable(False, False)
def create_widgets(self):
button_style = {"font": subtitle_type, "fg_color": button_fg_color,
"border_width": button_border_width, "border_color": button_border_color,
"text_color": text_color}
label_style = {"font": title_type, "text_color": text_color, "fg_color": title_fg_color}
# Heading label
heading_label = ctk.CTkLabel(self.root, text="Import/Export Data", **label_style)
heading_label.grid(row=0, column=0, padx=10, pady=10, columnspan=2)
# Database section
database_label = ctk.CTkLabel(self.root, text="Database:", **label_style)
database_label.grid(row=1, column=0, padx=10, pady=5, columnspan=2)
self.database_var = StringVar(value="AllItems")
Main_database_button = ctk.CTkRadioButton(self.root, text="All Items",
variable=self.database_var, value="AllItems",
command=None, fg_color=button_fg_color)
Main_database_button.grid(row=2, column=0, padx=20, pady=10, sticky="w")
Favourites_database_button = ctk.CTkRadioButton(self.root, text="Favourites",
variable=self.database_var, value="Favourites",
command=None, fg_color=button_fg_color)
Favourites_database_button.grid(row=2, column=1, padx=20, pady=10, sticky="w")
# Import section
import_label = ctk.CTkLabel(self.root, text="Import Data", **label_style)
import_label.grid(row=3, column=0, padx=10, pady=5, columnspan=2)
import_json_button = ctk.CTkButton(self.root, text="Import from JSON",
command=self.import_from_json, **button_style)
import_json_button.grid(row=4, column=0, padx=10, pady=5)
import_csv_button = ctk.CTkButton(self.root, text="Import from CSV",
command=self.import_from_csv, **button_style)
import_csv_button.grid(row=4, column=1, padx=10, pady=5)
# Export section
export_label = ctk.CTkLabel(self.root, text="Export Data", **label_style)
export_label.grid(row=5, column=0, padx=10, pady=5, columnspan=2)
165
export_json_button = ctk.CTkButton(self.root, text="Export to JSON",
command=self.export_as_json, **button_style)
export_json_button.grid(row=6, column=0, padx=10, pady=5)
export_csv_button = ctk.CTkButton(self.root, text="Export to CSV",
command=self.export_as_csv, **button_style)
export_csv_button.grid(row=6, column=1, padx=10, pady=5)
def determine_database(self):
# Check which database radio button is selected
selected_database = self.database_var.get()
# Set the appropriate database and table names based on the selected radio button
if selected_database == "AllItems":
self.database = "AllItems"
self.table = "AllItems"
elif selected_database == "Favourites":
self.database = "Favourites"
self.table = "Favourites"
else:
self.popup(self.root, "Please select a database")
def import_from_json(self):
# Call determine_database to set database and table names
self.determine_database()
# Call the import_data_from_json method with database and table parameters
self.import_data_from_json(self.database, self.table)
def import_from_csv(self):
# Call determine_database to set database and table names
self.determine_database()
# Call the import_data_from_csv method with database and table parameters
self.import_data_from_csv(self.database, self.table)
def export_as_json(self):
# Call determine_database to set database and table names
self.determine_database()
# Call the export_data_to_json method with database and table parameters
self.export_data_as_json(self.database, self.table)
def export_as_csv(self):
# Call determine_database to set database and table names
self.determine_database()
# Call the export_data_to_csv method with database and table parameters
166
self.export_data_as_csv(self.database, self.table)
def import_data_from_json(self, database, table):
try:
# Open file dialog to select JSON file
json_file = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
if not json_file:
self.popup(self.root, "No file selected.")
return
# Read data from selected JSON file
with open(json_file, 'r') as file:
data = json.load(file)
# Connect to the SQLite database
with sqlite3.connect(f"D:/Credential Manager/test/Password Manager/{database}.db")
as db:
cursor = db.cursor()
# Insert each record into the specified table
for record in data:
website = record.get('website', '')
username = record.get('username', '')
password = record.get('password', '')
# Execute SQL INSERT statement using f-string
cursor.execute(f"INSERT INTO {table} (website, username, password) VALUES
(?, ?, ?)",
(website, username, password))
db.commit()
self.popup(self.root, "Data imported successfully.")
except FileNotFoundError:
self.popup(self.root, f"File '{json_file}' not found.")
except json.JSONDecodeError:
self.popup(self.root, "Invalid JSON file.")
except sqlite3.Error as e:
self.popup(self.root, f"SQLite error: {e}")
def import_data_from_csv(self, database, table):
try:
# Open file dialog to select CSV file
csv_file = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
167
if not csv_file:
self.popup(self.root, "No file selected.")
return
# Read data from selected CSV file
with open(csv_file, 'r') as file:
csv_reader = csv.DictReader(file)
data = [row for row in csv_reader]
# Connect to the SQLite database
with sqlite3.connect(f"D:/Credential Manager/test/Password Manager/{database}.db")
as db:
cursor = db.cursor()
# Insert each record into the specified table
for record in data:
website = record.get('website', '')
username = record.get('username', '')
password = record.get('password', '')
# Execute SQL INSERT statement using f-string
cursor.execute(f"INSERT INTO {table} (website, username, password) VALUES
(?, ?, ?)",
(website, username, password))
db.commit()
self.popup(self.root, "Data imported successfully.")
except FileNotFoundError:
self.popup(self.root, f"File '{csv_file}' not found.")
except csv.Error as e:
self.popup(self.root, f"CSV error: {e}")
except sqlite3.Error as e:
self.popup(self.root, f"SQLite error: {e}")
def export_data_as_json(self, database, table):
try:
# Connect to the SQLite database
with sqlite3.connect(f"D:/Credential Manager/test/Password Manager/{database}.db")
as db:
cursor = db.cursor()
# Fetch all records from the specified table
cursor.execute(f"SELECT * FROM {table}")
168
records = cursor.fetchall()
# Convert records to a list of dictionaries
data = []
for record in records:
data.append({
'website': record[1],
'username': record[2],
'password': str((record[3])),
})
# Open file dialog to select export location
json_file = filedialog.asksaveasfilename(defaultextension=".json",
filetypes=[("JSON files", "*.json")])
if not json_file:
self.popup(self.root, "No file selected.")
return
# Write data to the selected JSON file
with open(json_file, 'w') as file:
json.dump(data, file, indent=4)
self.popup(self.root, "Data exported successfully.")
except sqlite3.Error as e:
self.popup(self.root, f"SQLite error: {e}")
def export_data_as_csv(self, database, table):
try:
# Connect to the SQLite database
with sqlite3.connect(f"D:/Credential Manager/test/Password Manager/{database}.db")
as db:
cursor = db.cursor()
# Fetch all records from the specified table
cursor.execute(f"SELECT * FROM {table}")
records = cursor.fetchall()
# Open file dialog to select export location
csv_file = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV
files", "*.csv")])
if not csv_file:
self.popup(self.root, "No file selected.")
return
169
# Write data to the selected CSV file
with open(csv_file, 'w', newline='') as file:
writer = csv.writer(file)
writer.writerow(['Website', 'Username', 'Password']) # Write header
for record in records:
writer.writerow([record[1], record[2], str(record[3])]) # Write each record
self.popup(self.root, "Data exported successfully.")
except sqlite3.Error as e:
self.popup(self.root, f"SQLite error: {e}")
def on_close(self):
# Reset the _instance attribute
FileManager._instance = None
# Destroy the current instance
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
170
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
171
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
# If all entries are filled, passwords match, and credential doesn't exist, proceed to
encrypt the password
encrypted_password = self.encrypt_password(password)
# Insert the encrypted password into the database
insert_values = f"""INSERT INTO {self.table}(website, username, password)
VALUES (?, ?, ?) """
with sqlite3.connect(f"D:/Credential Manager/test/Password
Manager/{self.database}.db") as db:
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
172
# First, check if `self.root` is not destroyed already
if self.root:
# Now you need to initialize the new MainVault before destroying the old root
if self.database == "AllItems":
app = MainVault(ctk.CTk(), "All Items", "AllItems", "AllItems")
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
173
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
174
with sqlite3.connect(f"D:/Credential Manager/test/Password
Manager/{self.database}.db") as db:
cursor = db.cursor()
cursor.execute(f"SELECT * FROM {self.table} WHERE website = ? AND username =
? AND password = ?", (website, username, password))
credential = cursor.fetchone()
if credential:
# Populate the text entries with the retrieved credential details
self.website_entry.delete(0, 'end')
self.website_entry.insert(0, credential[1])
self.username_entry.delete(0, 'end')
self.username_entry.insert(0, credential[2])
# Decrypt the password and insert it into the password entry
decrypted_password = self.decrypt_password(credential[3]) # Assuming password
is the third column
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
if new_website != self.previous_website or new_username != self.previous_username
or new_password != self.previous_password:
# Check to see if the credential exists
with sqlite3.connect(f"D:/Credential Manager/test/Password
Manager/{self.database}.db") as db:
cursor = db.cursor()
cursor.execute(f"SELECT * FROM {self.table} WHERE website = ? AND
username = ?", (self.previous_website, self.previous_username))
credential = cursor.fetchone()
if credential:
# Update the database with the new values
175
update_query = f"UPDATE {self.table} SET website = ?, username = ?,
password = ? WHERE website = ? AND username = ? AND password = ?"
encrypted_password = self.encrypt_password(new_password)
with sqlite3.connect(f"D:/Credential Manager/test/Password
Manager/{self.database}.db") as db:
cursor = db.cursor()
cursor.execute(update_query, (new_website, new_username,
encrypted_password, self.previous_website, self.previous_username,
self.previous_password))
db.commit()
self.root.after(100, self.destroy_window_and_create_main_vault)
else:
# If credential not found, show an error message
self.popup(self.root, f"No credential found for website: {self.previous_website}
and username: {self.previous_username}")
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
app = MainVault(root, "All Items", "AllItems", "AllItems")
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
def __new__(cls):
# If an instance of the class already exists, return it
if cls._instance is not None:
cls.popup(cls._instance.root, "Additional Information is already open")
176
return cls._instance
# If no instance exists, create a new one
cls._instance = super().__new__(cls)
return cls._instance
def __init__(self):
if hasattr(self, 'root'): # Check if root attribute already exists
return # Return without reinitializing if already initialized
# Initialize the instance only if it's a new instance
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
177
note_label = ctk.CTkLabel(info_frame, text="Ensure the password is updated
regularly.", font=('Roboto', 12))
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
log_label = ctk.CTkLabel(info_frame, text="Last Access: 01/03/2022 by
user@example.com", font=('Roboto', 12))
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
Database.py:
import sqlite3
import customtkinter as ctk
# Database for master passwords
with sqlite3.connect("D:/Credential Manager/test/Password Manager/MPasswords.db") as
db:
cursor = db.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword (
id INTEGER PRIMARY KEY,
password TEXT NOT NULL);
178
""")
with sqlite3.connect("D:/Credential Manager/test/Password Manager/AllItems.db") as db:
cursor = db.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS AllItems(
id INTEGER PRIMARY KEY,
website TEXT NOT NULL,
username TEXT NOT NULL,
password TEXT NOT NULL);
""")
with sqlite3.connect("D:/Credential Manager/test/Password Manager/Favourites.db") as db:
cursor = db.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS Favourites(
id INTEGER PRIMARY KEY,
website TEXT NOT NULL,
username TEXT NOT NULL,
password TEXT NOT NULL);
""")
# Database for User Settings
with sqlite3.connect("D:/Credential Manager/test/Password Manager/UserSettings.db") as
db:
cursor = db.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS settings (
id INTEGER PRIMARY KEY,
theme TEXT NOT NULL,
widget_theme TEXT NOT NULL,
text_size INTEGER NOT NULL,
text_color TEXT NOT NULL,
font_family TEXT NOT NULL);
""")
# Inserting default values
cursor.execute("""
INSERT INTO settings (theme, widget_theme, text_size, text_color, font_family)
VALUES ('system', 'dark-blue', 14, 'White', 'Arial');
""")
179
Settings.py:
import customtkinter as ctk
import sqlite3
root = ctk.CTk()
# Dictionary to store the user settings
# Values loaded from database
user_settings = {}
# Loading the settings database contents into the user_settings dictionary
with sqlite3.connect("D:/Credential Manager/test/Password Manager/UserSettings.db") as
db:
cursor = db.cursor()
# Fetch the values from the settings table
cursor.execute("SELECT * FROM settings WHERE id = 1;")
row = cursor.fetchone()
if row:
# Assign the values from the database to the user_settings dictionary
user_settings["theme"] = row[1]
user_settings["widget_theme"] = row[2]
user_settings["text_size"] = row[3]
user_settings["text_color"] = row[4]
user_settings["font_family"] = row[5]
else:
# If no values are found, assign default values
user_settings = {
"theme": "system",
"widget_theme": "dark-blue",
"text_size": 16,
"text_color": "White",
"font_family": "Arial"
}
# Assigning variables based on the user_settings dictionary
program_theme = user_settings["theme"]
widget_theme = user_settings["widget_theme"]
text_size = user_settings["text_size"]
text_color = user_settings["text_color"]
font_name = user_settings["font_family"]
180
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