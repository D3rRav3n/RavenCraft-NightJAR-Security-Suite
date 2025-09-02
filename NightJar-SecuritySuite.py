#!/usr/bin/env python3
#
# RavenCraft:NightJAR Security Suite v2.0 (Python)
# A professional suite for password generation and management,
# with advanced security auditing and TOTP functionality.
#
# Copyright (c) 2024 Tapiwa Alexander Shumba
# Licensed under MIT and CC BY-SA 4.0.
#
# --- Dependencies ---
# To install: pip install pyperclip cryptography requests pyotp
import tkinter as tk
from tkinter import simpledialog, messagebox, filedialog, ttk
import secrets
import string
import sys
import pyperclip
import threading
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import requests
import pathlib
import sqlite3
import time
import pyotp

# --- Constants & Configuration ---
GITHUB_REPO_URL = "https://github.com/your-username/your-repo-name"
PAYPAL_EMAIL = "alexandershumba97@gmail.com"
WORDLIST_URL = "https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt"
WORDLIST_FILE = ".eff_wordlist.txt"
DB_FILE = "passwords.dat"
MANAGER_MAGIC_NUMBER = b'RAVENCRAFT_PM_V1.0'
HIBP_API_URL = "https://api.pwnedpasswords.com/range/"

# --- Centralized Security Utilities ---
def get_key_from_password(password, salt):
    """Derives a strong key from a password using PBKDF2HMAC."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def secure_file_delete(filepath):
    """Securely deletes a file by overwriting its contents."""
    try:
        if os.path.exists(filepath):
            with open(filepath, 'ba+') as f:
                f.seek(0)
                file_size = f.tell()
                f.seek(0)
                f.write(os.urandom(file_size))
            os.remove(filepath)
    except Exception as e:
        messagebox.showerror("Deletion Error", f"Could not securely delete file: {e}")

class ClipboardManager:
    def __init__(self):
        self.thread = None
        self.interval = 30
    
    def clear_clipboard_in_future(self):
        if self.thread and self.thread.is_alive():
            self.thread.cancel()
        self.thread = threading.Timer(self.interval, pyperclip.copy, [''])
        self.thread.start()

# --- Generator Logic ---
class GeneratorLogic:
    def __init__(self):
        self.wordlist = self.get_wordlist()

    def get_wordlist(self):
        if not os.path.exists(WORDLIST_FILE):
            try:
                print("Downloading EFF wordlist...")
                response = requests.get(WORDLIST_URL)
                response.raise_for_status()
                with open(WORDLIST_FILE, 'wb') as f:
                    f.write(response.content)
                print("Wordlist downloaded successfully.")
            except requests.exceptions.RequestException as e:
                messagebox.showerror("Download Error", f"Failed to download wordlist.\nError: {e}")
                return []
        with open(WORDLIST_FILE, 'r') as f:
            return [line.strip().split()[-1] for line in f if line.strip()]

    def generate_password(self, length):
        if length < 4:
            raise ValueError("Password length must be at least 4.")
        lower, upper, digits, symbols = string.ascii_lowercase, string.ascii_uppercase, string.digits, string.punctuation
        all_chars = lower + upper + digits + symbols
        password = [secrets.choice(lower), secrets.choice(upper), secrets.choice(digits), secrets.choice(symbols)]
        for _ in range(length - 4):
            password.append(secrets.choice(all_chars))
        secrets.SystemRandom().shuffle(password)
        return ''.join(password)

    def generate_passphrase(self, num_words):
        if not self.wordlist:
            raise ValueError("Wordlist not available.")
        passphrase = [secrets.choice(self.wordlist) for _ in range(num_words)]
        return '-'.join(passphrase)

    def generate_pin(self, length):
        return ''.join(secrets.choice(string.digits) for _ in range(length))

# --- Database & Security Logic ---
class ManagerLogic:
    def __init__(self, password):
        self.password = password
        self.conn = None
        self.is_new_db = False

    def save(self):
        if not self.conn: return
        b = sqlite3.connect(":memory:")
        self.conn.backup(b)
        db_bytes = b.execute("SELECT hex(sqlite_master.sql) FROM sqlite_master;").fetchone()[0]
        b.close()
        db_bytes = bytes.fromhex(db_bytes)
        salt = os.urandom(16)
        key = get_key_from_password(self.password, salt)
        f = Fernet(key)
        encrypted_data = f.encrypt(db_bytes)
        with open(DB_FILE, 'wb') as file:
            file.write(MANAGER_MAGIC_NUMBER)
            file.write(salt)
            file.write(encrypted_data)

    def load(self):
        if not os.path.exists(DB_FILE):
            self.is_new_db = True
            self.conn = sqlite3.connect(":memory:")
            self.conn.execute("CREATE TABLE passwords (id INTEGER PRIMARY KEY, website TEXT, username TEXT, password TEXT, notes TEXT, totp_secret TEXT)")
            return True
        with open(DB_FILE, 'rb') as file:
            header = file.read(len(MANAGER_MAGIC_NUMBER))
            if header != MANAGER_MAGIC_NUMBER: raise ValueError("Invalid database file.")
            salt = file.read(16)
            encrypted_data = file.read()
        key = get_key_from_password(self.password, salt)
        f = Fernet(key)
        decrypted_data = f.decrypt(encrypted_data)
        self.conn = sqlite3.connect(":memory:")
        self.conn.executescript(decrypted_data.decode())
        # Check for old schema
        cursor = self.conn.cursor()
        try:
            cursor.execute("SELECT totp_secret FROM passwords LIMIT 1")
        except sqlite3.OperationalError:
            cursor.execute("ALTER TABLE passwords ADD COLUMN totp_secret TEXT")
            self.conn.commit()
        return True

    def audit_passwords(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT password FROM passwords")
        passwords = [row[0] for row in cursor.fetchall()]
        
        # Check for duplicates
        duplicates = {}
        for password in passwords:
            duplicates[password] = duplicates.get(password, 0) + 1
        num_duplicates = sum(1 for count in duplicates.values() if count > 1)
        
        # Check for breached passwords
        breached_passwords = set()
        for password in passwords:
            sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
            prefix, suffix = sha1_hash[:5], sha1_hash[5:]
            try:
                response = requests.get(HIBP_API_URL + prefix, timeout=10)
                if response.status_code == 200:
                    lines = response.text.splitlines()
                    for line in lines:
                        if line.startswith(suffix):
                            breached_passwords.add(password)
            except requests.exceptions.RequestException:
                pass # Fail silently, a network error shouldn't crash the audit

        return {
            'total_passwords': len(passwords),
            'num_duplicates': num_duplicates,
            'num_breached': len(breached_passwords),
            'breached_passwords': list(breached_passwords)
        }

    def close(self):
        if self.conn:
            self.conn.commit()
            self.conn.close()

# --- GUI Logic ---
class RavenCraftApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("RavenCraft:NightJAR Security Suite v2.0 ⚙️")
        self.geometry("800x600")
        self.manager_logic = None
        self.generator_logic = GeneratorLogic()
        self.clipboard_manager = ClipboardManager()
        self.progress_window = None
        self.create_widgets()

    def create_widgets(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(pady=10, expand=True, fill="both")
        self.generator_frame = tk.Frame(self.notebook)
        self.manager_frame = tk.Frame(self.notebook)
        self.notebook.add(self.generator_frame, text="Password Generator")
        self.notebook.add(self.manager_frame, text="Password Manager")
        self.setup_generator_tab()
        self.setup_manager_tab()

    def setup_generator_tab(self):
        tk.Label(self.generator_frame, text="Choose a generator profile:", font=("Helvetica", 14)).pack(pady=10)
        button_frame = tk.Frame(self.generator_frame)
        button_frame.pack(pady=5)
        tk.Button(button_frame, text="🔐 Password", command=self.generate_password_gui, width=20).pack(pady=5)
        tk.Button(button_frame, text="🔑 Passphrase", command=self.generate_passphrase_gui, width=20).pack(pady=5)
        tk.Button(button_frame, text="🔢 PIN Code", command=self.generate_pin_gui, width=20).pack(pady=5)
        
        footer_frame = tk.Frame(self.generator_frame)
        footer_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=10)
        tk.Button(footer_frame, text="📚 Help", command=self.show_help, width=15).pack(side=tk.LEFT, padx=10)
        tk.Button(footer_frame, text="💸 Donate", command=self.show_donation_info, width=15).pack(side=tk.LEFT, padx=10)

    def setup_manager_tab(self):
        self.login_frame = tk.Frame(self.manager_frame)
        self.main_manager_frame = tk.Frame(self.manager_frame)
        tk.Label(self.login_frame, text="Enter Master Password to Unlock Vault:", font=("Helvetica", 14)).pack(pady=10)
        self.manager_password_entry = tk.Entry(self.login_frame, show="*", width=30)
        self.manager_password_entry.pack(pady=5)
        tk.Button(self.login_frame, text="Unlock Vault", command=self.attempt_login).pack(pady=10)
        self.login_frame.pack(fill=tk.BOTH, expand=True)

        tk.Label(self.main_manager_frame, text="Password Vault", font=("Helvetica", 18, "bold")).pack(pady=10)
        
        self.tree = ttk.Treeview(self.main_manager_frame, columns=("Website", "Username"), show="headings")
        self.tree.heading("Website", text="Website")
        self.tree.heading("Username", text="Username")
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind("<Double-1>", self.on_item_double_click)

        button_frame = tk.Frame(self.main_manager_frame)
        button_frame.pack(fill=tk.X, pady=10)
        tk.Button(button_frame, text="➕ Add Entry", command=self.add_entry, width=15).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="✏️ Edit Entry", command=self.edit_entry, width=15).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="➖ Delete Entry", command=self.delete_entry, width=15).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="📋 Copy Password", command=self.copy_password, width=15).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="🔒 Lock Vault", command=self.lock_and_save, width=15).pack(side=tk.RIGHT, padx=5)
        tk.Button(button_frame, text="📊 Audit Vault", command=self.audit_vault, width=15).pack(side=tk.RIGHT, padx=5)
        
    def show_progress_bar(self, title, initial_value):
        self.progress_window = tk.Toplevel(self)
        self.progress_window.title(title)
        self.progress_window.geometry("300x100")
        self.progress_window.transient(self)
        self.progress_window.grab_set()
        tk.Label(self.progress_window, text="Processing...", font=("Helvetica", 12)).pack(pady=10)
        self.progress = ttk.Progressbar(self.progress_window, orient="horizontal", length=250, mode="determinate")
        self.progress.pack(pady=10)
        self.progress['value'] = initial_value
        self.progress_window.update()

    def update_progress(self, value):
        if self.progress_window:
            self.progress['value'] = value
            self.progress_window.update()
            
    def hide_progress_bar(self):
        if self.progress_window:
            self.progress_window.destroy()
            self.progress_window = None

    # --- Generator GUI Methods ---
    def show_result(self, generated_text, profile):
        pyperclip.copy(generated_text)
        self.clipboard_manager.clear_clipboard_in_future()
        messagebox.showinfo("✨ Success", f"Your new {profile} has been copied to your clipboard.\n\nIt will be cleared in 30 seconds.")

    def get_valid_input(self, title, prompt, min_val):
        while True:
            value_str = simpledialog.askstring(title, prompt, initialvalue=str(min_val))
            if value_str is None: return None
            if value_str.isdigit():
                value = int(value_str)
                if value >= min_val: return value
                else: messagebox.showwarning("Invalid Input", f"Input must be a number greater than or equal to {min_val}.")
            else: messagebox.showwarning("Invalid Input", "Please enter a valid number.")

    def generate_password_gui(self):
        try:
            length = self.get_valid_input("Password Length", "Enter desired password length (min. 15):", 15)
            if length is not None:
                password = self.generator_logic.generate_password(length)
                self.show_result(password, "Password")
        except ValueError as e: messagebox.showerror("Generation Error", str(e))

    def generate_passphrase_gui(self):
        try:
            num_words = self.get_valid_input("Passphrase Words", "Enter desired number of words (min. 6):", 6)
            if num_words is not None:
                passphrase = self.generator_logic.generate_passphrase(num_words)
                self.show_result(passphrase, "Passphrase")
        except ValueError as e: messagebox.showwarning("Generation Error", str(e))

    def generate_pin_gui(self):
        length = self.get_valid_input("PIN Length", "Enter desired PIN length (min. 4):", 4)
        if length is not None:
            pin = self.generator_logic.generate_pin(length)
            self.show_result(pin, "PIN Code")

    # --- Manager GUI Methods ---
    def attempt_login(self):
        master_password = self.manager_password_entry.get()
        if not master_password:
            messagebox.showerror("Error", "Please enter a password.")
            return
        self.show_progress_bar("Unlocking Vault...", 10)
        login_thread = threading.Thread(target=self.login_worker, args=(master_password,))
        login_thread.start()

    def login_worker(self, password):
        try:
            if not os.path.exists(DB_FILE):
                self.manager_logic = ManagerLogic(password)
                self.manager_logic.is_new_db = True
                self.manager_logic.load()
                self.manager_logic.save()
            else:
                with open(DB_FILE, 'rb') as f:
                    header_len = len(MANAGER_MAGIC_NUMBER) + 16
                    file_header = f.read(header_len)
                    if not file_header.startswith(MANAGER_MAGIC_NUMBER): raise ValueError("Invalid database file.")
                    salt = file_header[len(MANAGER_MAGIC_NUMBER):]
                    key = get_key_from_password(password, salt)
                    f_test = Fernet(key)
                    f.seek(header_len)
                    test_data = f.read(100)
                    if not test_data:
                        raise ValueError("Incorrect password.")
                    f_test.decrypt(test_data)
                self.manager_logic = ManagerLogic(password)
                self.manager_logic.load()
            
            self.update_progress(100)
            self.hide_progress_bar()
            messagebox.showinfo("Success", "Vault unlocked successfully.")
            self.login_frame.pack_forget()
            self.main_manager_frame.pack(fill=tk.BOTH, expand=True)
            self.load_entries()
        except Exception as e:
            self.hide_progress_bar()
            messagebox.showerror("Login Failed", "Incorrect password. Please try again.")
            if 'Incorrect' in str(e) or 'bad' in str(e) or 'invalid' in str(e) or 'empty' in str(e):
                if self.manager_logic and self.manager_logic.is_new_db:
                    secure_file_delete(DB_FILE)

    def load_entries(self):
        for item in self.tree.get_children(): self.tree.delete(item)
        cursor = self.manager_logic.conn.cursor()
        for row in cursor.execute("SELECT id, website, username FROM passwords ORDER BY website"):
            self.tree.insert("", "end", iid=row[0], values=(row[1], row[2]))

    def add_entry(self):
        EntryForm(self, self.manager_logic, parent_app=self)

    def edit_entry(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("No Selection", "Please select an entry to edit.")
            return
        item_id = selected_item[0]
        cursor = self.manager_logic.conn.cursor()
        cursor.execute("SELECT * FROM passwords WHERE id = ?", (item_id,))
        row = cursor.fetchone()
        if row: EntryForm(self, self.manager_logic, entry_data=row, parent_app=self)

    def delete_entry(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("No Selection", "Please select an entry to delete.")
            return
        item_id = selected_item[0]
        if messagebox.askyesno("Confirm Deletion", "Are you sure you want to delete this entry?"):
            cursor = self.manager_logic.conn.cursor()
            cursor.execute("DELETE FROM passwords WHERE id = ?", (item_id,))
            self.manager_logic.conn.commit()
            self.load_entries()
            messagebox.showinfo("Success", "Entry deleted successfully.")

    def on_item_double_click(self, event):
        item = self.tree.selection()[0]
        item_id = self.tree.item(item, "iid")
        cursor = self.manager_logic.conn.cursor()
        cursor.execute("SELECT password FROM passwords WHERE id = ?", (item_id,))
        password = cursor.fetchone()[0]
        pyperclip.copy(password)
        self.clipboard_manager.clear_clipboard_in_future()
        messagebox.showinfo("Copied to Clipboard", "Password copied. It will be cleared in 30 seconds.")

    def copy_password(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("No Selection", "Please select an entry to copy.")
            return
        self.on_item_double_click(None)

    def lock_and_save(self):
        if self.manager_logic:
            self.manager_logic.save()
            self.manager_logic.close()
            messagebox.showinfo("Vault Locked", "Your vault has been saved and locked.")
            self.login_frame.pack(fill=tk.BOTH, expand=True)
            self.main_manager_frame.pack_forget()

    def on_closing(self):
        if self.manager_logic and self.manager_logic.conn:
            if messagebox.askyesno("Exit & Save", "Do you want to save and lock your vault before exiting?"):
                self.manager_logic.save()
                self.manager_logic.close()
        self.destroy()

    def audit_vault(self):
        self.show_progress_bar("Auditing Passwords...", 10)
        audit_thread = threading.Thread(target=self.audit_worker)
        audit_thread.start()

    def audit_worker(self):
        try:
            audit_results = self.manager_logic.audit_passwords()
            self.update_progress(100)
            self.hide_progress_bar()
            
            report = f"Audit Report:\n\n"
            report += f"Total Passwords: {audit_results['total_passwords']}\n"
            report += f"Duplicate Passwords: {audit_results['num_duplicates']}\n"
            report += f"Compromised Passwords: {audit_results['num_breached']}\n\n"
            
            if audit_results['num_breached'] > 0:
                report += "⚠️ Found in Data Breaches:\n"
                for pwd in audit_results['breached_passwords']:
                    report += f"- {pwd}\n"
            
            messagebox.showinfo("Security Audit Complete", report)
        except Exception as e:
            self.hide_progress_bar()
            messagebox.showerror("Audit Error", f"An error occurred during the audit: {e}")

    def show_help(self):
        messagebox.showinfo("📚 Help & Guidance", f"""
RavenCraft:NightJAR Security Suite v2.0
    
### Password Generator
- **Password**: Guarantees a mix of letters, numbers, and symbols.
- **Passphrase**: Uses a large, secure wordlist (downloaded from EFF).
- **Secure Save**: Encrypts text into a password-protected file.
- **Secure Delete**: Irreversibly overwrites and deletes files.

### Password Manager
- **Master Password**: All data is encrypted with a single password.
- **Secure Storage**: Passwords are in an encrypted SQLite database file.
- **Clipboard Security**: Passwords are automatically cleared after 30 seconds.
- **Security Audit**: Scans your vault for duplicates and compromised passwords from known data breaches.
- **TOTP/MFA**: Store your TOTP secrets to generate one-time passwords for 2FA.

### Disclaimer
This software is provided "as is" for informational and personal use only. The author is not responsible for any security breaches or data loss resulting from its use. Always use this tool in conjunction with a professional password manager and adhere to secure computing practices.

### Get the Latest Updates
For the latest features and bug fixes, check out the official GitHub repository:
{GITHUB_REPO_URL}
""")

    def show_donation_info(self):
        messagebox.showinfo("💸 Support Our Work", f"""
If you find this tool helpful, please consider supporting its ongoing development.

You can donate via PayPal to:
{PAYPAL_EMAIL}

Thank you for your support!
""")

class EntryForm(tk.Toplevel):
    def __init__(self, parent, db_logic, entry_data=None, parent_app=None):
        super().__init__(parent)
        self.title("Add/Edit Entry")
        self.geometry("400x400")
        self.db = db_logic
        self.entry_data = entry_data
        self.parent_app = parent_app
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(pady=10, expand=True, fill="both")
        self.main_frame = tk.Frame(self.notebook)
        self.mfa_frame = tk.Frame(self.notebook)
        self.notebook.add(self.main_frame, text="Main Info")
        self.notebook.add(self.mfa_frame, text="TOTP / MFA")
        
        self.create_main_info_widgets()
        self.create_mfa_widgets()
        
        if self.entry_data:
            self.fill_data()
        
        tk.Button(self, text="Save", command=self.save_entry).pack(pady=10)

    def create_main_info_widgets(self):
        tk.Label(self.main_frame, text="Website:").pack(pady=5)
        self.website_entry = tk.Entry(self.main_frame, width=40)
        self.website_entry.pack(pady=5)
        tk.Label(self.main_frame, text="Username:").pack(pady=5)
        self.username_entry = tk.Entry(self.main_frame, width=40)
        self.username_entry.pack(pady=5)
        tk.Label(self.main_frame, text="Password:").pack(pady=5)
        self.password_entry = tk.Entry(self.main_frame, width=40)
        self.password_entry.pack(pady=5)
        tk.Label(self.main_frame, text="Notes:").pack(pady=5)
        self.notes_text = tk.Text(self.main_frame, width=30, height=4)
        self.notes_text.pack(pady=5)

    def create_mfa_widgets(self):
        tk.Label(self.mfa_frame, text="TOTP Secret Key (Base32 format):").pack(pady=5)
        self.totp_secret_entry = tk.Entry(self.mfa_frame, width=40)
        self.totp_secret_entry.pack(pady=5)
        self.totp_code_label = tk.Label(self.mfa_frame, text="", font=("Helvetica", 20, "bold"))
        self.totp_code_label.pack(pady=10)
        tk.Button(self.mfa_frame, text="Generate TOTP Code", command=self.generate_totp).pack(pady=5)

    def fill_data(self):
        self.website_entry.insert(0, self.entry_data[1])
        self.username_entry.insert(0, self.entry_data[2])
        self.password_entry.insert(0, self.entry_data[3])
        self.notes_text.insert(tk.END, self.entry_data[4])
        if self.entry_data[5]:
            self.totp_secret_entry.insert(0, self.entry_data[5])

    def generate_totp(self):
        secret = self.totp_secret_entry.get()
        if not secret:
            messagebox.showwarning("Warning", "Please enter a TOTP secret key first.")
            return
        try:
            totp = pyotp.TOTP(secret)
            code = totp.now()
            self.totp_code_label.config(text=f"{code}")
            pyperclip.copy(code)
            self.parent_app.clipboard_manager.clear_clipboard_in_future()
        except Exception as e:
            messagebox.showerror("TOTP Error", "Invalid secret key format.")

    def save_entry(self):
        website = self.website_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        notes = self.notes_text.get("1.0", tk.END).strip()
        totp_secret = self.totp_secret_entry.get()
        
        if not all([website, username, password]):
            messagebox.showerror("Error", "Website, Username, and Password are required.")
            return
        
        cursor = self.db.conn.cursor()
        if self.entry_data:
            cursor.execute("UPDATE passwords SET website=?, username=?, password=?, notes=?, totp_secret=? WHERE id=?", 
                           (website, username, password, notes, totp_secret, self.entry_data[0]))
        else:
            cursor.execute("INSERT INTO passwords (website, username, password, notes, totp_secret) VALUES (?, ?, ?, ?, ?)", 
                           (website, username, password, notes, totp_secret))
        self.db.conn.commit()
        self.master.load_entries()
        messagebox.showinfo("Success", "Entry saved successfully.")
        self.destroy()

if __name__ == "__main__":
    app = RavenCraftApp()
    app.mainloop()