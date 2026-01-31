import tkinter as tk
from tkinter import messagebox
import time
import re

from security import (
    create_master_password,
    master_exists,
    verify_master_password,
    generate_key,
    update_master_password
)

from vault import (
    add_credential,
    load_vault,
    export_backup,
    reencrypt_vault
)

# ---------------- GLOBALS ----------------
key = None
INACTIVITY_LIMIT = 60
last_activity = time.time()

# ---------------- PASSWORD STRENGTH ----------------
def password_strength(pwd):
    score = 0
    if len(pwd) >= 8: score += 1
    if re.search(r"[A-Z]", pwd): score += 1
    if re.search(r"[a-z]", pwd): score += 1
    if re.search(r"[0-9]", pwd): score += 1
    if re.search(r"[!@#$%^&*]", pwd): score += 1

    levels = ["Very Weak", "Weak", "Medium", "Strong", "Very Strong"]
    return levels[min(score, 4)]

# ---------------- ACTIVITY TRACK ----------------
def update_activity(event=None):
    global last_activity
    last_activity = time.time()

def check_inactivity():
    if time.time() - last_activity > INACTIVITY_LIMIT:
        messagebox.showwarning("Locked", "Session locked due to inactivity")
        vault_frame.pack_forget()
        show_login_screen()
        return
    root.after(5000, check_inactivity)

# ---------------- UI HELPERS ----------------
def show_login_screen():
    create_frame.pack_forget()
    vault_frame.pack_forget()
    login_frame.pack(pady=40)

def show_create_screen():
    login_frame.pack_forget()
    vault_frame.pack_forget()
    create_frame.pack(pady=40)

def show_vault():
    login_frame.pack_forget()
    create_frame.pack_forget()
    vault_frame.pack()

# ---------------- CREATE MASTER ----------------
def create_master():
    pwd = create_entry.get()

    if len(pwd) < 6:
        messagebox.showerror("Error", "Password must be at least 6 characters")
        return

    create_master_password(pwd)
    messagebox.showinfo("Success", "Master password created")
    show_login_screen()

# ---------------- LOGIN ----------------
def login():
    global key
    pwd = master_entry.get()

    if verify_master_password(pwd):
        key = generate_key(pwd)
        show_vault()
    else:
        messagebox.showerror("Error", "Wrong master password")

# ---------------- SAVE ----------------
def save_entry():
    add_credential(
        site_entry.get(),
        user_entry.get(),
        pass_entry.get(),
        key
    )
    messagebox.showinfo("Saved", "Credential stored securely")

# ---------------- VIEW ----------------
def show_entries():
    output.delete("1.0", tk.END)
    vault = load_vault(key)

    for site, c in vault.items():
        output.insert(
            tk.END,
            f"{site}\nUsername: {c['username']}\nPassword: {c['password']}\n\n"
        )

# ---------------- BACKUP ----------------
def backup():
    if export_backup():
        messagebox.showinfo("Backup", "Encrypted backup created")
    else:
        messagebox.showerror("Error", "No vault found")

# ---------------- CHANGE MASTER ----------------
def change_master():
    old_pwd = old_master_entry.get()
    new_pwd = new_master_entry.get()

    if len(new_pwd) < 6:
        messagebox.showerror("Error", "New password too short")
        return

    old_key = generate_key(old_pwd)

    if update_master_password(old_pwd, new_pwd):
        new_key = generate_key(new_pwd)
        reencrypt_vault(old_key, new_key)
        messagebox.showinfo("Success", "Master password changed")
    else:
        messagebox.showerror("Error", "Current password incorrect")

# ---------------- GUI ----------------
root = tk.Tk()
root.title("Secure Password Manager")
root.geometry("460x520")

root.bind_all("<Key>", update_activity)
root.bind_all("<Motion>", update_activity)
root.after(5000, check_inactivity)

# -------- CREATE MASTER FRAME --------
create_frame = tk.Frame(root)

tk.Label(create_frame, text="Create Master Password").pack()
create_entry = tk.Entry(create_frame, show="*")
create_entry.pack()
tk.Button(create_frame, text="Create", command=create_master).pack(pady=10)

# -------- LOGIN FRAME --------
login_frame = tk.Frame(root)

tk.Label(login_frame, text="Enter Master Password").pack()
master_entry = tk.Entry(login_frame, show="*")
master_entry.pack()
tk.Button(login_frame, text="Login", command=login).pack(pady=10)

# -------- VAULT FRAME --------
vault_frame = tk.Frame(root)

tk.Label(vault_frame, text="Website").pack()
site_entry = tk.Entry(vault_frame)
site_entry.pack()

tk.Label(vault_frame, text="Username").pack()
user_entry = tk.Entry(vault_frame)
user_entry.pack()

tk.Label(vault_frame, text="Password").pack()
pass_entry = tk.Entry(vault_frame)
pass_entry.pack()

strength_label = tk.Label(vault_frame, text="Strength:")
strength_label.pack()

def update_strength(event):
    strength_label.config(
        text="Strength: " + password_strength(pass_entry.get())
    )

pass_entry.bind("<KeyRelease>", update_strength)

tk.Button(vault_frame, text="Save Credential", command=save_entry).pack(pady=4)
tk.Button(vault_frame, text="View Vault", command=show_entries).pack(pady=4)
tk.Button(vault_frame, text="Backup Vault", command=backup).pack(pady=4)

# -------- CHANGE MASTER UI --------
tk.Label(vault_frame, text="Change Master Password").pack(pady=10)

old_master_entry = tk.Entry(vault_frame, show="*")
old_master_entry.pack()
old_master_entry.insert(0, "Current Master Password")

new_master_entry = tk.Entry(vault_frame, show="*")
new_master_entry.pack()
new_master_entry.insert(0, "New Master Password")

tk.Button(vault_frame, text="Change Master", command=change_master).pack(pady=5)

output = tk.Text(vault_frame, height=8)
output.pack()

# ---------------- STARTUP ----------------
if master_exists():
    show_login_screen()
else:
    show_create_screen()

root.mainloop()
