import tkinter as tk
from tkinter import messagebox
import time
import re

from security import verify_master_password, generate_encryption_key
from vault import add_credential, load_vault, export_vault_backup

# ------------------ GLOBAL SETTINGS ------------------
INACTIVITY_LIMIT = 60  # seconds
last_activity = time.time()
key = None

# ------------------ PASSWORD STRENGTH ------------------
def password_strength(pwd):
    score = 0
    if len(pwd) >= 8: score += 1
    if re.search(r"[A-Z]", pwd): score += 1
    if re.search(r"[a-z]", pwd): score += 1
    if re.search(r"[0-9]", pwd): score += 1
    if re.search(r"[!@#$%^&*]", pwd): score += 1

    levels = ["Very Weak", "Weak", "Medium", "Strong", "Very Strong"]
    return levels[min(score, 4)]


# ------------------ AUTO LOCK ------------------
def update_activity(event=None):
    global last_activity
    last_activity = time.time()


def check_inactivity():
    if time.time() - last_activity > INACTIVITY_LIMIT:
        messagebox.showwarning("Locked", "Vault locked due to inactivity")
        vault_frame.pack_forget()
        login_frame.pack()
        return
    root.after(5000, check_inactivity)


# ------------------ LOGIN ------------------
def login():
    global key
    pwd = master_entry.get()
    ok, password = verify_master_password(pwd)

    if not ok:
        messagebox.showerror("Error", "Wrong master password")
        return

    key = generate_encryption_key(password)
    login_frame.pack_forget()
    vault_frame.pack()


# ------------------ VAULT ACTIONS ------------------
def save_entry():
    add_credential(
        site_entry.get(),
        user_entry.get(),
        pass_entry.get(),
        key
    )
    messagebox.showinfo("Saved", "Credential stored securely")


def show_entries():
    output.delete("1.0", tk.END)
    vault = load_vault(key)

    for site, c in vault.items():
        output.insert(
            tk.END,
            f"{site}\nUsername: {c['username']}\nPassword: {c['password']}\n\n"
        )


def backup_vault():
    if export_vault_backup():
        messagebox.showinfo("Backup", "Encrypted backup created")
    else:
        messagebox.showerror("Error", "No vault found")


# ------------------ GUI SETUP ------------------
root = tk.Tk()
root.title("Secure Password Manager")
root.geometry("420x420")

root.bind_all("<Key>", update_activity)
root.bind_all("<Motion>", update_activity)
root.after(5000, check_inactivity)

# ------------------ LOGIN FRAME ------------------
login_frame = tk.Frame(root)
login_frame.pack(pady=40)

tk.Label(login_frame, text="Master Password").pack()
master_entry = tk.Entry(login_frame, show="*")
master_entry.pack()
tk.Button(login_frame, text="Login", command=login).pack(pady=10)

# ------------------ VAULT FRAME ------------------
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
tk.Button(vault_frame, text="Backup Vault", command=backup_vault).pack(pady=4)

output = tk.Text(vault_frame, height=8)
output.pack()

root.mainloop()
