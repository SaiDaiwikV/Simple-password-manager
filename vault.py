import os
import json
from security import encrypt_data, decrypt_data

VAULT_FILE = "vault.enc"


def load_vault(key):
    """
    Loads and decrypts vault data
    """
    if not os.path.exists(VAULT_FILE):
        return {}

    with open(VAULT_FILE, "rb") as f:
        encrypted = f.read()

    decrypted = decrypt_data(encrypted, key)
    return json.loads(decrypted)


def save_vault(data, key):
    """
    Encrypts and saves vault data
    """
    encrypted = encrypt_data(json.dumps(data), key)
    with open(VAULT_FILE, "wb") as f:
        f.write(encrypted)


def add_credential(site, username, password, key):
    """
    Adds or updates a credential
    """
    vault = load_vault(key)
    vault[site] = {"username": username, "password": password}
    save_vault(vault, key)


def export_vault_backup():
    """
    Creates encrypted backup of vault
    """
    if not os.path.exists(VAULT_FILE):
        return False

    with open(VAULT_FILE, "rb") as f:
        data = f.read()

    with open("vault_backup.enc", "wb") as b:
        b.write(data)

    return True
