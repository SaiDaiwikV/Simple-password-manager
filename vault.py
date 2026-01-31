import os
import json
from security import encrypt_data, decrypt_data

VAULT_FILE = "vault.enc"


def load_vault(key):
    if not os.path.exists(VAULT_FILE):
        return {}

    with open(VAULT_FILE, "rb") as f:
        encrypted = f.read()

    decrypted = decrypt_data(encrypted, key)
    return json.loads(decrypted)


def save_vault(data, key):
    encrypted = encrypt_data(json.dumps(data), key)

    with open(VAULT_FILE, "wb") as f:
        f.write(encrypted)


def add_credential(site, username, password, key):
    vault = load_vault(key)
    vault[site] = {
        "username": username,
        "password": password
    }
    save_vault(vault, key)


def export_backup():
    if not os.path.exists(VAULT_FILE):
        return False

    with open(VAULT_FILE, "rb") as f:
        data = f.read()

    with open("vault_backup.enc", "wb") as b:
        b.write(data)

    return True

def reencrypt_vault(old_key, new_key):
    """
    Re-encrypt vault with new encryption key
    """
    if not os.path.exists(VAULT_FILE):
        return

    with open(VAULT_FILE, "rb") as f:
        encrypted = f.read()

    data = decrypt_data(encrypted, old_key)
    new_encrypted = encrypt_data(data, new_key)

    with open(VAULT_FILE, "wb") as f:
        f.write(new_encrypted)
