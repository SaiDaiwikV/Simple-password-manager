import os
import json
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

MASTER_FILE = "master.json"


# ---------------- CREATE MASTER PASSWORD ----------------
def create_master_password(password):
    salt = os.urandom(16)
    hashed = hashlib.sha512(salt + password.encode()).hexdigest()

    with open(MASTER_FILE, "w") as f:
        json.dump({
            "salt": base64.b64encode(salt).decode(),
            "hash": hashed
        }, f)


# ---------------- CHECK IF MASTER EXISTS ----------------
def master_exists():
    return os.path.exists(MASTER_FILE)


# ---------------- VERIFY MASTER PASSWORD ----------------
def verify_master_password(password):
    with open(MASTER_FILE, "r") as f:
        data = json.load(f)

    salt = base64.b64decode(data["salt"])
    hashed = hashlib.sha512(salt + password.encode()).hexdigest()

    return hashed == data["hash"]


# ---------------- GENERATE ENCRYPTION KEY ----------------
def generate_key(password):
    with open(MASTER_FILE, "r") as f:
        data = json.load(f)

    salt = base64.b64decode(data["salt"])

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


# ---------------- ENCRYPT / DECRYPT ----------------
def encrypt_data(data, key):
    return Fernet(key).encrypt(data.encode())


def decrypt_data(data, key):
    return Fernet(key).decrypt(data).decode()

def update_master_password(old_password, new_password):
    """
    Verifies old password, then updates master password
    """
    if not verify_master_password(old_password):
        return False

    # Create new salt & hash
    salt = os.urandom(16)
    new_hash = hashlib.sha512(salt + new_password.encode()).hexdigest()

    with open(MASTER_FILE, "w") as f:
        json.dump({
            "salt": base64.b64encode(salt).decode(),
            "hash": new_hash
        }, f)

    return True
