import os
import json
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

MASTER_FILE = "master.json"


def create_master_password(password):
    """
    Creates master password:
    - Generates random salt
    - Hashes password using SHA-512
    - Stores salt + hash
    """
    salt = os.urandom(16)
    hashed = hashlib.sha512(salt + password.encode()).hexdigest()

    with open(MASTER_FILE, "w") as f:
        json.dump({
            "salt": base64.b64encode(salt).decode(),
            "hash": hashed
        }, f)


def verify_master_password(password):
    """
    Verifies entered master password
    """
    if not os.path.exists(MASTER_FILE):
        create_master_password(password)
        return True, password

    with open(MASTER_FILE, "r") as f:
        data = json.load(f)

    salt = base64.b64decode(data["salt"])
    hashed = hashlib.sha512(salt + password.encode()).hexdigest()

    return hashed == data["hash"], password


def generate_encryption_key(password):
    """
    Derives encryption key using PBKDF2
    """
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


def encrypt_data(data, key):
    """
    Encrypts data using AES (Fernet)
    """
    return Fernet(key).encrypt(data.encode())


def decrypt_data(data, key):
    """
    Decrypts encrypted data
    """
    return Fernet(key).decrypt(data).decode()
