# 🔐 Secure Password Manager (Python + Tkinter)

A **GUI-based Secure Password Manager** built using **Python** and
**Tkinter**, implementing **industry-standard cryptographic techniques**
to protect user credentials.\
The application enforces **master-password authentication**, encrypts
all stored data, and prevents unauthorized access.

This project demonstrates practical implementation of **cybersecurity
principles** such as hashing, encryption, key derivation, and secure
storage.

------------------------------------------------------------------------

## 🚀 Features

-   Master Password Creation on First Run\
-   Secure Login using Master Password\
-   SHA-512 Hashing with Per-User Random Salt\
-   PBKDF2 Key Derivation\
-   AES-Based Encryption (Fernet)\
-   Encrypted Credential Vault\
-   Auto-Lock After Inactivity\
-   Password Strength Meter\
-   Change Master Password (Re-encrypts Vault)\
-   Encrypted Vault Backup\
-   Simple and Clean GUI

------------------------------------------------------------------------

## 🧱 Architecture Overview

    User
      |
      v
    Tkinter GUI
      |
      v
    Authentication (SHA-512 + Salt)
      |
      v
    Key Derivation (PBKDF2)
      |
      v
    AES Encryption / Decryption
      |
      v
    Encrypted Vault (vault.enc)

------------------------------------------------------------------------

## 📂 Project Structure

    Simple-Password-Manager/
    │
    ├── app.py          # GUI and application logic
    ├── security.py     # Hashing, salting, encryption, key management
    ├── vault.py        # Encrypted vault handling & backup
    ├── master.json     # Stores salt + master password hash (auto-created)
    ├── vault.enc       # Encrypted credentials (auto-created)

------------------------------------------------------------------------

## ⚙️ Technologies Used

-   Python 3\
-   Tkinter (GUI)\
-   Cryptography Library\
-   SHA-512 Hash Algorithm\
-   PBKDF2 Key Derivation\
-   AES (Fernet) Encryption

------------------------------------------------------------------------

## 🛠 Installation

### 1️⃣ Clone Repository

``` bash
git clone https://github.com/SaiDaiwikV/Simple-password-manager.git
cd Simple-password-manager
```

### 2️⃣ Install Dependency

``` bash
pip install cryptography
```

### 3️⃣ Run Application

``` bash
python app.py
```

------------------------------------------------------------------------

## 🔐 How It Works

### First Launch

-   User creates a master password
-   Password is hashed with SHA-512 and salted
-   Hash and salt stored in `master.json`

### Login

-   User enters master password
-   Hash is verified
-   Encryption key derived using PBKDF2

### Vault Operations

-   Add credentials
-   View credentials
-   All credentials are encrypted before storage

### Change Master Password

-   Verifies old password
-   Generates new salt and hash
-   Re-encrypts entire vault with new key

### Auto-Lock

-   If user is inactive for 60 seconds, session locks automatically

------------------------------------------------------------------------

## 🛡 Security Highlights

-   No plaintext password storage\
-   Strong cryptographic hashing\
-   Secure key derivation\
-   Encrypted local storage\
-   Access control via master password\
-   Backup stored only in encrypted form

------------------------------------------------------------------------

## 📌 Resume Description

Developed a GUI-based secure password manager using Python and Tkinter,
implementing SHA-512 hashing with per-user salt, PBKDF2 key derivation,
AES-based encrypted credential storage, inactivity auto-lock, password
strength analysis, master-password rotation, and encrypted vault backup.

------------------------------------------------------------------------

## 👨‍💻 Author

**Sai Daiwik V**\
B.Tech -- Computer Science Engineering

------------------------------------------------------------------------

## 📜 License

This project is intended for educational purposes only.

