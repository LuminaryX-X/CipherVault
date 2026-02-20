# 🔐 CipherVault: Professional Zero-Knowledge Password Manager

**CipherVault** is a secure, cross-platform password management solution designed with a focus on high-performance cryptography and professional-grade security standards. It features both a **Web-based Dashboard** and a **CLI interface**, ensuring versatility for both power users and security professionals.

## 🛡️ Security Architecture

This project implements a "Zero-Knowledge" architecture, meaning the server never stores or knows your Master Password.

* **Key Derivation:** Uses **Argon2id** (the winner of the Password Hashing Competition) to derive a 256-bit key from your Master Password. This provides industry-leading resistance against GPU-based brute-force attacks.
* **Encryption:** Implements **AES-256-GCM** (Galois/Counter Mode). This authenticated encryption ensures not only data confidentiality but also data integrity—if the encrypted data is tampered with, decryption will fail.
* **Storage:** Uses a local **SQLite** database, keeping your data under your own control.

## 🚀 Technical Stack

* **Backend:** FastAPI (Python) - High performance and robust API.
* **Cryptography:** `cryptography` and `argon2-cffi` libraries.
* **Frontend:** HTML5, Tailwind CSS, JavaScript (Fetch API).
* **Database:** SQLite3.
* **CLI:** Click & Rich for a professional terminal experience.

## 🛠️ Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/YOUR_USERNAME/CipherVault.git](https://github.com/YOUR_USERNAME/CipherVault.git)
   cd CipherVault