# 🔐 CipherVault: Professional Zero-Knowledge Password Manager

**CipherVault** is a secure, cross-platform password management solution designed with a focus on high-performance cryptography and professional-grade security standards. It features a **Web-based Dashboard** ensuring versatility for both power users and security professionals.

## 🛡️ Security Architecture

This project implements a "Zero-Knowledge" architecture, meaning the server never stores or knows your Master Password.

* **Key Derivation:** Uses **Argon2id** to derive a 256-bit key from your Master Password, providing industry-leading resistance against brute-force attacks.
* **Encryption:** Implements **AES-256-GCM** for authenticated encryption, ensuring both data confidentiality and integrity.
* **Storage:** Uses a local **SQLite** database, keeping your data under your own control.

## 🚀 Technical Stack

* **Backend:** FastAPI (Python) - High performance and robust API.
* **Cryptography:** `cryptography` and `argon2-cffi` libraries.
* **Frontend:** HTML5, Tailwind CSS, JavaScript (Fetch API).
* **Database:** SQLite3.

## 🛠️ Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/LuminaryX-X/CipherVault.git](https://github.com/LuminaryX-X/CipherVault.git)
   cd CipherVault
   source venv/bin/activate
   pip install uvicorn
   python -m uvicorn server:app --reload
