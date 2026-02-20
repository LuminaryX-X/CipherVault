import os
import sqlite3
import base64
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from crypto_core import VaultCrypto

app = FastAPI(title="CipherVault API")
DB_FILE = "vault.db"

# --- Database Initialization ---
def init_db():
    """Initializes the SQLite database and creates necessary tables for secure storage."""
    with sqlite3.connect(DB_FILE) as conn:
        # Table for storing AES-GCM encrypted credentials
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vault (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service TEXT NOT NULL,
                username TEXT NOT NULL,
                nonce TEXT NOT NULL,
                ciphertext TEXT NOT NULL
            )
        """)
        # Table for storing the global encryption salt (used in Argon2id key derivation)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS metadata (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                salt TEXT NOT NULL
            )
        """)

# Initialize database on server startup
init_db()

# Mount the static directory to serve the frontend web interface
app.mount("/static", StaticFiles(directory="static"), name="static")

class PasswordEntry(BaseModel):
    service: str
    username: str
    password: str
    master_password: str

class MasterPass(BaseModel):
    master_password: str

def get_db_salt():
    """Retrieves the global salt used for the Key Derivation Function (KDF)."""
    with sqlite3.connect(DB_FILE) as conn:
        res = conn.execute("SELECT salt FROM metadata WHERE id = 1").fetchone()
        return base64.b64decode(res[0]) if res else None

@app.post("/add")
def add_password(entry: PasswordEntry):
    """Encrypts and stores a new credential entry into the vault."""
    salt = get_db_salt()
    
    # Initialize the cryptographic core. If salt is None, a new one is securely generated.
    crypto = VaultCrypto(entry.master_password, salt=salt)
    
    # Save the dynamically generated salt if this is the very first vault entry
    if not salt:
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute("INSERT OR IGNORE INTO metadata (id, salt) VALUES (1, ?)", (crypto.get_salt_b64(),))

    # Encrypt the plaintext password using AES-256-GCM
    encrypted = crypto.encrypt_data(entry.password)
    
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            "INSERT INTO vault (service, username, nonce, ciphertext) VALUES (?, ?, ?, ?)",
            (entry.service, entry.username, encrypted['nonce'], encrypted['ciphertext'])
        )
    return {"status": "success", "message": f"Credentials for '{entry.service}' saved successfully."}

@app.post("/get/{service}")
def get_password(service: str, auth: MasterPass):
    """Retrieves and decrypts a credential entry based on the service name."""
    salt = get_db_salt()
    if not salt: 
        raise HTTPException(status_code=404, detail="Vault is empty or not initialized.")

    # Reconstruct the decryption key using the provided master password and stored salt
    crypto = VaultCrypto(auth.master_password, salt=salt)
    
    with sqlite3.connect(DB_FILE) as conn:
        # Using LOWER() to make the service name search case-insensitive (e.g., 'Github' matches 'github')
        res = conn.execute(
            "SELECT nonce, ciphertext FROM vault WHERE LOWER(service) = LOWER(?)", 
            (service,)
        ).fetchone()
    
    if not res: 
        raise HTTPException(status_code=404, detail="Service not found in the vault.")

    try:
        # Attempt to decrypt. Will fail if the master password is wrong or data was tampered with.
        decrypted = crypto.decrypt_data(res[0], res[1])
        return {"service": service, "password": decrypted}
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid master password or corrupted data.")

@app.get("/")
async def read_index():
    """Serves the main frontend UI dashboard."""
    return FileResponse(os.path.join('static', 'index.html'))