import os
import sqlite3
import base64
import json
from typing import Optional, List

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from crypto_core import VaultCrypto

app = FastAPI(title="CipherVault API")
DB_FILE = "vault.db"


# --- Helpers ---
def normalize_service(s: str) -> str:
    return (s or "").strip().lower()


def db():
    return sqlite3.connect(DB_FILE)


def column_is_notnull(conn: sqlite3.Connection, table: str, col: str) -> bool:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    for r in rows:
        if r[1] == col:
            return bool(r[3])
    return False


def init_db():
    """Initialize DB + migrate old schema if username was NOT NULL."""
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS metadata (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                salt TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS vault (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service TEXT NOT NULL,
                username TEXT,
                nonce TEXT NOT NULL,
                ciphertext TEXT NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_vault_service ON vault(service)")

        # Migration (old username NOT NULL -> nullable)
        try:
            if column_is_notnull(conn, "vault", "username"):
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS vault_new (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        service TEXT NOT NULL,
                        username TEXT,
                        nonce TEXT NOT NULL,
                        ciphertext TEXT NOT NULL
                    )
                """)
                conn.execute("""
                    INSERT INTO vault_new (id, service, username, nonce, ciphertext)
                    SELECT id, service, username, nonce, ciphertext FROM vault
                """)
                conn.execute("DROP TABLE vault")
                conn.execute("ALTER TABLE vault_new RENAME TO vault")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_vault_service ON vault(service)")
                conn.commit()
        except sqlite3.OperationalError:
            pass


init_db()

# Frontend
app.mount("/static", StaticFiles(directory="static"), name="static")


# --- Models ---
class PasswordEntry(BaseModel):
    service: str
    username: Optional[str] = ""
    password: str
    master_password: str


class MasterPass(BaseModel):
    master_password: str


class VaultListItem(BaseModel):
    id: int
    service: str
    username: str


# --- Crypto salt ---
def get_db_salt() -> Optional[bytes]:
    with db() as conn:
        res = conn.execute("SELECT salt FROM metadata WHERE id = 1").fetchone()
        return base64.b64decode(res[0]) if res else None


def ensure_salt(master_password: str) -> bytes:
    salt = get_db_salt()
    if salt:
        return salt

    crypto = VaultCrypto(master_password, salt=None)
    with db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO metadata (id, salt) VALUES (1, ?)",
            (crypto.get_salt_b64(),)
        )
    return base64.b64decode(crypto.get_salt_b64())


def verify_master_password(master_password: str) -> None:
    """Verify master password by trying to decrypt latest row."""
    salt = get_db_salt()
    if not salt:
        return

    crypto = VaultCrypto(master_password, salt=salt)

    with db() as conn:
        row = conn.execute(
            "SELECT nonce, ciphertext FROM vault ORDER BY id DESC LIMIT 1"
        ).fetchone()

    if not row:
        return

    nonce, ciphertext = row
    try:
        crypto.decrypt_data(nonce, ciphertext)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid master password.")


# --- Routes ---
@app.post("/add")
def add_password(entry: PasswordEntry):
    salt = ensure_salt(entry.master_password)
    crypto = VaultCrypto(entry.master_password, salt=salt)

    service_norm = normalize_service(entry.service)
    username_clean = (entry.username or "").strip()

    # Encrypt username + password together
    payload = json.dumps({"username": username_clean, "password": entry.password})
    encrypted = crypto.encrypt_data(payload)

    # Do NOT store plaintext username in DB
    username_placeholder = ""

    with db() as conn:
        conn.execute(
            "INSERT INTO vault (service, username, nonce, ciphertext) VALUES (?, ?, ?, ?)",
            (service_norm, username_placeholder, encrypted["nonce"], encrypted["ciphertext"])
        )

    return {"status": "success", "message": f"Credentials for '{entry.service}' saved successfully."}


@app.post("/get/{service}")
def get_password(service: str, auth: MasterPass):
    """Default: return the latest saved credential for this service."""
    salt = get_db_salt()
    if not salt:
        raise HTTPException(status_code=404, detail="Vault is empty or not initialized.")

    crypto = VaultCrypto(auth.master_password, salt=salt)
    service_norm = normalize_service(service)

    with db() as conn:
        res = conn.execute(
            """
            SELECT id, nonce, ciphertext
            FROM vault
            WHERE service = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (service_norm,)
        ).fetchone()

    if not res:
        raise HTTPException(status_code=404, detail="Service not found in the vault.")

    _id, nonce, ciphertext = res

    try:
        decrypted = crypto.decrypt_data(nonce, ciphertext)
        data = json.loads(decrypted)
        return {
            "id": _id,
            "service": service_norm,
            "username": data.get("username", ""),
            "password": data.get("password", "")
        }
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid master password or corrupted data.")


# --- Dropdown support: LIST all entries for a service (POST for frontend) ---
@app.post("/list/{service}")
def list_service_entries(service: str, auth: MasterPass):
    """
    Returns all entries for a service:
      [{id, username, locked}]
    If some entries were encrypted with another master password,
    they will be returned as locked (no crash).
    """
    salt = get_db_salt()
    if not salt:
        return {"service": normalize_service(service), "items": []}

    crypto = VaultCrypto(auth.master_password, salt=salt)
    service_norm = normalize_service(service)

    with db() as conn:
        rows = conn.execute(
            """
            SELECT id, nonce, ciphertext
            FROM vault
            WHERE service = ?
            ORDER BY id DESC
            """,
            (service_norm,)
        ).fetchall()

    items = []
    for _id, nonce, ciphertext in rows:
        try:
            decrypted = crypto.decrypt_data(nonce, ciphertext)
            data = json.loads(decrypted)
            username = (data.get("username") or "").strip()
            items.append({"id": _id, "username": username, "locked": False})
        except Exception:
            items.append({"id": _id, "username": "Locked (wrong master)", "locked": True})

    return {"service": service_norm, "items": items}


@app.post("/get_by_id/{item_id}")
def get_by_id(item_id: int, auth: MasterPass):
    """Decrypt a specific entry by its ID."""
    salt = get_db_salt()
    if not salt:
        raise HTTPException(status_code=404, detail="Vault is empty or not initialized.")

    crypto = VaultCrypto(auth.master_password, salt=salt)

    with db() as conn:
        row = conn.execute(
            "SELECT service, nonce, ciphertext FROM vault WHERE id = ?",
            (item_id,)
        ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Item not found.")

    service_norm, nonce, ciphertext = row

    try:
        decrypted = crypto.decrypt_data(nonce, ciphertext)
        data = json.loads(decrypted)
        return {
            "id": item_id,
            "service": service_norm,
            "username": data.get("username", ""),
            "password": data.get("password", "")
        }
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid master password or corrupted data.")


@app.post("/list")
def list_services(auth: MasterPass) -> List[VaultListItem]:
    """Recent entries (service + placeholder username)."""
    salt = get_db_salt()
    if not salt:
        return []

    verify_master_password(auth.master_password)

    with db() as conn:
        rows = conn.execute(
            "SELECT id, service, COALESCE(username, '') FROM vault ORDER BY id DESC LIMIT 200"
        ).fetchall()

    return [{"id": r[0], "service": r[1], "username": r[2]} for r in rows]


@app.delete("/delete/{item_id}")
def delete_item(item_id: int, auth: MasterPass):
    salt = get_db_salt()
    if not salt:
        raise HTTPException(status_code=404, detail="Vault is empty.")

    verify_master_password(auth.master_password)

    with db() as conn:
        cur = conn.execute("DELETE FROM vault WHERE id = ?", (item_id,))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Item not found.")

    return {"status": "success", "message": f"Deleted item #{item_id}."}


@app.get("/")
async def read_index():
    return FileResponse(os.path.join("static", "index.html"))