import os
import base64
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class VaultCrypto:
    def __init__(self, master_password: str, salt: bytes = None):
        # Agar salt berilmasa, yangi ombor uchun 16 baytli tasodifiy salt yaratiladi
        self.salt = salt or os.urandom(16)
        
        # Master paroldan 256-bitli (32 bayt) kalit generatsiya qilish (Argon2id)
        self.key = hash_secret_raw(
            secret=master_password.encode('utf-8'),
            salt=self.salt,
            time_cost=2,
            memory_cost=102400, # 100 MB xotira talabi (brute-force ni qiyinlashtiradi)
            parallelism=8,
            hash_len=32,
            type=Type.ID
        )
        # AES-GCM shifrlash obyekti
        self.aesgcm = AESGCM(self.key)

    def encrypt_data(self, data: str) -> dict:
        """Ma'lumotni AES-256-GCM yordamida shifrlash."""
        nonce = os.urandom(12) # Har bir shifrlash uchun unikal Nonce
        ciphertext = self.aesgcm.encrypt(nonce, data.encode('utf-8'), None)
        
        return {
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
        }

    def decrypt_data(self, nonce_b64: str, ciphertext_b64: str) -> str:
        """Shifrlangan ma'lumotni qayta tiklash."""
        nonce = base64.b64decode(nonce_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
        
        # Agar kalit noto'g'ri bo'lsa yoki ma'lumot o'zgartirilgan bo'lsa, xatolik beradi
        decrypted_data = self.aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted_data.decode('utf-8')

    def get_salt_b64(self) -> str:
        return base64.b64encode(self.salt).decode('utf-8')
