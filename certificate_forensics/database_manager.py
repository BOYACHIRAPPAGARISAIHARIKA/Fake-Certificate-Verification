import sqlite3, datetime, base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

class DBManager:
    def __init__(self, secret="VERICERT_ROOT"):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b'salt_', iterations=100000)
        key = base64.urlsafe_b64encode(kdf.derive(secret.encode()))
        self.f = Fernet(key)
        self.conn = sqlite3.connect("forensic_vault.db", check_same_thread=False)
        self.conn.execute("CREATE TABLE IF NOT EXISTS reg (id INTEGER PRIMARY KEY, name TEXT, hash TEXT)")
        self.conn.execute("CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY, event TEXT, time TEXT)")

    def register(self, name, h):
        enc_n, enc_h = self.f.encrypt(name.encode()), self.f.encrypt(h.encode())
        self.conn.execute("INSERT INTO reg (name, hash) VALUES (?,?)", (enc_n, enc_h))
        self.conn.commit()

    def verify(self, h):
        cursor = self.conn.execute("SELECT name, hash FROM reg")
        for n, hash_enc in cursor:
            if self.f.decrypt(hash_enc).decode() == h:
                return self.f.decrypt(n).decode()
        return None