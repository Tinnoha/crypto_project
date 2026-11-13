
import hashlib
import hmac
import secrets
import sqlite3

from .crypto_engine import CryptoEngine

class TokenVault:

    def __init__(self, database: str, master_key: bytes):
        self.database = database
        self.engine = CryptoEngine(master_key)

        self.index_key = hashlib.sha256(
            b"tokenization-index-v1" + master_key
        ).digest()

        self._initialize_database()

    def _connect(self):
        connection = sqlite3.connect(self.database)
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _initialize_database(self):
        with self._connect() as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS tokens (
                    token TEXT PRIMARY KEY,
                    lookup_hash TEXT UNIQUE NOT NULL,
                    encryption_mode TEXT NOT NULL,
                    nonce BLOB,
                    ciphertext BLOB NOT NULL,
                    auth_tag BLOB
                )
            """)

    def _lookup_hash(self, value: str) -> str:
        return hmac.new(
            self.index_key,
            value.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

    def tokenize(
        self,
        value: str,
        mode: str = "AES-GCM"
    ) -> str:

        if not isinstance(value, str) or not value:
            raise ValueError("Некорректное значение")

        if mode not in ("AES-GCM", "AES-SIV"):
            raise ValueError("Недопустимый режим")

        lookup_hash = self._lookup_hash(value)

        # Повторное использование существующего токена.
        with self._connect() as db:
            existing = db.execute(
                "SELECT token FROM tokens WHERE lookup_hash = ?",
                (lookup_hash,)
            ).fetchone()

            if existing:
                return existing[0]

            token = "tok_" + secrets.token_urlsafe(24)

            encrypted = self.engine.encrypt(
                value.encode("utf-8"),
                mode,
                token.encode("utf-8")
            )

            db.execute("""
                INSERT INTO tokens (
                    token,
                    lookup_hash,
                    encryption_mode,
                    nonce,
                    ciphertext,
                    auth_tag
                )
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                token,
                lookup_hash,
                mode,
                encrypted["nonce"],
                encrypted["ciphertext"],
                encrypted["tag"]
            ))

            return token

    def detokenize(self, token: str) -> str:

        with self._connect() as db:
            record = db.execute("""
                SELECT
                    encryption_mode,
                    nonce,
                    ciphertext,
                    auth_tag
                FROM tokens
                WHERE token = ?
            """, (token,)).fetchone()

        if record is None:
            raise ValueError("Токен не найден")

        mode, nonce, ciphertext, tag = record

        plaintext = self.engine.decrypt(
            ciphertext=ciphertext,
            mode=mode,
            aad=token.encode("utf-8"),
            nonce=nonce,
            tag=tag
        )

        return plaintext.decode("utf-8")
