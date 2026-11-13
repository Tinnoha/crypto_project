
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Crypto.Cipher import AES


class CryptoEngine:
    """
    Криптографический движок с поддержкой AES-GCM и AES-SIV.

    Для каждого режима используется отдельный ключ.
    """

    def __init__(self, master_key: bytes):
        if len(master_key) < 32:
            raise ValueError("Master key должен быть не менее 32 байт")

        # Разделение ключевого материала по назначению.
        self.gcm_key = hashlib.sha256(
            b"tokenization-gcm-v1" + master_key
        ).digest()

        self.siv_key = hashlib.sha512(
            b"tokenization-siv-v1" + master_key
        ).digest()

    def encrypt(self, plaintext: bytes, mode: str, aad: bytes):
        if mode == "AES-GCM":
            nonce = __import__("secrets").token_bytes(12)

            cipher = AESGCM(self.gcm_key)

            ciphertext = cipher.encrypt(
                nonce,
                plaintext,
                aad
            )

            return {
                "nonce": nonce,
                "ciphertext": ciphertext,
                "tag": None
            }

        elif mode == "AES-SIV":
            cipher = AES.new(
                self.siv_key,
                AES.MODE_SIV
            )

            cipher.update(aad)

            ciphertext, tag = cipher.encrypt_and_digest(
                plaintext
            )

            return {
                "nonce": None,
                "ciphertext": ciphertext,
                "tag": tag
            }

        else:
            raise ValueError("Неподдерживаемый режим шифрования")

    def decrypt(
        self,
        ciphertext: bytes,
        mode: str,
        aad: bytes,
        nonce: bytes = None,
        tag: bytes = None
    ) -> bytes:

        if mode == "AES-GCM":
            if nonce is None:
                raise ValueError("Отсутствует nonce")

            cipher = AESGCM(self.gcm_key)

            return cipher.decrypt(
                nonce,
                ciphertext,
                aad
            )

        elif mode == "AES-SIV":
            if tag is None:
                raise ValueError("Отсутствует authentication tag")

            cipher = AES.new(
                self.siv_key,
                AES.MODE_SIV
            )

            cipher.update(aad)

            return cipher.decrypt_and_verify(
                ciphertext,
                tag
            )

        else:
            raise ValueError("Неподдерживаемый режим шифрования")
