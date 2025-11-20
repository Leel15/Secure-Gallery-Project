from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return kdf.derive(password.encode())


def encrypt_image(image_bytes: bytes, key: bytes):

    aesgcm = AESGCM(key)
    iv = os.urandom(12)
    ciphertext = aesgcm.encrypt(iv, image_bytes, associated_data=None)
    return {
        'ciphertext': ciphertext,
        'iv': iv
    }


def decrypt_image(ciphertext: bytes, iv: bytes, key: bytes):

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(iv, ciphertext, associated_data=None)
    return plaintext
