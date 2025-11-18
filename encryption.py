from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, base64

# توليد مفتاح AES ثابت
AES_KEY = AESGCM.generate_key(bit_length=256)

def encrypt_image(image_bytes):
    """
    تشفير الصورة.
    المدخل: bytes
    المخرجات: dict {ciphertext, iv}
    """
    aesgcm = AESGCM(AES_KEY)
    iv = os.urandom(12)  # 12 بايت للـ GCM
    ciphertext = aesgcm.encrypt(iv, image_bytes, associated_data=None)
    return {
        'ciphertext': ciphertext,
        'iv': iv
    }

def decrypt_image(ciphertext, iv):
    aesgcm = AESGCM(AES_KEY)
    plaintext = aesgcm.decrypt(iv, ciphertext, associated_data=None)
    return plaintext
