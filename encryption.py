# encryption.py

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os

# 1. دالة اشتقاق المفتاح (Key Derivation Function)
# ---------------------------------------------------------------------
# هذه الدالة ضرورية: تقوم بتحويل كلمة مرور المستخدم إلى مفتاح تشفير قوي (32 بايت)
# باستخدام PBKDF2. هذا يضمن أن المفتاح مرتبط بكلمة المرور ولا يُخزن بشكل صريح.

def derive_key(password: str, salt: bytes) -> bytes:
    """
    اشتقاق مفتاح AES 256-bit من كلمة المرور والـ Salt باستخدام PBKDF2.
    ملاحظة: يجب تخزين الـ salt الخاص بكل مستخدم في قاعدة البيانات.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, # مفتاح 256 بت
        salt=salt,
        iterations=480000, # عدد تكرارات عالٍ للأمان
    )
    return kdf.derive(password.encode())

# 2. دالة التشفير
# ---------------------------------------------------------------------

def encrypt_image(image_bytes: bytes, key: bytes):
    """
    تشفير الصورة باستخدام المفتاح المُمرر و AES-GCM.
    المدخل: image_bytes (بيانات الصورة), key (المفتاح المشتق)
    المخرجات: dict {'ciphertext', 'iv'}
    """
    aesgcm = AESGCM(key)
    iv = os.urandom(12) # Nonce (IV) 12 بايت للـ GCM
    ciphertext = aesgcm.encrypt(iv, image_bytes, associated_data=None)
    return {
        'ciphertext': ciphertext,
        'iv': iv
    }

# 3. دالة فك التشفير
# ---------------------------------------------------------------------

def decrypt_image(ciphertext: bytes, iv: bytes, key: bytes):
    """
    فك تشفير الصورة باستخدام المفتاح المُمرر و AES-GCM.
    المدخل: ciphertext (النص المشفر), iv (متجه التهيئة), key (المفتاح المشتق)
    المخرجات: plaintext (بيانات الصورة الأصلية)
    """
    aesgcm = AESGCM(key)
    # ملاحظة: إذا كان المفتاح خاطئًا أو تم التلاعب بالبيانات، فستطلق دالة .decrypt استثناء.
    plaintext = aesgcm.decrypt(iv, ciphertext, associated_data=None)
    return plaintext
