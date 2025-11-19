import os
import sqlite3
import bcrypt
import uuid
import datetime

DB_FILE = "users_new.db"


def get_db_connection():
    return sqlite3.connect(DB_FILE)


def init_db():
    if os.path.exists(DB_FILE):
        try:
            conn = get_db_connection()
            conn.execute("SELECT name FROM sqlite_master LIMIT 1;")
            conn.close()
        except sqlite3.DatabaseError:
            os.remove(DB_FILE)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT,
            password_hash TEXT NOT NULL,
            salt_for_key_derivation BLOB
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at TEXT NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS photos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            enc_path TEXT NOT NULL,
            iv_path TEXT NOT NULL,
            FOREIGN KEY (username) REFERENCES users(username)
        )
    ''')

    conn.commit()
    conn.close()


def register_user(username, email, password):
    conn = get_db_connection()
    cursor = conn.cursor()

    # نولد salt جديد لتجزئة كلمة المرور ولعملية اشتقاق المفتاح
    salt_key = os.urandom(16)
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    try:
        cursor.execute(
            "INSERT INTO users (username, email, password_hash, salt_for_key_derivation) VALUES (?, ?, ?, ?)",
            (username, email, hashed, salt_key)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def get_user_data(username):
    """جلب بيانات المستخدم بما في ذلك hash و salt."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash, salt_for_key_derivation FROM users WHERE username=?", (username,))
    result = cursor.fetchone()
    conn.close()
    return result


def verify_user(username, password):
    """التحقق من المستخدم (لا يتم استخدامه لتوليد المفتاح مباشرة)."""
    result = get_user_data(username)

    if result and bcrypt.checkpw(password.encode('utf-8'), result[0]):
        return True
    return False



def save_photo_metadata(username, original_filename, enc_path, iv_path):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO photos (username, original_filename, enc_path, iv_path) VALUES (?, ?, ?, ?)",
            (username, original_filename, enc_path, iv_path)
        )
        conn.commit()
        return True
    except sqlite3.Error:
        return False
    finally:
        conn.close()


def get_user_photos(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT original_filename, enc_path, iv_path FROM photos WHERE username = ?",
        (username,)
    )
    photos = cursor.fetchall()
    conn.close()
    return photos


def delete_photo_metadata(username, enc_path):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM photos WHERE username = ? AND enc_path = ?",
        (username, enc_path)
    )
    conn.commit()
    rows_deleted = cursor.rowcount
    conn.close()
    return rows_deleted > 0


def create_reset_token(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username=?", (username,))
    if not cursor.fetchone():
        conn.close()
        return None

    token = str(uuid.uuid4())
    expires_at = (datetime.datetime.utcnow() + datetime.timedelta(hours=1)).isoformat()

    cursor.execute("INSERT INTO password_resets (username, token, expires_at) VALUES (?, ?, ?)",
                   (username, token, expires_at))
    conn.commit()
    conn.close()
    return token


def verify_reset_token(token):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username, expires_at FROM password_resets WHERE token=?", (token,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    username, expires_at = row
    if datetime.datetime.utcnow() <= datetime.datetime.fromisoformat(expires_at):
        return username
    return None


def reset_user_password(token, new_password):
    username = verify_reset_token(token)
    if not username:
        return False

    conn = get_db_connection()
    cursor = conn.cursor()

    salt_key = os.urandom(16)
    hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

    cursor.execute("UPDATE users SET password_hash=?, salt_for_key_derivation=? WHERE username=?",
                   (hashed, salt_key, username))
    cursor.execute("DELETE FROM password_resets WHERE token=?", (token,))
    conn.commit()
    conn.close()
    return True

