import os
import sqlite3
import bcrypt
import uuid
import datetime

DB_FILE = "users_new.db"


def init_db():

    if os.path.exists(DB_FILE):
        try:
            conn = sqlite3.connect(DB_FILE)
            conn.execute("SELECT name FROM sqlite_master LIMIT 1;")
            conn.close()
        except sqlite3.DatabaseError:
            os.remove(DB_FILE)

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # جدول المستخدمين
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT,
            password_hash TEXT NOT NULL
        )
    ''')

    # جدول خاص بالتوكن لإعادة تعيين كلمة المرور
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at TEXT NOT NULL
        )
    ''')

    conn.commit()
    conn.close()


def register_user(username, email, password):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    try:
        cursor.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, hashed)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def verify_user(username, password):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE username=?", (username,))
    result = cursor.fetchone()
    conn.close()

    if result and bcrypt.checkpw(password.encode('utf-8'), result[0]):
        return True
    return False




def create_reset_token(username):

    conn = sqlite3.connect(DB_FILE)
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

    conn = sqlite3.connect(DB_FILE)
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


def reset_password(token, new_password):

    username = verify_reset_token(token)
    if not username:
        return False

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

    cursor.execute("UPDATE users SET password_hash=? WHERE username=?", (hashed, username))
    cursor.execute("DELETE FROM password_resets WHERE token=?", (token,))
    conn.commit()
    conn.close()
    return True
