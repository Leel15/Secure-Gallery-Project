import os
import sqlite3
import bcrypt

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
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT,
            password_hash TEXT NOT NULL
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
