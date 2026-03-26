from pathlib import Path
import sqlite3
import bcrypt
import re
import random
from datetime import datetime

DB = Path("data/app.db")


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed_password.encode())


def is_strong_password(password: str):
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character."
    return True, "Strong password"


def init_db():
    DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT,
            password_hash TEXT,
            role TEXT,
            is_verified INTEGER DEFAULT 0,
            otp_code TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            input_type TEXT,
            input_text TEXT,
            prediction TEXT,
            confidence REAL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            username TEXT,
            action TEXT,
            details TEXT
        )
    """)

    cur.execute("PRAGMA table_info(users)")
    cols = [row[1] for row in cur.fetchall()]

    if "email" not in cols:
        cur.execute("ALTER TABLE users ADD COLUMN email TEXT")
    if "is_verified" not in cols:
        cur.execute("ALTER TABLE users ADD COLUMN is_verified INTEGER DEFAULT 0")
    if "otp_code" not in cols:
        cur.execute("ALTER TABLE users ADD COLUMN otp_code TEXT")

    defaults = [
        ("admin", "admin123", "admin", "admin@example.com", 1),
        ("student", "student123", "user", "student@example.com", 1),
    ]

    for username, password, role, email, verified in defaults:
        cur.execute("SELECT username FROM users WHERE username=?", (username,))
        if cur.fetchone() is None:
            cur.execute(
                "INSERT INTO users (username, email, password_hash, role, is_verified, otp_code) VALUES (?, ?, ?, ?, ?, ?)",
                (username, email, hash_password(password), role, verified, None)
            )

    conn.commit()
    conn.close()


def authenticate(username, password):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT password_hash, role FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    conn.close()

    if row:
        stored_hash, role = row
        if verify_password(password, stored_hash):
            return True, role
    return False, None


def create_user(username, password, role="user", email=None):
    valid, msg = is_strong_password(password)
    if not valid:
        return False, msg

    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (username, email, password_hash, role, is_verified, otp_code) VALUES (?, ?, ?, ?, ?, ?)",
            (username, email, hash_password(password), role, 0, None)
        )
        conn.commit()
        return True, "Account created successfully."
    except sqlite3.IntegrityError:
        return False, "User already exists."
    except Exception as e:
        return False, f"Error creating account: {str(e)}"
    finally:
        conn.close()


def user_exists(username):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    conn.close()
    return row is not None


def verify_user_email(username):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("UPDATE users SET is_verified=1 WHERE username=?", (username,))
    conn.commit()
    conn.close()
    return True


def create_otp_for_user(username):
    otp_code = str(random.randint(100000, 999999))
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("UPDATE users SET otp_code=? WHERE username=?", (otp_code, username))
    conn.commit()
    conn.close()
    return otp_code


def verify_otp_code(username, otp_code):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT otp_code FROM users WHERE username=?", (username,))
    row = cur.fetchone()

    if not row:
        conn.close()
        return False, "User not found."

    saved_otp = row[0]
    if saved_otp and saved_otp == otp_code:
        cur.execute("UPDATE users SET is_verified=1, otp_code=NULL WHERE username=?", (username,))
        conn.commit()
        conn.close()
        return True, "OTP verified successfully."
    conn.close()
    return False, "Invalid OTP code."


def change_password(username, new_password):
    valid, msg = is_strong_password(new_password)
    if not valid:
        return False, msg

    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET password_hash=? WHERE username=?",
        (hash_password(new_password), username)
    )
    conn.commit()
    conn.close()
    return True, "Password updated successfully."


def save_history(input_type, input_text, prediction, confidence):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO history (timestamp, input_type, input_text, prediction, confidence) VALUES (?, ?, ?, ?, ?)",
        (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            input_type,
            input_text,
            prediction,
            float(confidence)
        )
    )
    conn.commit()
    conn.close()


def load_history(limit=None):
    import pandas as pd
    conn = sqlite3.connect(DB)
    q = "SELECT timestamp, input_type, input_text, prediction, confidence FROM history ORDER BY id DESC"
    if limit:
        q += f" LIMIT {int(limit)}"
    df = pd.read_sql_query(q, conn)
    conn.close()
    return df


def get_all_users():
    import pandas as pd
    conn = sqlite3.connect(DB)
    df = pd.read_sql_query(
        "SELECT id, username, email, role, is_verified FROM users ORDER BY id DESC",
        conn
    )
    conn.close()
    return df


def log_activity(username, action, details=""):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO activity_logs (timestamp, username, action, details) VALUES (?, ?, ?, ?)",
        (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            username,
            action,
            details
        )
    )
    conn.commit()
    conn.close()


def load_activity_logs(limit=None):
    import pandas as pd
    conn = sqlite3.connect(DB)
    q = "SELECT timestamp, username, action, details FROM activity_logs ORDER BY id DESC"
    if limit:
        q += f" LIMIT {int(limit)}"
    df = pd.read_sql_query(q, conn)
    conn.close()
    return df
