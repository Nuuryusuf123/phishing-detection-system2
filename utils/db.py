from pathlib import Path
import sqlite3, hashlib
from datetime import datetime

DB = Path("data/app.db")

def _hash(x):
    return hashlib.sha256(x.encode()).hexdigest()

def init_db():
    DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, role TEXT)")
    cur.execute("CREATE TABLE IF NOT EXISTS history (id INTEGER PRIMARY KEY, timestamp TEXT, input_type TEXT, input_text TEXT, prediction TEXT, confidence REAL)")
    for u, p, r in [("admin","admin123","admin"),("student","student123","user")]:
        cur.execute("SELECT username FROM users WHERE username=?", (u,))
        if cur.fetchone() is None:
            cur.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", (u, _hash(p), r))
    conn.commit()
    conn.close()

def authenticate(username, password):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT role FROM users WHERE username=? AND password_hash=?", (username, _hash(password)))
    row = cur.fetchone()
    conn.close()
    if row:
        return True, row[0]
    return False, None

def save_history(input_type, input_text, prediction, confidence):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("INSERT INTO history (timestamp, input_type, input_text, prediction, confidence) VALUES (?, ?, ?, ?, ?)",
                (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), input_type, input_text, prediction, float(confidence)))
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
