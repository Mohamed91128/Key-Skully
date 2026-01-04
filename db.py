import sqlite3
import os
from config import Config

def get_db():
    os.makedirs(os.path.dirname(Config.DATABASE_PATH), exist_ok=True)
    return sqlite3.connect(Config.DATABASE_PATH, check_same_thread=False)

def init_db():
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE,
            fingerprint TEXT UNIQUE,
            ip TEXT,
            created_at TEXT,
            expires_at TEXT,
            next_gen_at TEXT
        )
    """)
    db.commit()
    db.close()

def fetch_key(key):
    db = get_db()
    cur = db.execute("""
        SELECT key, fingerprint, ip, created_at, expires_at, next_gen_at
        FROM keys
        WHERE key = ?
    """, (key,))
    row = cur.fetchone()
    db.close()
    return row

def fetch_valid_key_by_fingerprint(fingerprint, now_iso):
    db = get_db()
    cur = db.execute("""
        SELECT key, expires_at
        FROM keys
        WHERE fingerprint = ?
          AND expires_at > ?
        ORDER BY created_at DESC
        LIMIT 1
    """, (fingerprint, now_iso))
    row = cur.fetchone()
    db.close()
    return row

def fetch_row_by_fingerprint(fingerprint):
    db = get_db()
    cur = db.execute("""
        SELECT key, fingerprint, ip, created_at, expires_at, next_gen_at
        FROM keys
        WHERE fingerprint = ?
        ORDER BY created_at DESC
        LIMIT 1
    """, (fingerprint,))
    row = cur.fetchone()
    db.close()
    return row

def fetch_cooldown(fingerprint, now_iso):
    db = get_db()
    cur = db.execute("""
        SELECT next_gen_at
        FROM keys
        WHERE fingerprint = ?
          AND next_gen_at > ?
        ORDER BY next_gen_at DESC
        LIMIT 1
    """, (fingerprint, now_iso))
    row = cur.fetchone()
    db.close()
    return row

def insert_key(data_dict):
    db = get_db()
    db.execute("""
        INSERT INTO keys (
            key, fingerprint, ip,
            created_at, expires_at, next_gen_at
        ) VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(fingerprint) DO UPDATE SET
            key = excluded.key,
            ip = excluded.ip,
            created_at = excluded.created_at,
            expires_at = excluded.expires_at,
            next_gen_at = excluded.next_gen_at
    """, (
        data_dict["key"],
        data_dict["fingerprint"],
        data_dict["ip"],
        data_dict["created_at"],
        data_dict["expires_at"],
        data_dict["next_gen_at"],
    ))
    db.commit()
    db.close()
