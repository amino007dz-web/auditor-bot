"""Access code authentication + audit history + quota system with SQLite backend."""

import sqlite3
import logging
import os
import random
import string
import threading
import time
from functools import wraps
from flask import session, redirect, request, jsonify

logger = logging.getLogger(__name__)

AUTH_DB_PATH = os.environ.get("AUTH_DB_PATH", os.path.join(os.path.dirname(__file__), "auth.db"))
_local = threading.local()

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")
DEFAULT_QUOTA = int(os.environ.get("DEFAULT_QUOTA", "50"))

def _get_conn():
    if not hasattr(_local, 'conn') or _local.conn is None:
        _local.conn = sqlite3.connect(AUTH_DB_PATH, timeout=10)
        _local.conn.row_factory = sqlite3.Row
    return _local.conn

def init_auth_db():
    conn = _get_conn()
    conn.execute("""CREATE TABLE IF NOT EXISTS access_codes (
        code TEXT PRIMARY KEY,
        created_by TEXT DEFAULT '',
        max_uses INTEGER DEFAULT -1,
        used_count INTEGER DEFAULT 0,
        is_active INTEGER DEFAULT 1,
        created_at REAL DEFAULT (strftime('%s','now'))
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS auth_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT,
        ip TEXT,
        success INTEGER,
        timestamp REAL DEFAULT (strftime('%s','now'))
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS audit_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT NOT NULL,
        title TEXT DEFAULT '',
        snippet TEXT DEFAULT '',
        full_report TEXT DEFAULT '',
        severity_counts TEXT DEFAULT '',
        created_at REAL DEFAULT (strftime('%s','now'))
    )""")
    conn.commit()

def generate_code(prefix="SCA"):
    code = prefix + "-" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=4)) \
           + "-" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
    return code

def create_access_code(created_by="", max_uses=-1):
    code = generate_code()
    conn = _get_conn()
    conn.execute(
        "INSERT OR IGNORE INTO access_codes (code, created_by, max_uses) VALUES (?, ?, ?)",
        (code, created_by, max_uses)
    )
    conn.commit()
    return code

def verify_code(code):
    conn = _get_conn()
    row = conn.execute(
        "SELECT * FROM access_codes WHERE code = ? AND is_active = 1",
        (code.strip().upper(),)
    ).fetchone()
    if row is None:
        return False
    if row["max_uses"] != -1 and row["used_count"] >= row["max_uses"]:
        return False
    conn.execute("UPDATE access_codes SET used_count = used_count + 1 WHERE code = ?", (code.strip().upper(),))
    conn.execute(
        "INSERT INTO auth_log (code, ip, success) VALUES (?, ?, 1)",
        (code.strip().upper(), request.remote_addr if request else "")
    )
    conn.commit()
    return True

def check_quota(code):
    conn = _get_conn()
    row = conn.execute(
        "SELECT max_uses, used_count FROM access_codes WHERE code = ?",
        (code,)
    ).fetchone()
    if row is None:
        return {"allowed": 0, "remaining": 0, "total": 0}
    total = row["max_uses"] if row["max_uses"] != -1 else DEFAULT_QUOTA
    used = row["used_count"]
    remaining = max(0, total - used)
    return {"allowed": total, "remaining": remaining, "used": used}

def list_codes():
    conn = _get_conn()
    rows = conn.execute(
        "SELECT code, created_by, max_uses, used_count, is_active, created_at FROM access_codes ORDER BY created_at DESC"
    ).fetchall()
    return [dict(r) for r in rows]

def deactivate_code(code):
    conn = _get_conn()
    conn.execute("UPDATE access_codes SET is_active = 0 WHERE code = ?", (code.strip().upper(),))
    conn.commit()


# --- Audit History ---

def save_history(code, title, snippet, full_report, severity_counts=""):
    conn = _get_conn()
    conn.execute(
        "INSERT INTO audit_history (code, title, snippet, full_report, severity_counts) VALUES (?, ?, ?, ?, ?)",
        (code, title[:200], snippet[:500], full_report, severity_counts)
    )
    conn.commit()

def get_history(code, limit=20):
    conn = _get_conn()
    rows = conn.execute(
        "SELECT id, title, snippet, severity_counts, created_at FROM audit_history WHERE code = ? ORDER BY created_at DESC LIMIT ?",
        (code, limit)
    ).fetchall()
    return [dict(r) for r in rows]

def get_history_item(history_id, code):
    conn = _get_conn()
    row = conn.execute(
        "SELECT * FROM audit_history WHERE id = ? AND code = ?",
        (history_id, code)
    ).fetchone()
    return dict(row) if row else None


# --- Decorators ---

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'authenticated' not in session:
            if request.path.startswith('/api/'):
                return jsonify({"error": "Unauthorized"}), 401
            return redirect('/')
        return f(*args, **kwargs)
    return decorated

def requires_admin(f):
    @wraps(f)
    @wraps
    def decorated(*args, **kwargs):
        if 'admin_authenticated' not in session:
            return redirect('/admin/login')
        return f(*args, **kwargs)
    return decorated

init_auth_db()
