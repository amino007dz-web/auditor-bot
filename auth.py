"""Access code authentication + audit history + quota system with SQLite backend."""

import sqlite3
import logging
import os
import secrets
import string
import threading
import time
from functools import wraps
from flask import session, redirect, request, jsonify
from flask_login import UserMixin

logger = logging.getLogger(__name__)

AUTH_DB_PATH = os.environ.get("AUTH_DB_PATH", os.path.join(os.path.dirname(__file__), "instance", "auth.db"))
os.makedirs(os.path.dirname(AUTH_DB_PATH), exist_ok=True)
_local = threading.local()

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
DEFAULT_QUOTA = int(os.environ.get("DEFAULT_QUOTA", "50"))

MONTHLY_FREE_CREDITS = int(os.environ.get("MONTHLY_FREE_CREDITS", "5"))

class User(UserMixin):
    def __init__(self, row):
        self.id = row["id"]
        self.github_id = row["github_id"]
        self.github_username = row["github_username"]
        self.email = row["email"]
        self.avatar_url = row["avatar_url"]
        self.plan = row["plan"]
        self.credits = row["credits"]
        self.credit_reset_at = row["credit_reset_at"]
        self.created_at = row["created_at"]

    def get_id(self):
        return str(self.id)

    def is_pro(self):
        return self.plan == "pro"

def get_user_by_id(user_id):
    conn = _get_conn()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return User(row) if row else None

def find_user_by_github_id(github_id):
    conn = _get_conn()
    row = conn.execute("SELECT * FROM users WHERE github_id = ?", (str(github_id),)).fetchone()
    return User(row) if row else None

def find_user_by_api_key(api_key):
    conn = _get_conn()
    row = conn.execute("""SELECT u.* FROM users u
        JOIN api_keys k ON k.user_id = u.id
        WHERE k.key = ? AND k.is_active = 1""", (api_key,)).fetchone()
    return User(row) if row else None

def create_user(github_id, github_username, email, avatar_url):
    conn = _get_conn()
    now = int(time.time())
    # Reset credits on the 1st of next month
    import calendar
    from datetime import datetime
    now_dt = datetime.utcnow()
    next_month = now_dt.month % 12 + 1
    next_year = now_dt.year + (1 if next_month == 1 else 0)
    reset_at = int(datetime(next_year, next_month, 1, 0, 0, 0).timestamp())
    conn.execute("""INSERT OR IGNORE INTO users
        (github_id, github_username, email, avatar_url, plan, credits, credit_reset_at, created_at)
        VALUES (?, ?, ?, ?, 'free', ?, ?, ?)""",
        (str(github_id), github_username, email or "", avatar_url or "",
         MONTHLY_FREE_CREDITS, reset_at, now))
    conn.commit()
    row = conn.execute("SELECT * FROM users WHERE github_id = ?", (str(github_id),)).fetchone()
    return User(row) if row else None

def reset_credits_if_needed(user):
    if user.plan == "pro":
        return
    now = int(time.time())
    if now >= user.credit_reset_at:
        import calendar
        from datetime import datetime
        now_dt = datetime.utcnow()
        next_month = now_dt.month % 12 + 1
        next_year = now_dt.year + (1 if next_month == 1 else 0)
        reset_at = int(datetime(next_year, next_month, 1, 0, 0, 0).timestamp())
        conn = _get_conn()
        conn.execute("UPDATE users SET credits = ?, credit_reset_at = ? WHERE id = ?",
                     (MONTHLY_FREE_CREDITS, reset_at, user.id))
        conn.commit()
        user.credits = MONTHLY_FREE_CREDITS
        user.credit_reset_at = reset_at

def deduct_credit(user):
    if user.plan == "pro":
        return True
    reset_credits_if_needed(user)
    if user.credits <= 0:
        return False
    conn = _get_conn()
    conn.execute("UPDATE users SET credits = credits - 1 WHERE id = ?", (user.id,))
    conn.commit()
    user.credits -= 1
    return True

def create_api_key(user_id, name=""):
    conn = _get_conn()
    key = "sca_" + secrets.token_urlsafe(32)
    conn.execute("INSERT INTO api_keys (user_id, key, name) VALUES (?, ?, ?)",
                 (user_id, key, name or "Default"))
    conn.commit()
    row = conn.execute("SELECT * FROM api_keys WHERE key = ?", (key,)).fetchone()
    return dict(row) if row else None

def list_api_keys(user_id):
    conn = _get_conn()
    rows = conn.execute("""SELECT id, name, key, created_at, last_used_at, is_active
        FROM api_keys WHERE user_id = ? ORDER BY created_at DESC""", (user_id,)).fetchall()
    return [dict(r) for r in rows]

def revoke_api_key(key_id, user_id):
    conn = _get_conn()
    conn.execute("UPDATE api_keys SET is_active = 0 WHERE id = ? AND user_id = ?",
                 (key_id, user_id))
    conn.commit()

def _get_conn():
    if not hasattr(_local, 'conn') or _local.conn is None:
        _local.conn = sqlite3.connect(AUTH_DB_PATH, timeout=10)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
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
        code TEXT DEFAULT '',
        user_id INTEGER DEFAULT NULL,
        title TEXT DEFAULT '',
        snippet TEXT DEFAULT '',
        full_report TEXT DEFAULT '',
        severity_counts TEXT DEFAULT '',
        created_at REAL DEFAULT (strftime('%s','now')),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        github_id TEXT UNIQUE NOT NULL,
        github_username TEXT DEFAULT '',
        email TEXT DEFAULT '',
        avatar_url TEXT DEFAULT '',
        plan TEXT DEFAULT 'free',
        credits INTEGER DEFAULT 5,
        credit_reset_at REAL DEFAULT 0,
        created_at REAL DEFAULT (strftime('%s','now'))
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        key TEXT UNIQUE NOT NULL,
        name TEXT DEFAULT '',
        created_at REAL DEFAULT (strftime('%s','now')),
        last_used_at REAL DEFAULT 0,
        is_active INTEGER DEFAULT 1,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )""")
    conn.commit()

def generate_code(prefix="SCA"):
    alphabet = string.ascii_uppercase + string.digits
    part1 = ''.join(secrets.choice(alphabet) for _ in range(4))
    part2 = ''.join(secrets.choice(alphabet) for _ in range(4))
    return f"{prefix}-{part1}-{part2}"

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

def save_history(code, title, snippet, full_report, severity_counts="", user_id=None):
    conn = _get_conn()
    conn.execute(
        "INSERT INTO audit_history (code, user_id, title, snippet, full_report, severity_counts) VALUES (?, ?, ?, ?, ?, ?)",
        (code or "", user_id, title[:200], snippet[:500], full_report, severity_counts)
    )
    conn.commit()

def get_history(code=None, user_id=None, limit=20):
    conn = _get_conn()
    if user_id:
        rows = conn.execute(
            "SELECT id, title, snippet, severity_counts, created_at FROM audit_history WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
            (user_id, limit)
        ).fetchall()
    elif code:
        rows = conn.execute(
            "SELECT id, title, snippet, severity_counts, created_at FROM audit_history WHERE code = ? ORDER BY created_at DESC LIMIT ?",
            (code, limit)
        ).fetchall()
    else:
        return []
    return [dict(r) for r in rows]

def get_history_item(history_id, code=None, user_id=None):
    conn = _get_conn()
    if user_id:
        row = conn.execute(
            "SELECT * FROM audit_history WHERE id = ? AND user_id = ?",
            (history_id, user_id)
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT * FROM audit_history WHERE id = ? AND code = ?",
            (history_id, code)
        ).fetchone()
    return dict(row) if row else None

def get_user_history_count(user_id):
    conn = _get_conn()
    row = conn.execute(
        "SELECT COUNT(*) as cnt FROM audit_history WHERE user_id = ?", (user_id,)
    ).fetchone()
    return row["cnt"] if row else 0


# --- Decorators ---

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        from flask_login import current_user
        if current_user.is_authenticated:
            return f(*args, **kwargs)
        if 'authenticated' in session:
            return f(*args, **kwargs)
        if request.path.startswith('/api/'):
            return jsonify({"error": "Unauthorized"}), 401
        return redirect('/')
    return decorated

def requires_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'admin_authenticated' not in session:
            return redirect('/admin/login')
        return f(*args, **kwargs)
    return decorated

init_auth_db()
