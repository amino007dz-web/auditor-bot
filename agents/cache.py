import hashlib
import logging
import os
import sqlite3
import threading
import time
from typing import Dict, Optional

_has_redis = False
_redis_client = None
_redis_module = None
try:
    import redis as _redis_module
except ImportError:
    pass


def _get_redis():
    global _redis_client, _has_redis
    if _redis_client is not None or _has_redis:
        return _redis_client
    if _redis_module is None:
        return None
    try:
        _redis_client = _redis_module.Redis.from_url(
            os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
            socket_connect_timeout=2, socket_timeout=2, decode_responses=True,
        )
        _has_redis = True
    except Exception:
        _redis_client = None
    return _redis_client

from config import CACHE_ENABLED, CACHE_DB_PATH, FREE_MODELS, MAX_CODE_CHARS
from cli_display import console

logger = logging.getLogger(__name__)
_cache_local = threading.local()


def _get_conn() -> sqlite3.Connection:
    """Get a thread-local SQLite connection (connection pooling via TLS)."""
    if not hasattr(_cache_local, 'conn') or _cache_local.conn is None:
        _cache_local.conn = sqlite3.connect(CACHE_DB_PATH, timeout=30)
        _cache_local.conn.execute("PRAGMA journal_mode=WAL")
    return _cache_local.conn


def _cache_cleanup(max_age_days: int = 30, batch_size: int = 1000):
    if not CACHE_ENABLED:
        return
    try:
        cutoff = time.time() - max_age_days * 86400
        conn = _get_conn()
        total_deleted = 0
        while True:
            deleted = conn.execute(
                "DELETE FROM responses WHERE rowid IN (SELECT rowid FROM responses WHERE created_at < ? LIMIT ?)",
                (cutoff, batch_size)
            ).rowcount
            conn.commit()
            total_deleted += deleted
            if deleted < batch_size:
                break
        if total_deleted:
            logger.info(f"Cache: deleted {total_deleted} entries older than {max_age_days} days")
    except Exception as e:
        logger.debug(f"Cache cleanup error: {e}")


def _init_cache():
    if not CACHE_ENABLED:
        return
    try:
        conn = _get_conn()
        conn.execute("""CREATE TABLE IF NOT EXISTS responses (
            model_id TEXT NOT NULL, prompt_hash TEXT NOT NULL,
            response TEXT NOT NULL, created_at REAL NOT NULL,
            hits INTEGER DEFAULT 1,
            PRIMARY KEY (model_id, prompt_hash))""")
        conn.execute("""CREATE TABLE IF NOT EXISTS stats (
            key TEXT PRIMARY KEY, value TEXT)""")
        conn.commit()
        _cache_cleanup()
    except Exception as e:
        logger.warning(f"Cache init failed: {e}")


def _cache_get(model_id: str, prompt: str) -> Optional[str]:
    if not CACHE_ENABLED:
        return None
    h = hashlib.sha256(prompt.encode()).hexdigest()
    try:
        rc = _get_redis()
        if rc:
            val = rc.get(f"cache:{model_id}:{h}")
            if val is not None:
                console.log(f"[dim]Redis Cache: {model_id} — hit[/]")
                return val
    except Exception:
        pass
    try:
        conn = _get_conn()
        row = conn.execute(
            "SELECT response FROM responses WHERE model_id=? AND prompt_hash=?",
            (model_id, h)
        ).fetchone()
        if row:
            conn.execute("UPDATE responses SET hits=hits+1 WHERE model_id=? AND prompt_hash=?", (model_id, h))
            conn.commit()
            console.log(f"[dim]Cache: {model_id} — from cache[/]")
            return row[0]
    except Exception as e:
        logger.debug(f"Cache get error: {e}")
    return None


def _cache_set(model_id: str, prompt: str, response: str):
    if not CACHE_ENABLED:
        return
    h = hashlib.sha256(prompt.encode()).hexdigest()
    try:
        rc = _get_redis()
        if rc:
            rc.setex(f"cache:{model_id}:{h}", 86400, response)
    except Exception:
        pass
    try:
        conn = _get_conn()
        conn.execute(
            "INSERT OR REPLACE INTO responses (model_id, prompt_hash, response, created_at) VALUES (?, ?, ?, ?)",
            (model_id, h, response, time.time())
        )
        conn.commit()
    except Exception as e:
        logger.debug(f"Cache set error: {e}")


def cache_stats() -> Dict:
    if not CACHE_ENABLED:
        return {"enabled": False}
    try:
        conn = _get_conn()
        total = conn.execute("SELECT COUNT(*) FROM responses").fetchone()[0]
        total_hits = conn.execute("SELECT COALESCE(SUM(hits), 0) FROM responses").fetchone()[0]
        return {"enabled": True, "entries": total, "total_hits": total_hits}
    except:
        return {"enabled": True, "entries": 0, "total_hits": 0}


_init_cache()
