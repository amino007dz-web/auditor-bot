import hashlib
import logging
import os
import sqlite3
import threading
import time
from typing import Dict, Optional

_HAS_REDIS = False
_REDIS_CLIENT = None
try:
    import redis as _redis_module
    _REDIS_CLIENT = _redis_module.Redis.from_url(
        os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
        socket_connect_timeout=2, socket_timeout=2, decode_responses=True,
    )
    _REDIS_CLIENT.ping()
    _HAS_REDIS = True
except Exception:
    _REDIS_CLIENT = None

from config import CACHE_ENABLED, CACHE_DB_PATH, FREE_MODELS, MAX_CODE_CHARS
from cli_display import console

logger = logging.getLogger(__name__)
_cache_lock = threading.Lock()


def _cache_cleanup(max_age_days: int = 30):
    if not CACHE_ENABLED:
        return
    try:
        cutoff = time.time() - max_age_days * 86400
        with _cache_lock:
            conn = sqlite3.connect(CACHE_DB_PATH, timeout=30)
            deleted = conn.execute("DELETE FROM responses WHERE created_at < ?", (cutoff,)).rowcount
            conn.commit()
            conn.close()
        if deleted:
            logger.info(f"Cache: deleted {deleted} entries older than {max_age_days} days")
    except Exception as e:
        logger.debug(f"Cache cleanup error: {e}")


def _init_cache():
    if not CACHE_ENABLED:
        return
    try:
        with _cache_lock:
            conn = sqlite3.connect(CACHE_DB_PATH, timeout=30)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""CREATE TABLE IF NOT EXISTS responses (
                model_id TEXT NOT NULL, prompt_hash TEXT NOT NULL,
                response TEXT NOT NULL, created_at REAL NOT NULL,
                hits INTEGER DEFAULT 1,
                PRIMARY KEY (model_id, prompt_hash))""")
            conn.execute("""CREATE TABLE IF NOT EXISTS stats (
                key TEXT PRIMARY KEY, value TEXT)""")
            conn.commit()
            conn.close()
        _cache_cleanup()
    except Exception as e:
        logger.warning(f"Cache init failed: {e}")


def _cache_get(model_id: str, prompt: str) -> Optional[str]:
    if not CACHE_ENABLED:
        return None
    h = hashlib.sha256(prompt.encode()).hexdigest()
    try:
        if _HAS_REDIS:
            val = _REDIS_CLIENT.get(f"cache:{model_id}:{h}")
            if val is not None:
                console.log(f"[dim]Redis Cache: {model_id} — hit[/]")
                return val
    except Exception:
        pass
    try:
        with _cache_lock:
            conn = sqlite3.connect(CACHE_DB_PATH, timeout=30)
            row = conn.execute(
                "SELECT response FROM responses WHERE model_id=? AND prompt_hash=?",
                (model_id, h)
            ).fetchone()
            if row:
                conn.execute("UPDATE responses SET hits=hits+1 WHERE model_id=? AND prompt_hash=?", (model_id, h))
                conn.commit()
                conn.close()
                console.log(f"[dim]Cache: {model_id} — from cache[/]")
                return row[0]
            conn.close()
    except Exception as e:
        logger.debug(f"Cache get error: {e}")
    return None


def _cache_set(model_id: str, prompt: str, response: str):
    if not CACHE_ENABLED:
        return
    h = hashlib.sha256(prompt.encode()).hexdigest()
    try:
        if _HAS_REDIS:
            _REDIS_CLIENT.setex(f"cache:{model_id}:{h}", 86400, response)
    except Exception:
        pass
    try:
        with _cache_lock:
            conn = sqlite3.connect(CACHE_DB_PATH, timeout=30)
            conn.execute(
                "INSERT OR REPLACE INTO responses (model_id, prompt_hash, response, created_at) VALUES (?, ?, ?, ?)",
                (model_id, h, response, time.time())
            )
            conn.commit()
            conn.close()
    except Exception as e:
        logger.debug(f"Cache set error: {e}")


def cache_stats() -> Dict:
    if not CACHE_ENABLED:
        return {"enabled": False}
    try:
        conn = sqlite3.connect(CACHE_DB_PATH, timeout=5)
        total = conn.execute("SELECT COUNT(*) FROM responses").fetchone()[0]
        total_hits = conn.execute("SELECT COALESCE(SUM(hits), 0) FROM responses").fetchone()[0]
        conn.close()
        return {"enabled": True, "entries": total, "total_hits": total_hits}
    except:
        return {"enabled": True, "entries": 0, "total_hits": 0}


_init_cache()
