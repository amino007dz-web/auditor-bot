"""
Knowledge Base — SQLite database that learns from every audit.
Stores vulnerability patterns, false positives, model performance, and user feedback.
"""
import hashlib
import json
import logging
import os
import sqlite3
import threading
import time
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_lock = threading.Lock()

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS vulnerability_patterns (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    severity    TEXT NOT NULL,
    pattern_type TEXT DEFAULT '',
    code_snippet TEXT DEFAULT '',
    description TEXT DEFAULT '',
    fix_code    TEXT DEFAULT '',
    contract_type TEXT DEFAULT '',
    source_report TEXT DEFAULT '',
    protocol_name TEXT DEFAULT '',
    created_at  REAL NOT NULL,
    hit_count   INTEGER DEFAULT 1,
    confirmed_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS false_positives (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_type TEXT DEFAULT '',
    code_snippet TEXT DEFAULT '',
    reason      TEXT DEFAULT '',
    original_severity TEXT DEFAULT '',
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS model_performance (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    model_name  TEXT NOT NULL,
    vulnerability_type TEXT NOT NULL,
    tp_count    INTEGER DEFAULT 0,
    fp_count    INTEGER DEFAULT 0,
    fn_count    INTEGER DEFAULT 0,
    avg_accuracy REAL DEFAULT 0.0,
    last_updated REAL NOT NULL,
    UNIQUE(model_name, vulnerability_type)
);

CREATE TABLE IF NOT EXISTS audit_sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    protocol_name TEXT DEFAULT '',
    contract_type TEXT DEFAULT '',
    code_hash   TEXT DEFAULT '',
    code_preview TEXT DEFAULT '',
    report_hash TEXT DEFAULT '',
    num_findings INTEGER DEFAULT 0,
    models_used TEXT DEFAULT '',
    user_rating INTEGER DEFAULT 0,
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS feedback (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER DEFAULT 0,
    finding_name TEXT DEFAULT '',
    user_severity TEXT DEFAULT '',
    is_fp       INTEGER DEFAULT 0,
    comment     TEXT DEFAULT '',
    created_at  REAL NOT NULL,
    FOREIGN KEY (session_id) REFERENCES audit_sessions(id)
);

CREATE INDEX IF NOT EXISTS idx_patterns_severity ON vulnerability_patterns(severity);
CREATE INDEX IF NOT EXISTS idx_patterns_type ON vulnerability_patterns(pattern_type);
CREATE INDEX IF NOT EXISTS idx_patterns_contract ON vulnerability_patterns(contract_type);
CREATE INDEX IF NOT EXISTS idx_fp_type ON false_positives(pattern_type);
CREATE INDEX IF NOT EXISTS idx_model_perf ON model_performance(model_name, vulnerability_type);
"""


class KnowledgeBase:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        try:
            with _lock:
                conn = sqlite3.connect(self.db_path, timeout=30)
                conn.execute("PRAGMA journal_mode=WAL")
                conn.executescript(SCHEMA_SQL)
                conn.commit()
                conn.close()
            logger.info(f"Knowledge Base initialised: {self.db_path}")
        except Exception as e:
            logger.warning(f"KB init failed: {e}")

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    # ─── Vulnerability Patterns ───

    def add_pattern(self, name: str, severity: str, pattern_type: str = "",
                    code_snippet: str = "", description: str = "", fix_code: str = "",
                    contract_type: str = "", source_report: str = "",
                    protocol_name: str = "") -> int:
        try:
            with _lock:
                conn = self._connect()
                c = conn.execute(
                    """INSERT INTO vulnerability_patterns
                    (name, severity, pattern_type, code_snippet, description, fix_code,
                     contract_type, source_report, protocol_name, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (name, severity, pattern_type, code_snippet, description, fix_code,
                     contract_type, source_report, protocol_name, time.time())
                )
                conn.commit()
                rid = c.lastrowid
                conn.close()
                logger.info(f"KB: new pattern '{name}' [{severity}]")
                return rid
        except Exception as e:
            logger.debug(f"KB add_pattern error: {e}")
            return 0

    def find_similar_patterns(self, code_snippet: str, contract_type: str = "",
                              limit: int = 5) -> List[Dict]:
        """Find patterns similar to the given code/contract type."""
        results = []
        try:
            with _lock:
                conn = self._connect()
                sql = "SELECT * FROM vulnerability_patterns WHERE 1=1"
                params = []
                if contract_type:
                    sql += " AND contract_type = ?"
                    params.append(contract_type)
                sql += " ORDER BY (confirmed_count + hit_count) DESC, created_at DESC LIMIT ?"
                params.append(limit)
                rows = conn.execute(sql, params).fetchall()
                conn.close()
                cols = ["id", "name", "severity", "pattern_type", "code_snippet",
                        "description", "fix_code", "contract_type", "source_report",
                        "protocol_name", "created_at", "hit_count", "confirmed_count"]
                for r in rows:
                    results.append(dict(zip(cols, r)))
        except Exception as e:
            logger.debug(f"KB find_similar error: {e}")
        return results

    def get_patterns_by_severity(self, severity: str = "", limit: int = 50) -> List[Dict]:
        try:
            with _lock:
                conn = self._connect()
                if severity:
                    rows = conn.execute(
                        "SELECT * FROM vulnerability_patterns WHERE severity=? ORDER BY created_at DESC LIMIT ?",
                        (severity, limit)
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM vulnerability_patterns ORDER BY (confirmed_count + hit_count) DESC LIMIT ?",
                        (limit,)
                    ).fetchall()
                conn.close()
                cols = ["id", "name", "severity", "pattern_type", "code_snippet",
                        "description", "fix_code", "contract_type", "source_report",
                        "protocol_name", "created_at", "hit_count", "confirmed_count"]
                return [dict(zip(cols, r)) for r in rows]
        except Exception as e:
            logger.debug(f"KB get_patterns error: {e}")
            return []

    def increment_hit(self, pattern_id: int):
        try:
            with _lock:
                conn = self._connect()
                conn.execute("UPDATE vulnerability_patterns SET hit_count = hit_count + 1 WHERE id = ?", (pattern_id,))
                conn.commit()
                conn.close()
        except:
            pass

    def confirm_pattern(self, pattern_id: int):
        try:
            with _lock:
                conn = self._connect()
                conn.execute("UPDATE vulnerability_patterns SET confirmed_count = confirmed_count + 1 WHERE id = ?",
                             (pattern_id,))
                conn.commit()
                conn.close()
        except:
            pass

    # ─── False Positives ───

    def add_false_positive(self, pattern_type: str = "", code_snippet: str = "",
                           reason: str = "", original_severity: str = ""):
        try:
            with _lock:
                conn = self._connect()
                conn.execute(
                    """INSERT INTO false_positives
                    (pattern_type, code_snippet, reason, original_severity, created_at)
                    VALUES (?,?,?,?,?)""",
                    (pattern_type, code_snippet, reason, original_severity, time.time())
                )
                conn.commit()
                conn.close()
                logger.info(f"KB: false positive recorded: {pattern_type}")
        except Exception as e:
            logger.debug(f"KB add_fp error: {e}")

    def is_known_false_positive(self, code_snippet: str) -> bool:
        try:
            with _lock:
                conn = self._connect()
                row = conn.execute(
                    "SELECT COUNT(*) FROM false_positives WHERE code_snippet LIKE ?",
                    (f"%{code_snippet[:50]}%",)
                ).fetchone()
                conn.close()
                return row[0] > 0
        except:
            return False

    # ─── Model Performance ───

    def record_model_result(self, model_name: str, vuln_type: str, correct: bool):
        try:
            with _lock:
                conn = self._connect()
                existing = conn.execute(
                    "SELECT tp_count, fp_count FROM model_performance WHERE model_name=? AND vulnerability_type=?",
                    (model_name, vuln_type)
                ).fetchone()
                if existing:
                    tp, fp = existing
                    if correct:
                        tp += 1
                    else:
                        fp += 1
                    total = tp + fp or 1
                    conn.execute(
                        """UPDATE model_performance
                        SET tp_count=?, fp_count=?, avg_accuracy=?, last_updated=?
                        WHERE model_name=? AND vulnerability_type=?""",
                        (tp, fp, tp / total, time.time(), model_name, vuln_type)
                    )
                else:
                    tp = 1 if correct else 0
                    fp = 0 if correct else 1
                    total = tp + fp or 1
                    conn.execute(
                        """INSERT INTO model_performance
                        (model_name, vulnerability_type, tp_count, fp_count, avg_accuracy, last_updated)
                        VALUES (?,?,?,?,?,?)""",
                        (model_name, vuln_type, tp, fp, tp / total, time.time())
                    )
                conn.commit()
                conn.close()
        except Exception as e:
            logger.debug(f"KB record_model error: {e}")

    def get_best_model_for(self, vulnerability_type: str) -> Optional[str]:
        try:
            with _lock:
                conn = self._connect()
                row = conn.execute(
                    """SELECT model_name FROM model_performance
                    WHERE vulnerability_type=? AND avg_accuracy > 0.6
                    ORDER BY avg_accuracy DESC, tp_count DESC LIMIT 1""",
                    (vulnerability_type,)
                ).fetchone()
                conn.close()
                return row[0] if row else None
        except:
            return None

    # ─── Audit Sessions & Feedback ───

    def start_session(self, protocol_name: str, code: str, models_used: str = "") -> int:
        h = hashlib.sha256(code.encode()).hexdigest()[:16]
        preview = code[:200]
        try:
            with _lock:
                conn = self._connect()
                c = conn.execute(
                    """INSERT INTO audit_sessions
                    (protocol_name, code_hash, code_preview, models_used, num_findings, created_at)
                    VALUES (?,?,?,?,0,?)""",
                    (protocol_name, h, preview, models_used, time.time())
                )
                conn.commit()
                sid = c.lastrowid
                conn.close()
                return sid
        except Exception as e:
            logger.debug(f"KB start_session error: {e}")
            return 0

    def update_session(self, session_id: int, **kwargs):
        allowed = {"num_findings", "user_rating", "report_hash", "models_used", "contract_type"}
        sets = []
        params = []
        for k, v in kwargs.items():
            if k in allowed:
                sets.append(f"{k}=?")
                params.append(v)
        if not sets:
            return
        params.append(session_id)
        try:
            with _lock:
                conn = self._connect()
                conn.execute(f"UPDATE audit_sessions SET {', '.join(sets)} WHERE id=?", params)
                conn.commit()
                conn.close()
        except Exception as e:
            logger.debug(f"KB update_session error: {e}")

    def add_feedback(self, session_id: int, finding_name: str, user_severity: str = "",
                     is_fp: bool = False, comment: str = ""):
        try:
            with _lock:
                conn = self._connect()
                conn.execute(
                    """INSERT INTO feedback
                    (session_id, finding_name, user_severity, is_fp, comment, created_at)
                    VALUES (?,?,?,?,?,?)""",
                    (session_id, finding_name, user_severity, 1 if is_fp else 0, comment, time.time())
                )
                conn.commit()
                conn.close()
        except Exception as e:
            logger.debug(f"KB add_feedback error: {e}")

    def get_feedback_summary(self, limit: int = 20) -> List[Dict]:
        try:
            with _lock:
                conn = self._connect()
                rows = conn.execute(
                    "SELECT * FROM feedback ORDER BY created_at DESC LIMIT ?", (limit,)
                ).fetchall()
                conn.close()
                cols = ["id", "session_id", "finding_name", "user_severity", "is_fp", "comment", "created_at"]
                return [dict(zip(cols, r)) for r in rows]
        except:
            return []

    def get_model_rankings(self) -> List[Dict]:
        try:
            with _lock:
                conn = self._connect()
                rows = conn.execute(
                    """SELECT model_name, AVG(avg_accuracy) as avg_acc,
                    SUM(tp_count) as total_tp, SUM(fp_count) as total_fp
                    FROM model_performance GROUP BY model_name
                    ORDER BY avg_acc DESC"""
                ).fetchall()
                conn.close()
                cols = ["model_name", "avg_accuracy", "total_tp", "total_fp"]
                return [dict(zip(cols, r)) for r in rows]
        except:
            return []

    def get_stats(self) -> Dict:
        try:
            with _lock:
                conn = self._connect()
                patterns = conn.execute("SELECT COUNT(*) FROM vulnerability_patterns").fetchone()[0]
                fps = conn.execute("SELECT COUNT(*) FROM false_positives").fetchone()[0]
                sessions = conn.execute("SELECT COUNT(*) FROM audit_sessions").fetchone()[0]
                feedbacks = conn.execute("SELECT COUNT(*) FROM feedback").fetchone()[0]
                models = conn.execute("SELECT COUNT(DISTINCT model_name) FROM model_performance").fetchone()[0]
                top = conn.execute(
                    """SELECT name, (confirmed_count + hit_count) as score
                    FROM vulnerability_patterns ORDER BY score DESC LIMIT 5"""
                ).fetchall()
                conn.close()
                return {
                    "patterns": patterns,
                    "false_positives": fps,
                    "sessions": sessions,
                    "feedback": feedbacks,
                    "models_tracked": models,
                    "top_patterns": [{"name": r[0], "score": r[1]} for r in top],
                }
        except Exception as e:
            return {"error": str(e)}

    def close(self):
        pass
