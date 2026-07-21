import html
import os
import sys
import time
import logging
import threading
import hmac
from functools import wraps
from flask import request, jsonify, session

from config import REPORT_DIR
from orchestrator import dispatch_analysis
from project_detector import analyze_project

logger = logging.getLogger(__name__)

_HAS_REDIS_RATE_LIMIT = False
_REDIS_RATE_CLIENT = None
try:
    import redis as _redis_module
    _url = os.environ.get("REDIS_URL", "")
    if _url:
        _REDIS_RATE_CLIENT = _redis_module.Redis.from_url(_url, socket_connect_timeout=1, socket_timeout=1, decode_responses=True)
        _HAS_REDIS_RATE_LIMIT = True
except Exception:
    _REDIS_RATE_CLIENT = None

_rate_limit_store = {}
_rate_limit_lock = threading.Lock()

def rate_limit(max_per_minute: int = 10):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            effective_max = int(os.environ.get("RATE_LIMIT_PER_MINUTE", max_per_minute))
            key = f"{request.remote_addr}:{request.path}"
            now = time.time()
            if _HAS_REDIS_RATE_LIMIT and _REDIS_RATE_CLIENT:
                try:
                    rkey = f"ratelimit:{key}"
                    count = _REDIS_RATE_CLIENT.get(rkey)
                    if count is None:
                        _REDIS_RATE_CLIENT.incr(rkey)
                        _REDIS_RATE_CLIENT.expire(rkey, 60)
                        count = 1
                    else:
                        count = int(count)
                        _REDIS_RATE_CLIENT.incr(rkey)
                        count += 1
                    if count > effective_max:
                        logger.warning(f"Rate limit hit: {key}")
                        return jsonify({"error": "Rate limit exceeded. Try again later."}), 429
                except Exception:
                    pass
            else:
                with _rate_limit_lock:
                    if len(_rate_limit_store) > 1000:
                        expired = [k for k, (t, _) in _rate_limit_store.items() if now - t > 120]
                        for k in expired:
                            del _rate_limit_store[k]
                    entry = _rate_limit_store.get(key)
                    if entry is None:
                        _rate_limit_store[key] = (now, 1)
                    else:
                        window_start, count = entry
                        if now - window_start > 60:
                            _rate_limit_store[key] = (now, 1)
                        elif count >= effective_max:
                            logger.warning(f"Rate limit hit: {key}")
                            return jsonify({"error": "Rate limit exceeded. Try again later."}), 429
                        else:
                            _rate_limit_store[key] = (window_start, count + 1)
            return f(*args, **kwargs)
        return wrapper
    return decorator

_EXPECTED_API_KEY = os.environ.get("AUDITOR_API_KEY", "")

def _check_user_api_key(provided_key):
    """Check if the provided API key belongs to an active user. Returns user or None."""
    try:
        from auth import find_user_by_api_key
        user = find_user_by_api_key(provided_key)
        if user:
            # Update last_used_at
            import sqlite3
            db_path = os.environ.get("AUTH_DB_PATH",
                os.path.join(os.path.dirname(__file__), "instance", "auth.db"))
            conn = sqlite3.connect(db_path)
            conn.execute("UPDATE api_keys SET last_used_at = (strftime('%s','now')) WHERE key = ?",
                        (provided_key,))
            conn.commit()
            conn.close()
            return user
    except Exception:
        pass
    return None

def require_api_key(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        from flask_login import current_user
        if current_user.is_authenticated:
            from auth import deduct_credit, reset_credits_if_needed
            reset_credits_if_needed(current_user)
            if not current_user.is_pro() and current_user.credits <= 0:
                return jsonify({"error": "No credits remaining. Upgrade your plan or wait for monthly reset."}), 402
            deduct_credit(current_user)
            return f(*args, **kwargs)
        if session.get('authenticated'):
            return f(*args, **kwargs)
        if _EXPECTED_API_KEY:
            auth = request.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                provided = auth[len("Bearer "):]
                if hmac.compare_digest(provided, _EXPECTED_API_KEY):
                    return f(*args, **kwargs)
        # Check user API keys table
        auth = request.headers.get("Authorization", "") or request.headers.get("X-API-Key", "")
        if auth.startswith("Bearer "):
            provided = auth[len("Bearer "):]
        else:
            provided = auth
        if provided:
            user = _check_user_api_key(provided)
            if user:
                # Deduct credit for API usage
                try:
                    from auth import deduct_credit
                    if not deduct_credit(user):
                        return jsonify({"error": "No credits remaining. Upgrade your plan or wait for monthly reset."}), 402
                except Exception:
                    pass
                return f(*args, **kwargs)
        if not _EXPECTED_API_KEY:
            return jsonify({"error": "Server misconfigured: AUDITOR_API_KEY not set"}), 503
        return jsonify({"error": "Missing or invalid API key. Pass Authorization: Bearer <key>"}), 401
    return wrapper

UPLOAD_DIR = os.path.join(REPORT_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

_CODE_EXTS: tuple = (".sol", ".vy", ".move", ".clsp", ".clib")
_IMAGE_EXTS: tuple = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".bmp", ".webp")

_has_grep = False
_grep_arsenal = None
try:
    import grep_arsenal as _grep_arsenal
    _has_grep = True
except ImportError:
    pass

_has_mcp = False
_mcp_int = None
try:
    import mcp_integration as _mcp_int
    _has_mcp = True
except ImportError:
    pass

_has_ai = False
_ai_scan = None
try:
    import ai_tools as _ai_scan
    _has_ai = True
except ImportError:
    pass

_has_zksync = False
_zksync_scan = None
try:
    import zksync_detector as _zksync_scan
    _has_zksync = True
except ImportError:
    pass

_has_sarif = False
report_to_sarif = None
try:
    from sarif_export import report_to_sarif
    _has_sarif = True
except ImportError:
    pass

_has_h1 = False
_h1_report_func = None
try:
    from hackerone_report import generate_h1_report
    _h1_report_func = generate_h1_report
    _has_h1 = True
except ImportError:
    pass

_has_cvss = False
score_report = None
compute_cvss = None
cvss_explanation = None
try:
    from cvss_scorer import score_report, compute_cvss, cvss_explanation
    _has_cvss = True
except ImportError:
    pass

_has_gas_profiler = False
compile_estimate_gas = None
try:
    from gas_profiler import estimate_gas as compile_estimate_gas
    _has_gas_profiler = True
except ImportError:
    pass

_has_sbom = False
analyze_sbom = None
format_sbom_text = None
generate_sbom_json = None
try:
    from sbom import analyze_sbom, format_sbom_text, generate_sbom_json
    _has_sbom = True
except ImportError:
    pass

def _run_analysis(code: str, analysis_type: str) -> str:
    return dispatch_analysis(code, analysis_type)

def _save_html_report(filename: str, report: str, label: str, analysis_type: str) -> str:
    safe_report = html.escape(report)
    page = f"""<!DOCTYPE html>
<html lang="en" dir="ltr">
<head><meta charset="UTF-8">
<title>{label} - {analysis_type} Report</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #c9d1d9; padding: 2rem; }}
h1 {{ color: #58a6ff; text-align: center; margin-bottom: 1rem; }}
h2 {{ color: #58a6ff; margin: 1.5rem 0 0.5rem; }}
pre {{ font-family: 'Cascadia Code', monospace; font-size: 0.85rem; line-height: 1.6; white-space: pre-wrap; word-break: break-word; direction: ltr; text-align: left; background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem; }}
.meta {{ color: #8b949e; text-align: center; margin-bottom: 2rem; }}
hr {{ border: none; border-top: 1px solid #30363d; margin: 1rem 0; }}
.finding {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 0.75rem; margin-bottom: 0.5rem; }}
.critical {{ border-right: 4px solid #da3633; }}
.high {{ border-right: 4px solid #d29922; }}
.medium {{ border-right: 4px solid #58a6ff; }}
.low {{ border-right: 4px solid #8b949e; }}
.info {{ border-right: 4px solid #238636; }}
</style></head>
<body>
<h1>{label}</h1>
<p class="meta"><strong>Analysis type:</strong> {analysis_type} | <strong>Date:</strong> {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
<hr>
<pre>{safe_report}</pre>
<hr>
<p class="meta" style="margin-top: 2rem;">Smart Contract Auditor — Secure Analysis Engine</p>
</body></html>"""
    path = os.path.join(REPORT_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(page)
    logger.info(f"HTML report saved: {path}")
    return path

def _fmt_size(size: int) -> str:
    for unit in ['B', 'KB', 'MB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"

def _handle_zip_upload(file_storage):
    import tempfile, zipfile, shutil
    tmpdir = tempfile.mkdtemp(prefix="project_upload_")
    zippath = os.path.join(tmpdir, file_storage.filename)
    file_storage.save(zippath)
    try:
        with zipfile.ZipFile(zippath, 'r') as zf:
            file_size = os.path.getsize(zippath)
            if file_size > 50 * 1024 * 1024:
                return {"error": "Zip file exceeds maximum size of 50 MB"}
            rejected = []
            for name in zf.namelist():
                # Path traversal check via realpath
                extracted_path = os.path.realpath(os.path.join(tmpdir, name))
                if not extracted_path.startswith(os.path.realpath(tmpdir)):
                    rejected.append(name + " (path traversal)")
                    continue
                parts = name.replace('\\', '/').split('/')
                if '__pycache__' in parts or 'node_modules' in parts:
                    rejected.append(name)
                    continue
                ext = os.path.splitext(name)[1].lower()
                if ext in ('.exe', '.sh', '.bat', '.cmd', '.dll', '.so', '.dylib', '.ps1'):
                    rejected.append(name)
                    continue
            if rejected:
                return {"error": f"Zip contains rejected files: {', '.join(rejected[:3])}" + (f" and {len(rejected)-3} more" if len(rejected) > 3 else "")}
            try:
                zf.extractall(tmpdir, filter='data')
            except TypeError:
                for member in zf.infolist():
                    target = os.path.realpath(os.path.join(tmpdir, member.filename))
                    if not target.startswith(os.path.realpath(tmpdir)):
                        continue
                    zf.extract(member, tmpdir)
        items = os.listdir(tmpdir)
        root = tmpdir
        for item in items:
            item_path = os.path.join(tmpdir, item)
            if os.path.isdir(item_path) and item != '__MACOSX':
                root = item_path
                break
        return analyze_project(root, "english")
    except zipfile.BadZipFile:
        return {"error": "Invalid or corrupted zip file"}
    except Exception as e:
        logger.exception("Zip upload analysis failed")
        return {"error": "Analysis failed"}
    finally:
        try:
            shutil.rmtree(tmpdir)
        except Exception:
            pass
