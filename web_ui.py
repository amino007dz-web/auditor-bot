import os
import sys
import json
import time
import logging
from flask import Flask, render_template, request, jsonify, send_from_directory, session, redirect
from flask_wtf.csrf import CSRFProtect

sys.path.insert(0, os.path.dirname(__file__))

from _shared import (
    rate_limit, require_api_key, UPLOAD_DIR, _CODE_EXTS, _IMAGE_EXTS,
    _run_analysis, _save_html_report, _fmt_size,
    _has_cvss, _has_gas_profiler, _has_sbom,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from api_routes import api_bp
from audit_service import AuditService
from config import KB_ENABLED, CACHE_ENABLED, REPORT_DIR, GITHUB_TOKEN, SECRET_KEY
from main import ensure_report_dir, save_report_txt, load_local_contract
from batch_audit import batch_audit
from gas_analysis import analyze_gas, estimate_gas_savings
from test_generator import generate_foundry_test, generate_hardhat_test
from project_detector import analyze_project
from inheritance_graph import extract_inheritance, generate_html_graph
from permission_analysis import analyze_permissions
from custom_rules import get_rules_engine, CustomRule
from chain_loader import load_from_explorer, list_supported_chains
from external_analyzers import TOOL_AVAILABLE
from _shared import _has_gas_profiler as _has_gas_profiler_local
from _shared import compile_estimate_gas
from auth import verify_code, requires_auth, create_access_code, list_codes, deactivate_code, ADMIN_PASSWORD

try:
    from cvss_scorer import score_report, compute_cvss, cvss_explanation
except ImportError:
    score_report = compute_cvss = cvss_explanation = None

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
app.config['WTF_CSRF_TIME_LIMIT'] = 3600
app.static_folder = 'static'
app.register_blueprint(api_bp)

# CSRF protection: exempt API blueprint (uses Bearer token)
csrf = CSRFProtect(app)
csrf.exempt(api_bp)

from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

# Rate limiter
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

# CSP + security headers
@app.after_request
def add_security_headers(resp):
    resp.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; font-src 'self' data:; img-src 'self' data:; connect-src 'self'"
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['X-XSS-Protection'] = '1; mode=block'
    resp.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    resp.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return resp


@app.route('/')
def landing():
    if 'authenticated' in session:
        return redirect('/app')
    return render_template('landing.html')


@app.route('/app')
@requires_auth
def index():
    return render_template('index.html')


@app.route('/api/auth/verify', methods=['POST'])
@limiter.limit("10 per minute")
def api_auth_verify():
    data = request.get_json()
    if not data or 'code' not in data:
        return jsonify({"success": False, "error": "Code is required"}), 400
    if verify_code(data['code']):
        session['authenticated'] = True
        session['access_code'] = data['code'].strip().upper()
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Invalid or expired access code"}), 403

csrf.exempt(api_auth_verify)


@app.route('/report/interactive/<filename>')
def report_interactive(filename):
    fpath = os.path.join(REPORT_DIR, filename)
    if not os.path.isfile(fpath):
        return "Report not found", 404
    with open(fpath, "r", encoding="utf-8") as f:
        content = f.read()
    import html
    escaped = html.escape(content)
    lines = escaped.split("\n")
    findings_html = []
    in_finding = False
    for line in lines:
        lower = line.lower()
        sev = ""
        for s in ("critical", "high", "medium", "low", "info"):
            if lower.startswith(f"### {s}") or lower.startswith(f"## {s}") or lower.startswith(f"**{s}"):
                sev = s
                break
        if sev:
            title = line.replace("###", "").replace("##", "").replace("**", "").strip()
            findings_html.append(
                f'<div class="finding">'
                f'<div class="finding-header" onclick="toggleFinding(this)">'
                f'<span class="severity-badge {sev}">{sev}</span>'
                f'<span class="title">{html.escape(title)}</span>'
                f'<span class="toggle">&rsaquo;</span></div>'
                f'<div class="finding-body">'
            )
            in_finding = True
        elif line.strip().startswith("---") and in_finding:
            findings_html[-1] = findings_html[-1].rstrip("</div>\n</div>") + "</div></div>"
            in_finding = False
        elif in_finding:
            findings_html.append(f"<pre>{line}</pre>")
        else:
            findings_html.append(f"<pre>{line}</pre>")
    if in_finding and findings_html:
        findings_html.append("</div></div>")
    return render_template('report_interactive.html',
                           label=filename.replace('.txt', '').replace('.html', ''),
                           analysis_type="audit",
                           date=time.strftime('%Y-%m-%d %H:%M:%S'),
                           findings_html="\n".join(findings_html))


@app.route('/download/<filename>')
def download(filename):
    return send_from_directory(REPORT_DIR, filename, as_attachment=False)


@app.route('/report/list')
def report_list():
    ensure_report_dir()
    reports = []
    if os.path.isdir(REPORT_DIR):
        for fname in sorted(os.listdir(REPORT_DIR), reverse=True):
            if fname.endswith(('.txt', '.html', '.json')) and fname != ".gitkeep":
                fpath = os.path.join(REPORT_DIR, fname)
                size = os.path.getsize(fpath)
                mtime = time.strftime('%Y-%m-%d %H:%M', time.localtime(os.path.getmtime(fpath)))
                reports.append({"name": fname, "size": _fmt_size(size), "modified": mtime})
    return render_template('reports.html', reports=reports)


@app.route('/dashboard')
def dashboard():
    ensure_report_dir()
    s = AuditService.kb_stats() if KB_ENABLED else {}
    report_count = 0
    if os.path.isdir(REPORT_DIR):
        report_count = len([f for f in os.listdir(REPORT_DIR)
                           if f.endswith(('.txt', '.html')) and f != ".gitkeep"])
    kb_dynamic = None
    if KB_ENABLED:
        try:
            from knowledge_base import KnowledgeBase
            from config import KB_DB_PATH
            _tmp_kb = KnowledgeBase(KB_DB_PATH)
            kb_dynamic = _tmp_kb.get_dynamic_stats()
        except:
            pass
    stats = {
        "reports": report_count,
        "patterns": s.get("patterns", 0),
        "false_positives": s.get("false_positives", 0),
        "sessions": s.get("sessions", 0),
        "top_patterns": s.get("top_patterns", []),
        "rankings": s.get("rankings", []),
        "slither": TOOL_AVAILABLE.get("slither", False),
        "mythril": TOOL_AVAILABLE.get("mythril", False),
        "kb_enabled": KB_ENABLED,
        "cache_enabled": CACHE_ENABLED,
        "kb_dynamic": kb_dynamic,
    }
    return render_template('dashboard.html', stats=stats)


@app.route('/explorer', methods=['GET', 'POST'])
def explorer():
    result = None
    if request.method == 'POST':
        address = request.form.get('address', '').strip()
        chain = request.form.get('chain', 'ethereum').strip()
        api_key = request.form.get('api_key', '').strip()
        if address:
            data = load_from_explorer(address, chain, api_key)
            if data:
                result = data
            else:
                result = {"error": f"Failed to fetch contract {address} from {chain}"}
    return render_template('explorer.html', result=result,
                           chains=list_supported_chains())


@app.route('/batch', methods=['GET', 'POST'])
def batch_page():
    result = None
    if request.method == 'POST':
        path = request.form.get('path', '').strip()
        if path and os.path.isdir(path):
            result = batch_audit(path)
        elif 'zipfile' in request.files and request.files['zipfile'].filename:
            import tempfile, zipfile, shutil
            f = request.files['zipfile']
            tmpdir = tempfile.mkdtemp(prefix="batch_upload_")
            zippath = os.path.join(tmpdir, f.filename)
            f.save(zippath)
            try:
                with zipfile.ZipFile(zippath, 'r') as zf:
                    zf.extractall(tmpdir)
                items = os.listdir(tmpdir)
                root = tmpdir
                for item in items:
                    item_path = os.path.join(tmpdir, item)
                    if os.path.isdir(item_path) and item != '__MACOSX':
                        root = item_path
                        break
                result = batch_audit(root)
            except zipfile.BadZipFile:
                result = {"error": "Invalid zip file"}
            except Exception as e:
                logger.exception("Batch zip upload failed")
                result = {"error": str(e)}
            finally:
                try: shutil.rmtree(tmpdir)
                except: pass
        else:
            result = {"error": "Invalid path or no file uploaded"}
    return render_template('batch.html', result=result)


@app.route('/gas', methods=['GET', 'POST'])
def gas_page():
    result = None
    if request.method == 'POST':
        code = request.form.get('code', '')
        if code:
            pattern_result = analyze_gas(code)
            estimate = estimate_gas_savings(code)
            parts = [pattern_result]
            if _has_gas_profiler:
                compile_result = compile_estimate_gas(code)
                parts.append(compile_result)
            result = "\n\n".join(parts)
    return render_template('gas.html', result=result)


@app.route('/testgen', methods=['GET', 'POST'])
def testgen_page():
    tests = None
    if request.method == 'POST':
        code = request.form.get('code', '')
        report = request.form.get('report', '')
        name = request.form.get('name', 'Contract')
        if code and report:
            framework = request.form.get('framework', 'foundry')
            if framework == 'foundry':
                tests = generate_foundry_test(name, report, code)
            else:
                tests = generate_hardhat_test(name, report)
    return render_template('testgen.html', tests=tests)


@app.route('/inhgraph', methods=['GET', 'POST'])
def inhgraph_page():
    html_graph = None
    if request.method == 'POST':
        code = request.form.get('code', '')
        if code:
            contracts = extract_inheritance(code)
            html_graph = generate_html_graph(contracts)
            html_path = os.path.join(REPORT_DIR, f"inheritance_{int(time.time())}.html")
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html_graph)
    return render_template('inhgraph.html', graph=html_graph)


@app.route('/project', methods=['GET', 'POST'])
def project_page():
    from _shared import _handle_zip_upload
    result = None
    if request.method == 'POST':
        path = request.form.get('path', '').strip()
        if path:
            result = analyze_project(path, "english")
        if 'zipfile' in request.files and request.files['zipfile'].filename:
            result = _handle_zip_upload(request.files['zipfile'])
    return render_template('project.html', result=result)


@app.route('/permissions', methods=['GET', 'POST'])
def permissions_page():
    result = None
    if request.method == 'POST':
        code = request.form.get('code', '')
        if code:
            result = analyze_permissions(code)
    return render_template('permissions.html', result=result)


@app.route('/cvss', methods=['GET', 'POST'])
def cvss_page():
    result = None
    if request.method == 'POST':
        action = request.form.get('action', 'score')
        if action == 'score' and _has_cvss:
            av = request.form.get('av', 'N')
            ac = request.form.get('ac', 'L')
            pr = request.form.get('pr', 'N')
            ui = request.form.get('ui', 'N')
            vc = request.form.get('vc', 'H')
            vi = request.form.get('vi', 'H')
            va = request.form.get('va', 'H')
            score, sev, vector = compute_cvss(av, ac, pr, ui, vc, vi, va)
            result = {"score": score, "severity": sev, "vector": vector,
                       "explanation": cvss_explanation(score, sev, vector)}
        elif action == 'report':
            report_text = request.form.get('report', '')
            if report_text and _has_cvss:
                result = score_report(report_text)
    return render_template('cvss.html', result=result, cvss_available=_has_cvss)


@app.route('/rules', methods=['GET', 'POST'])
def rules_page():
    engine = get_rules_engine()
    scan_result = None
    if request.method == 'POST':
        action = request.form.get('action', '')
        if action == 'add':
            rule = CustomRule(
                request.form['name'], request.form['pattern'],
                request.form.get('severity', 'medium'),
                request.form.get('description', ''),
                request.form.get('lang', 'solidity'),
            )
            engine.add_rule(rule)
        elif action == 'remove':
            engine.remove_rule(request.form['name'])
        elif action == 'scan':
            code = request.form.get('code', '')
            lang = request.form.get('lang', 'solidity')
            if code:
                scan_result = engine.scan_to_text(code, lang)
    return render_template('rules.html', rules=engine.list_rules(), scan=scan_result)


@app.route('/report/view/<filename>')
def report_view(filename):
    fpath = os.path.join(REPORT_DIR, filename)
    if not os.path.isfile(fpath):
        return "Report not found", 404
    with open(fpath, "r", encoding="utf-8") as f:
        content = f.read()
    return render_template('report_view.html', filename=filename, content=content)


@app.route('/report/hackerone/<filename>')
def report_hackerone(filename):
    fpath = os.path.join(REPORT_DIR, filename)
    if not os.path.isfile(fpath):
        return "Report not found", 404
    with open(fpath, "r", encoding="utf-8") as f:
        content = f.read()
    try:
        from hackerone_report import generate_h1_report
        h1 = generate_h1_report(content, label=os.path.splitext(filename)[0])
    except ImportError:
        from agents import generate_hackerone_report
        h1 = generate_hackerone_report(content, label=os.path.splitext(filename)[0])
    return render_template('report_view.html', filename=f"h1_{filename}", content=h1)


@app.route('/download_pdf/<filename>')
def download_pdf(filename):
    return send_from_directory(REPORT_DIR, filename, as_attachment=True)


@app.route('/privacy')
def privacy_page():
    return render_template('privacy.html')


@app.route('/docs')
def api_docs():
    return render_template('swagger.html')


@app.route('/api/openapi.json')
def api_openapi():
    return jsonify({
        "openapi": "3.0.0",
        "info": {"title": "Smart Contract Auditor API", "version": "2.0.0", "description": "AI-powered smart contract security auditing API"},
        "servers": [{"url": "/api", "description": "API server"}],
        "paths": {
            "/analyze/stream": {
                "post": {
                    "summary": "Stream analysis results via SSE",
                    "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object", "properties": {
                        "code": {"type": "string", "description": "Source code"},
                        "type": {"type": "string", "enum": ["audit", "quick", "deep"]}
                    }}}}},
                    "responses": {"200": {"description": "SSE stream of analysis progress and results"}}
                }
            },
            "/auth/verify": {
                "post": {
                    "summary": "Verify an access code",
                    "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object", "properties": {
                        "code": {"type": "string"}
                    }}}}},
                    "responses": {"200": {"description": "Authentication result"}}
                }
            },
            "/quota": {
                "get": {"summary": "Get remaining quota", "responses": {"200": {"description": "Quota info"}}}
            },
            "/history": {
                "get": {"summary": "List audit history", "responses": {"200": {"description": "History list"}}},
                "post": {
                    "summary": "Save an audit report",
                    "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object", "properties": {
                        "report": {"type": "string"}, "title": {"type": "string"}
                    }}}}},
                    "responses": {"200": {"description": "Saved"}}
                }
            },
            "/gas": {
                "post": {
                    "summary": "Analyze gas usage",
                    "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object", "properties": {
                        "code": {"type": "string"}
                    }}}}},
                    "responses": {"200": {"description": "Gas report"}}
                }
            },
            "/knowledge/ingest": {
                "post": {
                    "summary": "Upload PDF to knowledge base",
                    "requestBody": {"required": True, "content": {"multipart/form-data": {"schema": {"type": "object", "properties": {
                        "file": {"type": "string", "format": "binary"}
                    }}}}},
                    "responses": {"200": {"description": "Ingestion result"}}
                }
            },
            "/analyze/fix": {
                "post": {
                    "summary": "Suggest a fix for vulnerable code",
                    "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object", "properties": {
                        "code": {"type": "string"}, "report": {"type": "string"}
                    }}}}},
                    "responses": {"200": {"description": "Suggested fix"}}
                }
            },
            "/analyze/github": {
                "post": {
                    "summary": "Audit a GitHub repository",
                    "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object", "properties": {
                        "url": {"type": "string"}
                    }}}}},
                    "responses": {"200": {"description": "SSE stream of audit results"}}
                }
            },
            "/analyze/project": {
                "post": {
                    "summary": "Audit a ZIP project",
                    "requestBody": {"required": True, "content": {"multipart/form-data": {"schema": {"type": "object", "properties": {
                        "project": {"type": "string", "format": "binary"},
                        "entry_contract": {"type": "string"}
                    }}}}},
                    "responses": {"200": {"description": "SSE stream of audit results"}}
                }
            },
        }
    })


@app.route('/admin/login')
def admin_login_page():
    return render_template('admin.html')


@app.route('/api/admin/login', methods=['POST'])
@limiter.limit("5 per minute")
def api_admin_login():
    data = request.get_json()
    if data and data.get('password') == ADMIN_PASSWORD:
        session['admin_authenticated'] = True
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Wrong password"}), 403

csrf.exempt(api_admin_login)


@app.route('/api/admin/check')
def api_admin_check():
    return jsonify({"authenticated": 'admin_authenticated' in session})

csrf.exempt(api_admin_check)


@app.route('/api/admin/codes', methods=['GET', 'POST'])
def api_admin_codes():
    if 'admin_authenticated' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    if request.method == 'POST':
        data = request.get_json() or {}
        code = create_access_code(
            created_by=data.get('created_by', ''),
            max_uses=int(data.get('max_uses', -1))
        )
        return jsonify({"code": code})
    return jsonify({"codes": list_codes()})

csrf.exempt(api_admin_codes)


@app.route('/api/admin/codes/deactivate', methods=['POST'])
def api_admin_deactivate():
    if 'admin_authenticated' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json()
    if data and 'code' in data:
        deactivate_code(data['code'])
        return jsonify({"success": True})
    return jsonify({"error": "Code required"}), 400

csrf.exempt(api_admin_deactivate)


try:
    from telegram_bot import get_bot
    _tg_bot = get_bot()
    _tg_bot.start()
    if _tg_bot.token:
        logger.info("Telegram bot polling thread started")
except Exception as e:
    logger.warning(f"Telegram bot not started: {e}")

if __name__ == '__main__':
    ensure_report_dir()
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    logger.info(f"Starting Web UI on http://0.0.0.0:{port} (debug={debug})")
    app.run(host="0.0.0.0", port=port, debug=debug)
