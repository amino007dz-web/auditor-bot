import os
import sys
import json
import time
import logging
from flask import Flask, render_template, request, jsonify, send_from_directory

sys.path.insert(0, os.path.dirname(__file__))

from _shared import (
    rate_limit, require_api_key, UPLOAD_DIR, _CODE_EXTS, _IMAGE_EXTS,
    _run_analysis, _save_html_report, _fmt_size,
    _has_cvss, _has_gas_profiler, _has_sbom,
)
from api_routes import api_bp
from audit_service import AuditService
from config import KB_ENABLED, CACHE_ENABLED, REPORT_DIR, GITHUB_TOKEN
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

try:
    from cvss_scorer import score_report, compute_cvss, cvss_explanation
except ImportError:
    score_report = compute_cvss = cvss_explanation = None

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
app.static_folder = 'static'
app.register_blueprint(api_bp)


@app.route('/')
def index():
    return render_template('index.html')


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
    logger.info(f"Starting Web UI on http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=True)
