import os
import sys
import json
import time
import logging
from flask import Flask, render_template, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename

sys.path.insert(0, os.path.dirname(__file__))
from audit_service import AuditService
from orchestrator import dispatch_analysis, save_report
from chain_loader import load_from_explorer, list_supported_chains
from external_analyzers import TOOL_AVAILABLE, run_external_analyzers, findings_to_text
from config import KB_ENABLED, CACHE_ENABLED, REPORT_DIR
from main import ensure_report_dir, save_report_txt, load_local_contract
from pdf_report import generate_pdf_report
from batch_audit import batch_audit
from gas_analysis import analyze_gas, estimate_gas_savings
from test_generator import generate_foundry_test, generate_hardhat_test
from project_detector import analyze_project
from inheritance_graph import extract_inheritance, generate_html_graph
from permission_analysis import analyze_permissions
from custom_rules import get_rules_engine, CustomRule


logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
UPLOAD_DIR = os.path.join(REPORT_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    ensure_report_dir()
    analysis_type = request.form.get('analysis_type', 'audit')
    code = None
    label = "upload"
    if 'file' in request.files and request.files['file'].filename:
        f = request.files['file']
        safe_name = secure_filename(f.filename)
        path = os.path.join(UPLOAD_DIR, safe_name)
        f.save(path)
        code = load_local_contract(path)
        label = os.path.splitext(safe_name)[0]
    else:
        return jsonify({"error": "No file was uploaded"}), 400
    if not code:
        return jsonify({"error": "Failed to read the file"}), 400
    try:
        report = _run_analysis(code, analysis_type)
    except Exception as e:
        logger.exception("Analysis failed")
        return jsonify({"error": "An internal error occurred during analysis. Please try again later."}), 500
    timestamp = int(time.time())
    filename_txt = f"{analysis_type}_{label}_{timestamp}.txt"
    filename_html = f"{analysis_type}_{label}_{timestamp}.html"
    txt_path = save_report_txt(filename_txt, report)
    html_path = _save_html_report(filename_html, report, label, analysis_type)
    return jsonify({
        "report": report,
        "filename": filename_txt,
        "filename_html": filename_html,
    })


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


@app.route('/analyze_chain', methods=['POST'])
def analyze_chain():
    data = request.get_json()
    if not data or 'address' not in data:
        return jsonify({"error": "Incomplete data"}), 400
    chain_data = load_from_explorer(data['address'], data.get('chain', 'ethereum'),
                                     data.get('api_key', ''))
    if not chain_data:
        return jsonify({"error": "Failed to fetch contract"}), 400
    analysis_type = data.get('analysis_type', 'audit')
    report = _run_analysis(chain_data['code'], analysis_type)
    ts = int(time.time())
    fn_txt = f"chain_{chain_data['name']}_{ts}.txt"
    save_report_txt(fn_txt, report)
    return jsonify({"report": report, "filename": fn_txt,
                    "contract": chain_data['name']})


@app.route('/batch', methods=['GET', 'POST'])
def batch_page():
    result = None
    if request.method == 'POST':
        lang = request.form.get('lang', 'arabic')
        path = request.form.get('path', '').strip()
        if path and os.path.isdir(path):
            result = batch_audit(path, lang=lang)
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
                result = batch_audit(root, lang=lang)
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
            result = analyze_gas(code)
            estimate = estimate_gas_savings(code)
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
    result = None
    if request.method == 'POST':
        path = request.form.get('path', '').strip()
        lang = request.form.get('lang', 'arabic')
        if path:
            result = analyze_project(path, lang)
        # Also handle zip file upload
        if 'zipfile' in request.files and request.files['zipfile'].filename:
            result = _handle_zip_upload(request.files['zipfile'], lang)
    return render_template('project.html', result=result)


@app.route('/upload_project', methods=['POST'])
def upload_project():
    ensure_report_dir()
    lang = request.form.get('lang', 'english')
    if 'file' not in request.files or not request.files['file'].filename:
        return jsonify({"error": "No file uploaded"}), 400
    result = _handle_zip_upload(request.files['file'], lang)
    if isinstance(result, dict) and 'error' in result:
        return jsonify(result), 400
    return jsonify({"report": str(result)})


def _handle_zip_upload(file_storage, lang="english"):
    """Extract and analyze an uploaded zip file containing a project."""
    import tempfile, zipfile, os, json
    tmpdir = tempfile.mkdtemp(prefix="project_upload_")
    zippath = os.path.join(tmpdir, file_storage.filename)
    file_storage.save(zippath)
    try:
        with zipfile.ZipFile(zippath, 'r') as zf:
            zf.extractall(tmpdir)
        # Find the project root (first subdirectory)
        items = os.listdir(tmpdir)
        root = tmpdir
        for item in items:
            item_path = os.path.join(tmpdir, item)
            if os.path.isdir(item_path) and item != '__MACOSX':
                root = item_path
                break
        return analyze_project(root, lang)
    except zipfile.BadZipFile:
        return {"error": "Invalid or corrupted zip file"}
    except Exception as e:
        logger.exception("Zip upload analysis failed")
        return {"error": str(e)}
    finally:
        import shutil
        try:
            shutil.rmtree(tmpdir)
        except Exception:
            pass


@app.route('/permissions', methods=['GET', 'POST'])
def permissions_page():
    result = None
    if request.method == 'POST':
        code = request.form.get('code', '')
        if code:
            result = analyze_permissions(code)
    return render_template('permissions.html', result=result)


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


@app.route('/api/pdf', methods=['POST'])
def api_pdf():
    data = request.get_json()
    if not data or 'report' not in data:
        return jsonify({"error": "Field 'report' is required"}), 400
    label = data.get('label', 'report')
    path = generate_pdf_report(data['report'], label)
    return jsonify({"path": path, "url": f"/download/{os.path.basename(path)}"})


@app.route('/download_pdf/<filename>')
def download_pdf(filename):
    return send_from_directory(REPORT_DIR, filename, as_attachment=True)


def _run_analysis(code: str, analysis_type: str) -> str:
    return dispatch_analysis(code, analysis_type)


def _save_html_report(filename: str, report: str, label: str, analysis_type: str) -> str:
    html = f"""<!DOCTYPE html>
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
<pre>{report}</pre>
<hr>
<p class="meta" style="margin-top: 2rem;">Smart Contract Auditor — Secure Analysis Engine</p>
</body></html>"""
    path = os.path.join(REPORT_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    logger.info(f"HTML report saved: {path}")
    return path


def _fmt_size(size: int) -> str:
    for unit in ['B', 'KB', 'MB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


# Start Telegram bot in background thread if TELEGRAM_BOT_TOKEN is set
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
