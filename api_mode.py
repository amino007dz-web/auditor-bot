"""API Mode - REST API for programmatic use."""
import os
import sys
import tempfile
import time

import logging
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename

sys.path.insert(0, os.path.dirname(__file__))
from agents import analyze_code, chunked_audit
from main import load_local_contract
from orchestrator import dispatch_analysis
from chain_loader import load_from_explorer
from batch_audit import batch_audit
from diff_audit import compute_diff, run_diff_audit
from external_analyzers import run_external_analyzers, findings_to_text
from gas_analysis import analyze_gas, estimate_gas_savings
from test_generator import generate_foundry_test
from project_detector import analyze_project

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("api")

app = Flask(__name__)
API_KEY = os.environ.get("AUDITOR_API_KEY", "")
UPLOAD_DIR = os.path.join(tempfile.gettempdir(), "smart_audit_uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

def cleanup_old_uploads(max_age_hours: int = 24):
    """Delete uploaded files older than 24 hours."""
    now = time.time()
    removed = 0
    for fname in os.listdir(UPLOAD_DIR):
        fpath = os.path.join(UPLOAD_DIR, fname)
        try:
            if os.path.isfile(fpath) and now - os.path.getmtime(fpath) > max_age_hours * 3600:
                os.remove(fpath)
                removed += 1
        except OSError:
            pass
    if removed:
        logger.info(f"Cleanup: deleted {removed} old file(s) from uploads")

# Clean up old files at startup
cleanup_old_uploads()


def require_auth(f):
    """Middleware to verify API key."""
    def wrapper(*args, **kwargs):
        if API_KEY:
            key = request.headers.get("X-API-Key", "")
            if key != API_KEY:
                return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper


@app.route("/v1/audit", methods=["POST"])
@require_auth
def api_audit():
    """Analyze a smart contract."""
    data = request.get_json()
    if not data or "code" not in data:
        return jsonify({"error": "Field 'code' is required"}), 400

    code = data["code"]
    analysis_type = data.get("type", "audit")

    try:
        result = dispatch_analysis(code, analysis_type)
    except Exception as e:
        logger.exception("Audit failed")
        return jsonify({"error": "An internal error occurred"}), 500

    return jsonify({"result": result, "type": analysis_type})


@app.route("/v1/analyze/file", methods=["POST"])
@require_auth
def api_file():
    """Analyze a contract file."""
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    f = request.files["file"]
    safe = secure_filename(f.filename) or "upload.sol"
    path = os.path.join(UPLOAD_DIR, safe)
    f.save(path)
    code = load_local_contract(path)
    if not code:
        return jsonify({"error": "Failed to read file"}), 400
    result = analyze_code(code)
    return jsonify({"result": result, "filename": f.filename})


@app.route("/v1/contract/<chain>/<address>", methods=["GET"])
@require_auth
def api_contract(chain, address):
    """Fetch a contract from a chain and analyze it."""
    api_key = request.args.get("api_key", "")
    data = load_from_explorer(address, chain, api_key)
    if not data:
        return jsonify({"error": "Contract not found"}), 404
    result = analyze_code(data["code"])
    return jsonify({
        "contract": data["name"],
        "chain": chain,
        "compiler": data.get("compiler", ""),
        "result": result,
    })


@app.route("/v1/batch", methods=["POST"])
@require_auth
def api_batch():
    """Analyze an entire folder."""
    data = request.get_json()
    if not data or "path" not in data:
        return jsonify({"error": "Field 'path' is required"}), 400
    workers = data.get("workers", 4)
    result = batch_audit(data["path"], workers)
    return jsonify(result)


@app.route("/v1/gas", methods=["POST"])
@require_auth
def api_gas():
    """Analyze gas."""
    data = request.get_json()
    if not data or "code" not in data:
        return jsonify({"error": "Field 'code' is required"}), 400
    analysis = analyze_gas(data["code"])
    estimate = estimate_gas_savings(data["code"])
    return jsonify({"analysis": analysis, "estimate": estimate})


@app.route("/v1/diff", methods=["POST"])
@require_auth
def api_diff():
    """Compare two versions."""
    data = request.get_json()
    if not data or "v1" not in data or "v2" not in data:
        return jsonify({"error": "Fields 'v1' and 'v2' are required"}), 400
    diff = compute_diff(data["v1"], data["v2"])
    audit = run_diff_audit(data["v1"], data["v2"], data.get("lang", "solidity"))
    return jsonify({"diff": diff, "audit": audit})


@app.route("/v1/project", methods=["POST"])
@require_auth
def api_project():
    """Analyze a full project."""
    data = request.get_json()
    if not data or "path" not in data:
        return jsonify({"error": "Field 'path' is required"}), 400
    result = analyze_project(data["path"], "english")
    return jsonify({"result": result})


@app.route("/v1/tests", methods=["POST"])
@require_auth
def api_tests():
    """Generate Foundry tests."""
    data = request.get_json()
    if not data or "code" not in data or "report" not in data:
        return jsonify({"error": "Fields 'code' and 'report' are required"}), 400
    name = data.get("contract_name", "Contract")
    tests = generate_foundry_test(name, data["report"], data["code"])
    return jsonify({"tests": tests})


@app.route("/v1/health")
def api_health():
    return jsonify({"status": "ok", "version": "1.0.0"})


def run_api(host="0.0.0.0", port=5001, debug=False):
    """Run API server."""
    logger.info(f"API running on http://{host}:{port}")
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    run_api(debug=True)
