import os
import sys
import json
import time
import html
import logging
from flask import Blueprint, request, jsonify, Response, stream_with_context, session

sys.path.insert(0, os.path.dirname(__file__))

from _shared import (
    rate_limit, require_api_key, UPLOAD_DIR, _CODE_EXTS,
    _run_analysis, _save_html_report, _fmt_size,
    _has_grep, _grep_arsenal, _has_mcp, _mcp_int,
    _has_ai, _ai_scan, _has_zksync, _zksync_scan,
    _has_sarif, report_to_sarif, _has_h1, _h1_report_func,
    _handle_zip_upload,
)
from main import ensure_report_dir, save_report_txt, load_local_contract
from config import OLLAMA_MODEL, GITHUB_TOKEN, SECRET_KEY, API_PROVIDER, ACTIVE_MODEL, FREE_MODELS
from agents.pipeline import truncate_code
from agents.llm_client import _stream_ollama, _stream_openrouter
from agents.prompts import SYSTEM_PROMPT
from agents.pre_scan import run_pre_scan
from werkzeug.utils import secure_filename
from orchestrator import dispatch_analysis
from auth import save_history, get_history, get_history_item, check_quota, requires_auth, deduct_credit, reset_credits_if_needed, MONTHLY_FREE_CREDITS
from flask_login import current_user

# Helper: choose the right streaming function based on config
def _stream_model(prompt, timeout=300):
    """Stream tokens from the configured model (OpenRouter or Ollama)."""
    if API_PROVIDER == "openrouter":
        model_id = FREE_MODELS.get(ACTIVE_MODEL, {}).get("id", "openrouter/free")
        return _stream_openrouter(model_id, prompt, timeout)
    return _stream_ollama(OLLAMA_MODEL, prompt, timeout)

logger = logging.getLogger(__name__)

api_bp = Blueprint('api', __name__, url_prefix='/api')

@api_bp.route('/analyze', methods=['POST'])
@rate_limit(5)
@require_api_key
def api_analyze():
    ensure_report_dir()
    analysis_type = request.form.get('analysis_type', 'audit')
    code = None
    label = "upload"
    if 'file' in request.files and request.files['file'].filename:
        f = request.files['file']
        ext = os.path.splitext(f.filename)[1].lower()
        if ext not in _CODE_EXTS:
            return jsonify({"error": f"Unsupported file type '{ext}'. Only {', '.join(_CODE_EXTS)} files are allowed."}), 400
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


@api_bp.route('/analyze/json', methods=['POST'])
@rate_limit(10)
@require_api_key
def api_analyze_json():
    """JSON endpoint for VS Code extension and programmatic use."""
    data = request.get_json()
    if not data or 'code' not in data:
        return jsonify({"error": "Field 'code' is required"}), 400
    code = truncate_code(data['code'])
    analysis_type = data.get('type', 'audit')
    try:
        report = _run_analysis(code, analysis_type)
        return jsonify({"report": report})
    except Exception as e:
        logger.exception("Analysis failed")
        return jsonify({"error": "An internal error occurred"}), 500


@api_bp.route('/analyze/stream', methods=['POST'])
@rate_limit(3)
@require_api_key
def api_analyze_stream():
    data = request.get_json()
    if not data or 'code' not in data:
        return jsonify({"error": "Field 'code' is required"}), 400
    code = data['code']
    code = truncate_code(code)
    # Credit check — actual deduction happens in @require_api_key decorator
    import flask_login
    if flask_login.current_user.is_authenticated:
        reset_credits_if_needed(flask_login.current_user)

    def generate():
        # Step 1: Pre-scan
        yield f"data: {json.dumps({'type': 'meta', 'message': 'Running pre-scan...'})}\n\n"
        yield f"data: {json.dumps({'type': 'step', 'step': 1, 'status': 'done'})}\n\n"
        try:
            pre_scan = run_pre_scan(code)
            if pre_scan:
                yield f"data: {json.dumps({'type': 'pre_scan', 'text': pre_scan})}\n\n"
        except Exception as e:
            logger.debug(f"Pre-scan in stream skipped: {e}")

        # Step 2: AI Analysis with SSE streaming
        yield f"data: {json.dumps({'type': 'step', 'step': 2, 'status': 'active'})}\n\n"
        yield f"data: {json.dumps({'type': 'meta', 'message': 'Analyzing with AI...'})}\n\n"
        prompt = f"{SYSTEM_PROMPT}\n\nCode to analyze:\n```solidity\n{code}\n```\nLanguage: english"
        full_report = ""
        for event in _stream_model(prompt):
            if event.startswith("data: "):
                try:
                    edata = json.loads(event[6:])
                    if 'token' in edata:
                        full_report += edata['token']
                        yield f"data: {json.dumps({'type': 'token', 'text': edata['token']})}\n\n"
                        continue
                    elif 'done' in edata:
                        full_report = edata.get('full', full_report)
                        yield f"data: {json.dumps({'type': 'step', 'step': 2, 'status': 'done'})}\n\n"
                        continue
                    elif 'error' in edata:
                        yield f"data: {json.dumps({'type': 'error', 'message': edata['error']})}\n\n"
                        return
                except json.JSONDecodeError:
                    logger.warning(f"SSE stream: JSON decode error for event: {event[:200]}")
                    continue
            yield event

        # Check if model returned an error instead of a report
        if not full_report or len(full_report.strip()) < 20:
            yield f"data: {json.dumps({'type': 'error', 'message': 'The AI model returned an empty response. Please try again.'})}\n\n"
            return
        if any(indicator in full_report.lower() for indicator in ["cannot read", "this model does not support", "image input", "i cannot", "i'm unable to", "not designed for"]):
            yield f"data: {json.dumps({'type': 'error', 'message': 'The AI model returned an internal error. This is a temporary issue — please try again.'})}\n\n"
            return

        # Step 3: Validation pass
        if full_report:
            yield f"data: {json.dumps({'type': 'step', 'step': 3, 'status': 'active'})}\n\n"
            yield f"data: {json.dumps({'type': 'meta', 'message': 'Running second-pass validation...'})}\n\n"
            try:
                from agents.validation import validate_report
                validated = validate_report(full_report, code, "english")
                if validated and len(validated) > 50:
                    full_report = validated
            except Exception as e:
                logger.debug(f"Validation in stream skipped: {e}")
            yield f"data: {json.dumps({'type': 'step', 'step': 3, 'status': 'done'})}\n\n"

        # Step 4: CVSS scoring
        if full_report:
            yield f"data: {json.dumps({'type': 'step', 'step': 4, 'status': 'active'})}\n\n"
            yield f"data: {json.dumps({'type': 'meta', 'message': 'Computing CVSS scores...'})}\n\n"
            try:
                from cvss_scorer import score_report as _score_cvss
                cvss_result = _score_cvss(full_report)
                if cvss_result:
                    full_report += f"\n\n---\n## CVSS Score\n{cvss_result}\n"
            except Exception as e:
                logger.debug(f"CVSS in stream skipped: {e}")
            yield f"data: {json.dumps({'type': 'step', 'step': 4, 'status': 'done'})}\n\n"

        # KB learning (silent, no step)
        try:
            from agents.pipeline import learn_from_audit
            learn_from_audit(code, full_report)
        except Exception as e:
            logger.debug(f"KB learning skipped: {e}")

        # Step 5: Done
        yield f"data: {json.dumps({'type': 'step', 'step': 5, 'status': 'done'})}\n\n"
        yield f"data: {json.dumps({'type': 'final', 'report': full_report})}\n\n"

    return Response(stream_with_context(generate()), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@api_bp.route('/analyze/diff', methods=['POST'])
@rate_limit(5)
@require_api_key
def api_analyze_diff():
    data = request.get_json()
    if not data or 'old_code' not in data or 'new_code' not in data:
        return jsonify({"error": "Fields 'old_code' and 'new_code' are required"}), 400
    try:
        from diff_auditor import analyze_diff as _diff_analyze, summarize_diff, compute_diff
        old = truncate_code(data['old_code'])
        new = truncate_code(data['new_code'])
        diff = compute_diff(old, new)
        summary = summarize_diff(diff)
        result = _diff_analyze(old, new)
        return jsonify({"summary": summary, "diff": diff, "analysis": result})
    except ImportError:
        return jsonify({"error": "Diff auditor not available"}), 500
    except Exception as e:
        logger.exception("Internal error")
        return jsonify({"error": "An internal error occurred"}), 500


@api_bp.route('/analyze_chain', methods=['POST'])
@rate_limit(3)
@require_api_key
def api_analyze_chain():
    from chain_loader import load_from_explorer
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


@api_bp.route('/analyze_github', methods=['POST'])
@rate_limit(5)
@require_api_key
def api_analyze_github():
    from github_loader import download_contracts
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "GitHub URL is required"}), 400
    url = data['url'].strip()
    analysis_type = data.get('analysis_type', 'audit')
    try:
        contracts = download_contracts(url, GITHUB_TOKEN if GITHUB_TOKEN else None)
        if not contracts:
            return jsonify({"error": "No Solidity files found in the repository"}), 404
        combined_code = "\n\n// ====== " + "=" * 40 + "\n\n".join(
            f"// File: {c['name']}\n{c['code'][:2000]}" for c in contracts[:10]
        )[:5000]
        report = dispatch_analysis(combined_code, analysis_type)
        ts = int(time.time())
        label = url.rstrip('/').split('/')[-1] or "github"
        fn_txt = f"github_{label}_{ts}.txt"
        fn_html = f"github_{label}_{ts}.html"
        save_report_txt(fn_txt, report)
        _save_html_report(fn_html, report, label, analysis_type)
        return jsonify({"report": report, "filename": fn_txt, "filename_html": fn_html})
    except ImportError:
        return jsonify({"error": "PyGithub not installed. Run: pip install PyGithub"}), 500
    except Exception as e:
        logger.exception("GitHub analysis failed")
        return jsonify({"error": "An internal error occurred"}), 500


@api_bp.route('/analyze/github', methods=['POST'])
@rate_limit(5)
@require_api_key
def api_github_stream():
    from github_loader import extract_repo_info
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "GitHub URL is required"}), 400
    url = data['url'].strip()

    def gen():
        from github_loader import get_all_sol_files
        username, repo_name = extract_repo_info(url)
        if not username or not repo_name:
            yield 'data: {}\n\n'.format(json.dumps({'type': 'error', 'message': 'Invalid GitHub URL'}))
            return

        yield 'data: {}\n\n'.format(json.dumps({'type': 'progress', 'step': 'github', 'text': f'Connecting to {username}/{repo_name}, scanning files...'}))
        contracts = get_all_sol_files(username, repo_name, GITHUB_TOKEN)
        if not contracts:
            yield 'data: {}\n\n'.format(json.dumps({'type': 'error', 'message': 'No Solidity files found in the repository'}))
            return

        yield 'data: {}\n\n'.format(json.dumps({'type': 'progress', 'step': 'github', 'text': f'Found {len(contracts)} file(s), preparing analysis...'}))
        combined = "\n\n// ====== " + "=" * 40 + "\n\n".join(
            f"// File: {c['name']}\n{c['code'][:2000]}" for c in contracts
        )[:5000]

        from agents.llm_client import _stream_ollama, _stream_openrouter
        from agents.prompts import SYSTEM_PROMPT
        from config import API_PROVIDER, ACTIVE_MODEL, FREE_MODELS, OLLAMA_MODEL
        yield 'data: {}\n\n'.format(json.dumps({'type': 'progress', 'step': 'pre-scan', 'text': 'Running static analysis (grep, MCP, AST)...'}))
        pre = run_pre_scan(combined)
        msg = 'GitHub repo: {} files found, pre-scan complete'.format(len(contracts))
        yield 'data: {}\n\n'.format(json.dumps({'type': 'progress', 'step': 'pre-scan', 'text': msg}))
        prompt = "{}\n\nPre-scan findings:\n{}\n\nGitHub repo ({}) code:\n{}\n\nProvide a comprehensive security audit.".format(
            SYSTEM_PROMPT, pre, url.rsplit('/', 1)[-1], combined)
        yield 'data: {}\n\n'.format(json.dumps({'type': 'progress', 'step': 'ai', 'text': 'Running AI analysis on repository...'}))
        full = ""
        _stream_fn = _stream_openrouter if API_PROVIDER == "openrouter" else _stream_ollama
        model_name = FREE_MODELS.get(ACTIVE_MODEL, {}).get("id", "openrouter/free") if API_PROVIDER == "openrouter" else OLLAMA_MODEL
        for event in _stream_fn(model_name, prompt):
            if event.startswith("data: "):
                try:
                    edata = json.loads(event[6:])
                    if 'token' in edata:
                        full += edata['token']
                        yield 'data: {}\n\n'.format(json.dumps({'type': 'token', 'text': edata['token']}))
                        continue
                    elif 'error' in edata:
                        yield 'data: {}\n\n'.format(json.dumps({'type': 'error', 'message': edata['error']}))
                        return
                except json.JSONDecodeError:
                    logger.warning(f"SSE stream: JSON decode error in event: {event[:200]}")
                    continue
            yield event
        if not full or len(full.strip()) < 20:
            yield 'data: {}\n\n'.format(json.dumps({'type': 'error', 'message': 'The AI model returned an empty response. Please try again.'}))
            return
        yield 'data: {}\n\n'.format(json.dumps({'type': 'final', 'report': full}))

    return Response(stream_with_context(gen()), mimetype='text/event-stream', headers={
        'X-Accel-Buffering': 'no', 'Cache-Control': 'no-cache',
    })


@api_bp.route('/history', methods=['GET'])
@requires_auth
def api_history_list():
    code = session.get('access_code', '')
    uid = current_user.id if current_user.is_authenticated else None
    if uid:
        items = get_history(user_id=uid)
    else:
        items = get_history(code=code)
    return jsonify({"items": items})


@api_bp.route('/history/<int:history_id>', methods=['GET'])
@requires_auth
def api_history_detail(history_id):
    code = session.get('access_code', '')
    uid = current_user.id if current_user.is_authenticated else None
    if uid:
        item = get_history_item(history_id, user_id=uid)
    else:
        item = get_history_item(history_id, code=code)
    if not item:
        return jsonify({"error": "Not found"}), 404
    return jsonify(item)


@api_bp.route('/history', methods=['POST'])
@requires_auth
def api_history_save():
    data = request.get_json()
    if not data or 'report' not in data:
        return jsonify({"error": "Field 'report' is required"}), 400
    code = session.get('access_code', '')
    title = data.get('title', 'Audit ' + time.strftime('%Y-%m-%d %H:%M'))
    report = data['report']
    snippet = report[:500]
    uid = current_user.id if current_user.is_authenticated else None
    save_history(code, title, snippet, report, data.get('severity_counts', ''), user_id=uid)
    return jsonify({"success": True})


@api_bp.route('/quota', methods=['GET'])
@requires_auth
def api_quota():
    code = session.get('access_code', '')
    if current_user.is_authenticated:
        reset_credits_if_needed(current_user)
        return jsonify({"allowed": "monthly", "remaining": current_user.credits,
                        "used": MONTHLY_FREE_CREDITS - current_user.credits,
                        "plan": current_user.plan})
    return jsonify(check_quota(code))


@api_bp.route('/gas', methods=['POST'])
@rate_limit(10)
@require_api_key
def api_gas():
    data = request.get_json()
    if not data or 'code' not in data:
        return jsonify({"error": "Field 'code' is required"}), 400
    from gas_profiler import estimate_gas
    from gas_analysis import analyze_gas, estimate_gas_savings
    code = truncate_code(data['code'])
    gas_report = estimate_gas(code)
    static_analysis = analyze_gas(code)
    savings = estimate_gas_savings(static_analysis)
    return jsonify({
        "gas_report": gas_report,
        "static_analysis": static_analysis,
        "savings_usd": savings,
    })


@api_bp.route('/knowledge/ingest', methods=['POST'])
@rate_limit(5)
@require_api_key
def api_knowledge_ingest():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    f = request.files['file']
    if not f.filename.lower().endswith('.pdf'):
        return jsonify({"error": "Only PDF files accepted"}), 400
    f.seek(0, 2)
    size = f.tell()
    f.seek(0)
    if size > 5 * 1024 * 1024:
        return jsonify({"error": "File too large. Maximum size is 5MB."}), 400
    try:
        from pypdf import PdfReader
        from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
        def _read_pdf():
            reader = PdfReader(f)
            text = ""
            for page in reader.pages:
                text += page.extract_text() or ""
            return reader, text
        with ThreadPoolExecutor(max_workers=1) as pool:
            try:
                fut = pool.submit(_read_pdf)
                reader, text = fut.result(timeout=30)
            except FuturesTimeout:
                return jsonify({"error": "PDF processing timed out (max 30s)"}), 408
        if not text.strip():
            return jsonify({"error": "No extractable text found in PDF"}), 400
        from agents.pipeline import _kb_manager
        kb = _kb_manager.kb
        if kb:
            title = f.filename.rsplit('.', 1)[0]
            kb.add_knowledge_entry(title=title, content=text, source=title)
            return jsonify({"success": True, "pages": len(reader.pages), "chars": len(text)})
        return jsonify({"error": "Knowledge base not available"}), 500
    except ImportError:
        return jsonify({"error": "pypdf not installed. Run: pip install pypdf"}), 500
    except Exception as e:
        logger.exception("Internal error")
        return jsonify({"error": "An internal error occurred"}), 500


@api_bp.route('/analyze/project', methods=['POST'])
@rate_limit(5)
@require_api_key
def api_analyze_project():
    ensure_report_dir()
    if 'project' not in request.files or not request.files['project'].filename:
        return jsonify({"error": "No project ZIP uploaded"}), 400
    import tempfile
    import zipfile
    f = request.files['project']
    entry_contract = request.form.get('entry_contract', '')
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
    try:
        f.save(tmp.name)
        tmp.close()
        sol_files = []
        with zipfile.ZipFile(tmp.name, 'r') as zf:
            for name in zf.namelist():
                if name.lower().endswith(('.sol', '.vy', '.move')):
                    raw = zf.read(name)
                    code = raw[:8000].decode('utf-8', errors='replace')
                    sol_files.append((name, code))
        if not sol_files:
            return jsonify({"error": "No Solidity/Vyper/Move files found in ZIP"}), 400
        entry_code = ""
        lib_code = ""
        for path, code in sol_files[:20]:
            is_entry = entry_contract and entry_contract.lower() in path.lower()
            if is_entry or (not entry_code and not entry_contract):
                entry_code = code[:4000]
            else:
                lib_code += "\n\n// File: {}\n{}".format(path, code[:1500])
        combined = entry_code + lib_code
        combined = combined[:8000]

        def generate():
            from agents.llm_client import _stream_ollama, _stream_openrouter
            from agents.prompts import SYSTEM_PROMPT
            from config import API_PROVIDER, ACTIVE_MODEL, FREE_MODELS, OLLAMA_MODEL
            pre = run_pre_scan(combined)
            prompt = "{}\n\nPre-scan findings:\n{}\n\nProject files ({}):\n{}\n\nProvide a comprehensive security audit of this project. Focus on the entry contract.".format(
                SYSTEM_PROMPT, pre, len(sol_files), combined)
            msg = 'Pre-scan complete: {} files found'.format(len(sol_files))
            yield 'data: {}\n\n'.format(json.dumps({'type': 'progress', 'step': 'pre-scan', 'text': msg}))
            yield 'data: {}\n\n'.format(json.dumps({'type': 'progress', 'step': 'ai', 'text': 'Running AI analysis across project...'}))
            full = ""
            _stream_fn = _stream_openrouter if API_PROVIDER == "openrouter" else _stream_ollama
            model_name = FREE_MODELS.get(ACTIVE_MODEL, {}).get("id", "openrouter/free") if API_PROVIDER == "openrouter" else OLLAMA_MODEL
            for event in _stream_fn(model_name, prompt):
                if event.startswith("data: "):
                    try:
                        edata = json.loads(event[6:])
                        if 'token' in edata:
                            full += edata['token']
                            yield 'data: {}\n\n'.format(json.dumps({'type': 'token', 'text': edata['token']}))
                            continue
                        elif 'error' in edata:
                            yield 'data: {}\n\n'.format(json.dumps({'type': 'error', 'message': edata['error']}))
                            return
                    except json.JSONDecodeError:
                        logger.warning(f"SSE stream: JSON decode error in event: {event[:200]}")
                        continue
                yield event
            if not full or len(full.strip()) < 20:
                yield 'data: {}\n\n'.format(json.dumps({'type': 'error', 'message': 'The AI model returned an empty response. Please try again.'}))
                return
            yield 'data: {}\n\n'.format(json.dumps({'type': 'final', 'report': full}))

        return Response(stream_with_context(generate()), mimetype='text/event-stream', headers={
            'X-Accel-Buffering': 'no', 'Cache-Control': 'no-cache',
        })
    except zipfile.BadZipFile:
        return jsonify({"error": "Invalid ZIP file"}), 400
    except Exception as e:
        logger.exception("Project analysis failed")
        return jsonify({"error": "An internal error occurred"}), 500
    finally:
        try: os.unlink(tmp.name)
        except: pass


@api_bp.route('/analyze/malware', methods=['POST'])
@rate_limit(10)
@require_api_key
def api_malware_scan():
    data = request.get_json()
    if not data or 'code' not in data:
        return jsonify({"error": "Field 'code' is required"}), 400
    from analyzers.malware_scanner import scan
    result = scan(data['code'], data.get('bytecode', ''))
    return jsonify(result)


@api_bp.route('/analyze/fuzz', methods=['POST'])
@rate_limit(5)
@require_api_key
def api_fuzz():
    data = request.get_json()
    if not data or 'code' not in data:
        return jsonify({"error": "Field 'code' is required"}), 400
    code = data['code'][:4000]
    try:
        from agents.llm_client import call_model
        from config import OLLAMA_MODEL
        prompt = "Generate a Foundry fuzz test for this Solidity contract. Include invariant tests and edge cases. Return ONLY the Solidity code in a code block.\n\n```solidity\n{}\n```".format(code)
        fuzz = call_model(OLLAMA_MODEL, prompt)
        return jsonify({"fuzz_test": fuzz})
    except Exception as e:
        logger.exception("Internal error")
        return jsonify({"error": "An internal error occurred"}), 500


@api_bp.route('/plugins', methods=['GET'])
@require_api_key
def api_plugins_list():
    from analyzers.plugin_system import list_plugins
    return jsonify({"plugins": list_plugins()})


@api_bp.route('/plugins/run', methods=['POST'])
@rate_limit(10)
@require_api_key
def api_plugins_run():
    data = request.get_json()
    if not data or 'code' not in data:
        return jsonify({"error": "Field 'code' is required"}), 400
    from analyzers.plugin_system import run_plugins
    from dataclasses import asdict
    results = run_plugins(data['code'])
    return jsonify({"results": [asdict(r) for r in results]})


@api_bp.route('/analyze/fix', methods=['POST'])
@rate_limit(5)
@require_api_key
def api_fix():
    data = request.get_json()
    if not data or 'code' not in data:
        return jsonify({"error": "Field 'code' is required"}), 400
    code = data['code'][:4000]
    report = (data.get('report') or '')[:2000]
    try:
        from agents.llm_client import call_model
        from config import OLLAMA_MODEL
        prompt = "You are a Solidity security fixer. Given the vulnerable code and audit findings, provide the FIXED version of the code.\n\nVulnerable code:\n```solidity\n{}\n```\n\nAudit findings:\n{}\n\nReturn ONLY the fixed Solidity code in a code block.".format(code, report)
        fix = call_model(OLLAMA_MODEL, prompt)
        return jsonify({"fix": fix})
    except Exception as e:
        logger.exception("Internal error")
        return jsonify({"error": "An internal error occurred"}), 500


@api_bp.route('/hackerone', methods=['GET', 'POST'])
@rate_limit(10)
@require_api_key
def api_hackerone():
    if request.method == 'GET':
        return jsonify({"status": "ready", "description": "Submit audit reports to HackerOne format"})
    data = request.get_json()
    if not data or 'report' not in data:
        return jsonify({"error": "Field 'report' is required"}), 400
    label = data.get('label', 'Smart Contract')
    code = data.get('code', '')
    if _has_h1:
        h1_report = _h1_report_func(data['report'], code, label)
        return jsonify({"report": h1_report})
    else:
        from agents import generate_hackerone_report
        h1_report = generate_hackerone_report(data['report'], code, label)
        return jsonify({"report": h1_report})


@api_bp.route('/grep-arsenal', methods=['POST'])
@rate_limit(20)
@require_api_key
def api_grep_arsenal():
    data = request.get_json()
    if not data or 'code' not in data:
        return jsonify({"error": "Field 'code' is required"}), 400
    if not _has_grep:
        return jsonify({"error": "Grep arsenal not available"}), 500
    summary = _grep_arsenal.get_summary(data['code'])
    return jsonify({"summary": summary})


@api_bp.route('/mcp-scan', methods=['POST'])
@rate_limit(20)
@require_api_key
def api_mcp_scan():
    data = request.get_json()
    if not data or 'code' not in data:
        return jsonify({"error": "Field 'code' is required"}), 400
    if not _has_mcp:
        return jsonify({"error": "MCP scanner not available"}), 500
    result = _mcp_int.analyze_contract(data['code'])
    return jsonify(result)


@api_bp.route('/ai-detect', methods=['POST'])
@rate_limit(20)
@require_api_key
def api_ai_detect():
    data = request.get_json()
    if not data or 'code' not in data:
        return jsonify({"error": "Field 'code' is required"}), 400
    if not _has_ai:
        return jsonify({"error": "AI detector not available"}), 500
    ai_check = _ai_scan.detect_ai_generated(data['code'])
    vulns = _ai_scan.check_ai_vulnerabilities(data['code'])
    return jsonify({"ai_likely": ai_check, "vulnerabilities": vulns})


@api_bp.route('/zksync-analyze', methods=['POST'])
@rate_limit(20)
@require_api_key
def api_zksync_analyze():
    data = request.get_json()
    if not data or 'code' not in data:
        return jsonify({"error": "Field 'code' is required"}), 400
    if not _has_zksync:
        return jsonify({"error": "ZKsync analyzer not available"}), 500
    result = _zksync_scan.check_vulnerable_patterns(data['code'])
    return jsonify(result)


@api_bp.route('/poc', methods=['POST'])
@rate_limit(15)
@require_api_key
def api_poc():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body is required"}), 400
    bug_class = data.get('bug_class', 'reentrancy')
    target_addr = data.get('target_addr', '0x...')
    fork_block = data.get('fork_block', 18000000)
    try:
        from hackerone_report import _get_poc_template
        poc = _get_poc_template(bug_class, target_addr, fork_block)
        return jsonify({"poc": poc, "filename": f"ExploitPoC_{bug_class}.t.sol"})
    except ImportError:
        return jsonify({"error": "PoC generator not available"}), 500


@api_bp.route('/analyze/poc', methods=['POST'])
@rate_limit(5)
@require_api_key
def api_generate_poc():
    data = request.get_json()
    if not data or 'report' not in data:
        return jsonify({"error": "Field 'report' is required"}), 400
    report = data['report']
    code = data.get('code', '')
    try:
        from hackerone_report import _extract_findings
        from analyzers.base import Finding
        from proof_generator import generate_poc
        findings = _extract_findings(report)
        target = None
        for f in findings:
            if f.get('severity', '').replace('*', '').strip() in ('Critical', 'High'):
                target = f
                break
        if not target:
            return jsonify({"error": "No Critical or High findings found to generate PoC"}), 400

        finding = Finding(
            agent_name=target.get('name', 'Vulnerability'),
            severity=target.get('severity', 'Critical').replace('*', '').strip(),
            category=target.get('category', 'Unknown'),
            file='source.sol',
            function_name='',
            description=(target.get('description', '') or '')[:500],
            code_snippet=code[:200],
        )
        poc_path = generate_poc(finding, code)
        if poc_path:
            with open(poc_path, 'r') as f:
                poc_code = f.read()
            try:
                os.unlink(poc_path)
            except OSError:
                pass
            return jsonify({"poc": poc_code, "filename": os.path.basename(poc_path)})

        from hackerone_report import _get_poc_template
        cat = (target.get('category', '') or '') or (target.get('name', '') or '')
        poc = _get_poc_template(cat)
        return jsonify({"poc": poc, "filename": f"PoC_{target.get('name', 'vuln').replace(' ', '_')}.t.sol"})

    except ImportError as e:
        return jsonify({"error": f"PoC generator not available: {e}"}), 500
    except Exception as e:
        logger.exception("PoC generation failed")
        return jsonify({"error": f"PoC generation failed: {e}"}), 500


@api_bp.route('/sarif', methods=['POST'])
@rate_limit(10)
@require_api_key
def api_sarif():
    data = request.get_json()
    if not data or 'report' not in data:
        return jsonify({"error": "Field 'report' is required"}), 400
    if not _has_sarif:
        return jsonify({"error": "SARIF exporter not available"}), 500
    try:
        sarif = report_to_sarif(data['report'], data.get('code', ''), data.get('label', 'contract'))
        return Response(sarif, mimetype='application/json',
                        headers={'Content-Disposition': 'attachment; filename=audit.sarif'})
    except Exception as e:
        logger.exception("Internal error")
        return jsonify({"error": "An internal error occurred"}), 500
