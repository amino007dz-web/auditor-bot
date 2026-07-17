"""Batch Audit - scan entire folder with multiple contracts."""
import os
import sys
import json
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(__file__))
from agents import analyze_code

logger = logging.getLogger(__name__)

EXTENSIONS = {".sol": "solidity", ".move": "move", ".cl": "chialisp", ".vy": "vyper"}


def find_contracts(root_dir: str, max_files: int = 200) -> list[dict[str, str]]:
    """Find all Solidity/Move/Chialisp contracts in a directory."""
    contracts = []
    for dirpath, _, filenames in os.walk(root_dir):
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if ext in EXTENSIONS:
                contracts.append({
                    "path": os.path.join(dirpath, fn),
                    "name": fn,
                    "lang": EXTENSIONS[ext],
                })
                if len(contracts) >= max_files:
                    return contracts
    return contracts


def audit_single(item: dict) -> dict:
    """Audit a single contract."""
    try:
        with open(item["path"], "r", encoding="utf-8", errors="replace") as f:
            code = f.read()
        if len(code) < 10:
            return {"file": item["name"], "status": "skipped", "reason": "empty"}
        result = analyze_code(code)
        return {"file": item["name"], "status": "done", "result": result}
    except Exception as e:
        logger.warning(f"  Failed {item['name']}: {e}")
        return {"file": item["name"], "status": "error", "reason": str(e)}


def batch_audit(root_dir: str, max_workers: int = 4) -> dict:
    """Audit all contracts in a directory in parallel."""
    contracts = find_contracts(root_dir)
    if not contracts:
        return {"total": 0, "results": [], "message": "No contracts found"}

    logger.info(f"batch_audit: {len(contracts)} contracts — {max_workers} workers")
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(audit_single, c): c for c in contracts}
        for f in as_completed(futures):
            results.append(f.result())

    # Save summary
    summary = {
        "total": len(results),
        "done": sum(1 for r in results if r["status"] == "done"),
        "errors": sum(1 for r in results if r["status"] == "error"),
        "skipped": sum(1 for r in results if r["status"] == "skipped"),
        "results": results,
        "timestamp": time.time(),
    }

    # Save JSON report
    out = os.path.join(os.path.dirname(__file__), "reports", "batch_summary.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    # Save text report
    lines = [f"=== Batch Audit Report ===",
             f"Total: {summary['total']} | Done: {summary['done']} | Errors: {summary['errors']} | Skipped: {summary['skipped']}",
             ""]
    for r in results:
        status = "✅" if r["status"] == "done" else "❌" if r["status"] == "error" else "⏭"
        lines.append(f"{status} {r['file']} — {r['status']}")
        if r["status"] == "done":
            lines.append(r["result"][:1000])
            lines.append("---")
    txt = "\n".join(lines)
    txt_dir = os.path.join(os.path.dirname(__file__), "reports")
    os.makedirs(txt_dir, exist_ok=True)
    with open(os.path.join(txt_dir, f"batch_{int(time.time())}.txt"), "w", encoding="utf-8") as f:
        f.write(txt)

    return summary
