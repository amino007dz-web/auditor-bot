"""
Pure business logic layer — no input(), print(), or I/O side effects.
All methods return data; presentation is handled by callers (main.py, web_ui.py).
"""
import json
import logging
import os
import sys
from typing import Dict, List, Optional, Tuple

from agents import audit, self_critique, cache_stats, run_parallel
from multiaudit import multi_audit, DEFAULT_TEAM
from hierarchical_audit import hierarchical_audit
from diff_audit import run_diff_audit, compute_diff
from static_analysis import (
    analyze_opcodes, analyze_storage_single,
    analyze_inheritance, generate_combined_report,
    _extract_contracts_from_code,
)
from config import REPORT_DIR, KB_ENABLED, KB_DB_PATH, FREE_MODELS

logger = logging.getLogger(__name__)


class AuditService:
    """Encapsulates all audit operations. No print/input — returns data."""

    REPORT_DIR: str = REPORT_DIR

    @staticmethod
    def save_report(filename: str, content: str) -> str:
        os.makedirs(AuditService.REPORT_DIR, exist_ok=True)
        path = os.path.join(AuditService.REPORT_DIR, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    @staticmethod
    def load_code(path: str) -> Optional[str]:
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return f.read()
        except Exception as e:
            logger.error(f"Failed to read file: {e}")
            return None

    @staticmethod
    def run_audit(code: str) -> str:
        return audit(code)

    @staticmethod
    def run_critique(code: str) -> Tuple[str, str]:
        initial = audit(code)
        critique = self_critique(initial, code, "english")
        return initial, critique

    @staticmethod
    def run_multi(code: str, team: Optional[List[str]] = None) -> str:
        return multi_audit(code, team)

    @staticmethod
    def run_hierarchical(code: str, protocol: str = "Protocol",
                          focus: str = "",
                          repo_url: str = "") -> str:
        return hierarchical_audit(code, protocol, repo_url, focus=focus)

    @staticmethod
    def run_parallel(code: str, n_workers: int = 3) -> Tuple[str, list]:
        models = list(FREE_MODELS.keys())[:n_workers]
        prompt = f"""You are a smart contract security expert. Analyze the following code and find vulnerabilities:
```solidity
{code[:3000]}
```
Language: English"""
        work_items = [
            {"model_id": FREE_MODELS[m]["id"], "prompt": prompt, "label": m}
            for m in models
        ]
        results = run_parallel(work_items)
        combined = "# Parallel Analysis Report\n\n"
        for label, result, error in results:
            combined += f"\n--- {label} ---\n"
            combined += result or f"Failed: {error}"
            combined += "\n"
        return combined, results

    @staticmethod
    def analyze_opcodes(code: str) -> str:
        return analyze_opcodes(code)

    @staticmethod
    def analyze_storage(code: str) -> str:
        return analyze_storage_single(code)

    @staticmethod
    def analyze_inheritance(code: str) -> str:
        contracts_data = _extract_contracts_from_code(code)
        return analyze_inheritance(code, contracts_data)

    @staticmethod
    def analyze_combined(code: str, name: str = "Contract") -> str:
        return generate_combined_report(code, name)

    @staticmethod
    def analyze_unified(code: str, name: str = "Contract") -> str:
        op = AuditService.analyze_opcodes(code)
        st = AuditService.analyze_storage(code)
        ih = AuditService.analyze_inheritance(code)
        cm = AuditService.analyze_combined(code, name)
        return (f"=== Opcodes ===\n{op}\n\n=== Storage ===\n{st}\n\n"
                f"=== Inheritance ===\n{ih}\n\n=== Combined ===\n{cm}")

    @staticmethod
    def collect_feedback(code: str, label: str = "", report: str = "") -> Tuple[int, str]:
        if not KB_ENABLED:
            return (0, "")
        from knowledge_base import KnowledgeBase
        try:
            kb = KnowledgeBase(KB_DB_PATH)
            sid = kb.start_session(label, code, "auto")
            kb.update_session(sid, report_hash=str(hash(report))[:16])
            kb.close()
            return (sid, label)
        except Exception as e:
            logger.debug(f"Feedback init skipped: {e}")
            return (0, "")

    @staticmethod
    def cache_stats() -> dict:
        return cache_stats()

    @staticmethod
    def kb_stats() -> dict:
        if not KB_ENABLED:
            return {"enabled": False}
        from knowledge_base import KnowledgeBase
        kb = KnowledgeBase(KB_DB_PATH)
        stats = kb.get_stats()
        stats["rankings"] = kb.get_model_rankings()
        kb.close()
        return stats

    @staticmethod
    def run_diff_audit(v1: str, v2: str) -> str:
        return run_diff_audit(v1, v2, "english")

    @staticmethod
    def compute_diff(v1: str, v2: str) -> str:
        diff = compute_diff(v1, v2)
        return diff.summary

    @staticmethod
    def run_external_analyzers(code: str) -> str:
        from external_analyzers import run_external_analyzers as _run_ext, findings_to_text
        findings = _run_ext(code)
        return findings_to_text(findings)

    @staticmethod
    def json_output(report: str, type_name: str, label: str) -> dict:
        data = {"type": type_name, "protocol": label, "report": report}
        AuditService.save_report(f"report_{label}.json",
                                  json.dumps(data, ensure_ascii=False, indent=2))
        return data
