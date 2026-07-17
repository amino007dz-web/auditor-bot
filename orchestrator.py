"""
Shared analysis orchestrator — single dispatch layer used by CLI, Web UI, and API.

Eliminates the duplicated routing logic that previously lived in main.py, web_ui.py,
and api_mode.py by providing a unified entry point for all analysis types.
"""

import logging
from typing import Optional

from audit_service import AuditService
from agents import analyze_code, chunked_audit, self_critique, call_model_with_fallback
from multiaudit import multi_audit
from hierarchical_audit import hierarchical_audit
from static_analysis import (
    analyze_opcodes,
    analyze_storage_single,
    analyze_inheritance,
    generate_combined_report,
    _extract_contracts_from_code,
)
from gas_analysis import analyze_gas
from permission_analysis import analyze_permissions
from external_analyzers import run_external_analyzers, findings_to_text
from diff_audit import run_diff_audit, compute_diff
from auto_poc import validate_with_poc_silent
from config import FREE_MODELS

logger = logging.getLogger(__name__)

svc = AuditService()


def dispatch_analysis(
    code: str,
    analysis_type: str = "audit",
    protocol_name: str = "Protocol",
    focus: str = "",
    repo_url: str = "",
    name: str = "Contract",
    team: Optional[list[str]] = None,
) -> str:
    """Route a code analysis request to the correct handler based on type."""
    if analysis_type == "opcodes":
        return analyze_opcodes(code)

    if analysis_type == "storage":
        return analyze_storage_single(code)

    if analysis_type == "inheritance":
        contracts_data = _extract_contracts_from_code(code)
        return analyze_inheritance(code, contracts_data)

    if analysis_type == "combined":
        return generate_combined_report(code, name)

    if analysis_type == "gas":
        return analyze_gas(code)

    if analysis_type == "permissions":
        return analyze_permissions(code)

    if analysis_type == "chunked":
        return chunked_audit(code)

    if analysis_type == "external":
        ext = run_external_analyzers(code)
        return findings_to_text(ext)

    if analysis_type == "autopoc":
        initial = analyze_code(code)
        critique = self_critique(initial, code)
        return validate_with_poc_silent(critique, code)

    if analysis_type == "multi":
        return multi_audit(code, team)

    if analysis_type == "hierarchical":
        return hierarchical_audit(code, protocol_name, repo_url, focus=focus)

    return analyze_code(code)


def run_parallel_analysis(
    code: str,
    n_workers: int = 3,
) -> tuple[str, list]:
    """Run parallel analysis using multiple models."""
    from agents import run_parallel as _run_parallel

    models = list(FREE_MODELS.keys())[:n_workers]
    prompt = (
        f"You are a smart contract security expert. "
        f"Analyze the following code and find vulnerabilities:\n"
        f"```solidity\n{code[:3000]}\n```\n"
        f"Language: English"
    )
    work_items = [
        {"model_id": FREE_MODELS[m]["id"], "prompt": prompt, "label": m}
        for m in models
    ]
    results = _run_parallel(work_items)

    combined = "# Parallel Analysis Report\n\n"
    for label, result, error in results:
        combined += f"\n--- {label} ---\n"
        combined += result or f"Failed: {error}"
        combined += "\n"
    return combined, results


def save_report(report: str, filename: str) -> str:
    """Save report to disk via AuditService."""
    return svc.save_report(filename, report)
