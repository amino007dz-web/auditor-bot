import logging
import re
import os
from typing import List, Optional
from dataclasses import dataclass

from analyzers.base import Finding
from proof_generator import generate_poc, run_foundry_test, PROOFS_DIR

logger = logging.getLogger(__name__)

@dataclass
class ParsedCritical:
    agent_name: str
    description: str


def _parse_critical_findings(report: str) -> List[ParsedCritical]:
    findings = []
    lines = report.split("\n")
    capturing = False
    current: Optional[ParsedCritical] = None
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[Critical") or stripped.upper().startswith("[CRITICAL"):
            if current:
                findings.append(current)
            label = stripped.split("]")[0].lstrip("[").strip()
            desc_start = stripped.find("]")
            desc = stripped[desc_start + 1:].strip() if desc_start != -1 else ""
            current = ParsedCritical(agent_name=label, description=desc)
            capturing = True
        elif capturing and current:
            if re.match(r"^\s*\[?(High|Medium|Low|Info)\b", stripped):
                findings.append(current)
                current = None
                capturing = False
            elif stripped:
                current.description += "\n" + stripped
    if current:
        findings.append(current)
    return findings


def _create_finding_from_parsed(p: ParsedCritical, code: str) -> Optional[Finding]:
    if not p.agent_name or len(p.description) < 10:
        return None
    return Finding(
        agent_name=p.agent_name,
        severity="Critical",
        category="Auto-PoC",
        file="source.sol",
        function_name=p.agent_name.split(".")[-1] if "." in p.agent_name else "",
        description=p.description[:500],
        code_snippet=code[:200],
    )


def _adjust_report(report: str, proved: List[str], disproved: List[str]) -> str:
    lines = report.split("\n")
    adjusted = []
    for line in lines:
        stripped = line.strip()
        modified = False
        for name in proved:
            if name in stripped and stripped.startswith("[Critical"):
                adjusted.append(line.replace("[Critical", "[Critical ✅ Proved"))
                modified = True
                break
        if not modified:
            for name in disproved:
                if name in stripped and stripped.startswith("[Critical"):
                    adjusted.append(line.replace("[Critical", "[Info] ❌ False Positive"))
                    modified = True
                    break
        if not modified:
            adjusted.append(line)
    return "\n".join(adjusted)


def validate_with_poc(report: str, code: str) -> str:
    parsed = _parse_critical_findings(report)
    if not parsed:
        logger.info("auto_poc: no Critical findings to validate")
        return report

    logger.info(f"auto_poc: validating {len(parsed)} Critical finding(s) with PoC")

    proved = []
    disproved = []

    for p in parsed:
        finding = _create_finding_from_parsed(p, code)
        if not finding:
            logger.debug(f"auto_poc: skipped '{p.agent_name}' — insufficient data")
            continue

        poc_path = generate_poc(finding, code)
        if not poc_path:
            logger.warning(f"auto_poc: PoC generation failed for '{p.agent_name}' — keeping as Critical")
            continue

        try:
            result = run_foundry_test(poc_path, use_docker=True)
            if result["passed"]:
                logger.info(f"auto_poc: ✅ PoC PASSED for '{p.agent_name}' — vulnerability confirmed")
                proved.append(p.agent_name)
            else:
                logger.info(f"auto_poc: ❌ PoC FAILED for '{p.agent_name}' — likely false positive, downgrading to Info")
                disproved.append(p.agent_name)
        finally:
            if os.path.exists(poc_path):
                os.unlink(poc_path)

    if disproved or proved:
        report = _adjust_report(report, proved, disproved)

    critical_count = len(parsed)
    proved_count = len(proved)
    disproved_count = len(disproved)
    summary = (
        f"\n\n---\n### Auto-PoC Validation\n"
        f"- Critical findings validated: {critical_count}\n"
        f"- ✅ Proved (confirmed): {proved_count}\n"
        f"- ❌ False positives (downgraded to Info): {disproved_count}\n"
    )
    report += summary
    return report


def validate_with_poc_silent(report: str, code: str) -> str:
    try:
        return validate_with_poc(report, code)
    except Exception as e:
        logger.error(f"auto_poc: validation failed — {e}")
        report += (
            f"\n\n---\n### Auto-PoC Validation\n"
            f"- ❌ Auto-PoC validation failed due to an internal error.\n"
            f"- Findings are reported as-is without proof verification.\n"
        )
        return report