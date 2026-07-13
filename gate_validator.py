"""
4-Gate Validator — third-pass validation adapted from BugHunter.
Each finding must pass all 4 gates before being reported.
"""
import logging
import re
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Known safe names (Gate 1 filter)
_SAFE_NAME_KEYWORDS = [
    "gas optimization", "gas saving", "unused import", "unused variable",
    "typo", "comment", "naming convention", "code style",
    "pragma", "SPDX", "missing event", "named return",
]

# Patterns that indicate the finding is a false positive (Gate 1)
_FP_INDICATORS = [
    "could lead to", "might be", "potentially", "possibly",
    "it is recommended", "best practice", "consider",
    "may result in", "could cause",
]

# Severity downgrade map (Gate 3)
_SEVERITY_DOWNGRADE = {
    "Critical": "High",
    "High": "Medium",
    "Medium": "Low",
    "Low": "Info",
}


def _extract_findings(report: str) -> List[Dict]:
    findings = []
    lines = report.split("\n")
    current: Dict = {}
    for line in lines:
        s = line.strip()
        if s.startswith("- **Name**"):
            if current and current.get("name"):
                findings.append(current)
            current = {"name": s.split(":", 1)[1].strip() if ":" in s else s.replace("**Name**", "").strip()}
        elif s.startswith("- **Severity**") and current:
            sev = s.split(":", 1)[1].strip() if ":" in s else "Medium"
            current["severity"] = sev.rstrip("*")
        elif s.startswith("- **Description**") and current:
            current["description"] = s.split(":", 1)[1].strip() if ":" in s else ""
        elif s.startswith("- **Fix**") and current:
            current["fix"] = s.split(":", 1)[1].strip() if ":" in s else ""
        elif s.startswith("- **PoC**") and current:
            current["poc"] = s.split(":", 1)[1].strip() if ":" in s else ""
    if current and current.get("name"):
        findings.append(current)
    return findings


def _gate1_is_real(finding: Dict, code: str) -> Tuple[bool, str]:
    """Gate 1: Is It Real? — skip safe patterns, vague findings, and non-exploitable issues."""
    name = finding.get("name", "").lower()
    desc = finding.get("description", "").lower()
    combined = name + " " + desc

    for kw in _SAFE_NAME_KEYWORDS:
        if kw in combined:
            return False, f"Known non-vulnerability pattern: '{kw}'"

    for fp in _FP_INDICATORS:
        if fp in combined and "exploit path" not in desc and "steps" not in desc:
            return False, f"Vague language without concrete exploit: '{fp}'"

    if "overall security rating" in name or "gas optimization" in combined:
        if "vulnerability" not in combined:
            return False, "Not a vulnerability finding"

    if not finding.get("description", "").strip():
        return False, "Missing description"

    return True, ""


def _gate2_in_scope(finding: Dict, code: str) -> Tuple[bool, str]:
    """Gate 2: Is It In Scope? — only report genuine security issues."""
    sev = finding.get("severity", "Medium")
    desc = finding.get("description", "").lower()

    if sev == "Info":
        return False, "Info-level findings are excluded from vulnerability list"

    if sev == "Low" and "fix" not in finding:
        return False, "Low severity without suggested fix"

    return True, ""


def _gate3_is_exploitable(finding: Dict) -> Tuple[bool, str]:
    """Gate 3: Is It Exploitable? — must have concrete impact and realistic preconditions."""
    name = finding.get("name", "")
    desc = finding.get("description", "")
    sev = finding.get("severity", "Medium")
    combined = (name + " " + desc).lower()

    if sev in ("Critical", "High"):
        has_impact_words = any(w in combined for w in ["steal", "drain", "loss", "theft", "lock", "freeze", "burn"])
        if not has_impact_words:
            return False, f"No concrete fund loss impact described for {sev} finding"

    has_exploit = any(w in combined for w in ["step", "transaction", "call", "attack", "exploit"])
    if not has_exploit and sev in ("Critical", "High", "Medium"):
        return False, "No exploit path described"

    return True, ""


def _gate4_is_duplicate(finding: Dict, kb_patterns: List[Dict]) -> Tuple[bool, str]:
    """Gate 4: Is It a Duplicate? — check if already in KB."""
    name = finding.get("name", "").lower()
    for p in kb_patterns:
        pname = p.get("name", "").lower()
        if name == pname or name.startswith(pname) or pname.startswith(name):
            return False, f"Duplicate of existing KB pattern: '{p.get('name')}'"
    return True, ""


def validate_finding(finding: Dict, code: str, kb_patterns: Optional[List[Dict]] = None) -> Tuple[bool, Optional[str], str]:
    """Run all 4 gates on a single finding. Returns (passed, downgraded_severity, reason)."""
    passed, reason = _gate1_is_real(finding, code)
    if not passed:
        return False, None, reason

    passed, reason = _gate2_in_scope(finding, code)
    if not passed:
        return False, None, reason

    passed, reason = _gate3_is_exploitable(finding)
    if not passed:
        cur_sev = finding.get("severity", "Medium")
        downgraded = _SEVERITY_DOWNGRADE.get(cur_sev)
        if downgraded:
            return True, downgraded, f"Downgraded from {cur_sev} to {downgraded}: {reason}"
        return False, None, reason

    if kb_patterns:
        passed, reason = _gate4_is_duplicate(finding, kb_patterns)
        if not passed:
            return False, None, reason

    return True, None, ""


def validate_report(report: str, code: str, kb_patterns: Optional[List[Dict]] = None) -> str:
    """Run 4-Gate validation on an entire report. Returns a cleaned report."""
    findings = _extract_findings(report)
    if not findings:
        return report

    removed = []
    downgraded = []
    kept = []

    for f in findings:
        passed, new_sev, reason = validate_finding(f, code, kb_patterns)
        if not passed:
            removed.append((f.get("name", "?"), reason))
            logger.info(f"Gate rejected: {f.get('name')} — {reason}")
        else:
            if new_sev:
                f["severity"] = new_sev
                downgraded.append((f["name"], new_sev, reason))
            kept.append(f)

    if not kept:
        severity_match = re.search(r"### Overall Security Rating:\s*(\S+)", report)
        rating = severity_match.group(1) if severity_match else "N/A"
        header = f"### Overall Security Rating: {rating}\n\nNo vulnerabilities found after validation.\n"
        gas = ""
        gas_match = re.search(r"(### Gas Optimizations.*?)(?=###|$)", report, re.DOTALL)
        if gas_match:
            gas = "\n" + gas_match.group(1)
        return header + gas

    result_lines = []
    in_vuln_section = False
    in_gas_section = False
    kept_names = {f["name"] for f in kept}

    for line in report.split("\n"):
        s = line.strip()
        if s.startswith("- **Name**"):
            name = s.split(":", 1)[1].strip() if ":" in s else s.replace("**Name**", "").strip()
            in_vuln_section = name in kept_names
            in_gas_section = False
        elif s.startswith("### Gas Optimizations"):
            in_vuln_section = False
            in_gas_section = True

        if in_vuln_section or in_gas_section or s.startswith("### Overall") or s.startswith("### Vulnerability") or s.startswith("### Gas"):
            result_lines.append(line)

    result = "\n".join(result_lines)

    if downgraded:
        notes = "\n\n### Validation Notes\n"
        for name, new_sev, reason in downgraded:
            notes += f"- **{name}**: {reason}\n"
        result += notes

    return result


def gate_stats_str(removed: List[Tuple[str, str]], downgraded: List[Tuple[str, str, str]]) -> str:
    lines = []
    for name, reason in removed:
        lines.append(f"  ✗ {name}: {reason}")
    for name, new_sev, reason in downgraded:
        lines.append(f"  ↓ {name} → {new_sev}: {reason}")
    return "\n".join(lines)
