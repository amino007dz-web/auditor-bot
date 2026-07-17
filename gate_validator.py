"""
7-Question Gate Validator — third-pass validation adapted from web3-triage-report SKILL.
Each finding must pass all 7 questions before being reported.
"""
import logging
import re
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Known safe names (Q1 filter)
_SAFE_NAME_KEYWORDS = [
    "gas optimization", "gas saving", "unused import", "unused variable",
    "typo", "comment", "naming convention", "code style",
    "pragma", "SPDX", "missing event", "named return",
]

# Patterns that indicate vague / non-exploitable (Q1)
_FP_INDICATORS = [
    "could lead to", "might be", "potentially", "possibly",
    "it is recommended", "best practice", "consider",
    "may result in", "could cause",
]

# Severity downgrade map
_SEVERITY_DOWNGRADE = {
    "Critical": "High",
    "High": "Medium",
    "Medium": "Low",
    "Low": "Info",
}

# Accepted impact tiers (Q2) — from Immunefi standard
_ACCEPTED_IMPACTS = {
    "Critical": ["direct theft", "permanent freezing", "protocol insolvency"],
    "High": ["theft of unclaimed yield", "permanent freezing of unclaimed yield", "temporary freezing"],
    "Medium": ["unable to operate due to lack of token funds", "griefing"],
    "Low": ["fails to deliver promised returns", "best practice"],
}

# Centralization signals (Q4)
_CENTRALIZATION_SIGNALS = [
    "admin", "onlyowner", "onlyRole(", "privileged", "centralization",
    "timelock", "governance", "multisig",
]


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
        elif s.startswith("- **Impact**") and current:
            current["impact"] = s.split(":", 1)[1].strip() if ":" in s else ""
        elif s.startswith("- **Category**") and current:
            current["category"] = s.split(":", 1)[1].strip() if ":" in s else ""
    if current and current.get("name"):
        findings.append(current)
    return findings


def _has_exploit_path(combined: str) -> bool:
    """Check if the finding has a concrete step-by-step exploit path."""
    return any(w in combined for w in [
        "step", "transaction", "call", "attack", "exploit",
        "1.", "2.", "3.", "first", "then", "sequence",
        "flash", "repay", "borrow", "swap",
    ])


def _has_impact_words(combined: str, sev: str) -> bool:
    """Check if the finding describes concrete impact for its severity."""
    if sev in ("Critical", "High"):
        return any(w in combined for w in [
            "steal", "drain", "loss", "theft", "lock", "freeze",
            "burn", "insolvent", "bad debt",
        ])
    return True


def _has_roi_assessment(combined: str) -> bool:
    """Check if the finding includes profit vs cost analysis."""
    return any(w in combined for w in [
        "profit", "cost", "gas", "capital", "spend", "gain",
        "roi", "returns", "economics",
    ])


def _is_centralization_risk(finding: Dict) -> bool:
    """Check if the finding is just 'admin can drain' which is usually OOS."""
    name = finding.get("name", "").lower()
    desc = finding.get("description", "").lower()
    combined = name + " " + desc
    signals = sum(1 for s in _CENTRALIZATION_SIGNALS if s in combined)
    if signals >= 2 and "without admin" not in combined and "non-admin" not in combined:
        if "frontrun" not in combined and "unprivileged" not in combined:
            return True
    return False


def _is_known_public(finding: Dict) -> bool:
    """Q7: Check if finding is already public (known issue)."""
    name = finding.get("name", "").lower()
    desc = finding.get("description", "").lower()
    combined = name + " " + desc
    known_indicators = [
        "acknowledged", "known issue", "won't fix", "risk accepted",
        "previously reported", "prior audit", "disclosed",
    ]
    for ind in known_indicators:
        if ind in combined:
            return True
    return False


# --- 7 Gates ---

def _gate_q1_exploit_path(finding: Dict, code: str) -> Tuple[bool, str]:
    """Q1: Can an attacker use this RIGHT NOW, step by step?
    Must have concrete function calls, parameters, and result description."""
    name = finding.get("name", "").lower()
    desc = finding.get("description", "").lower()
    combined = name + " " + desc

    for kw in _SAFE_NAME_KEYWORDS:
        if kw in combined:
            return False, f"Known non-vulnerability pattern: '{kw}'"

    for fp in _FP_INDICATORS:
        if fp in combined and not _has_exploit_path(combined):
            return False, f"Vague language without concrete exploit: '{fp}'"

    if "overall security rating" in name or "gas optimization" in combined:
        if "vulnerability" not in combined:
            return False, "Not a vulnerability finding"

    if not finding.get("description", "").strip():
        return False, "Missing description"

    # Require exploit path for Critical/High/Medium
    sev = finding.get("severity", "Medium")
    if sev in ("Critical", "High", "Medium"):
        if not _has_exploit_path(combined):
            return False, "No concrete exploit path — cannot complete steps 2-3 of attack template"

    # Check for fill-in-the-template capability
    if sev in ("Critical", "High"):
        has_setup = any(w in combined for w in ["setup", "need", "require", "precondition", "prerequisite"])
        has_call = _has_exploit_path(combined)
        has_result = _has_impact_words(combined, sev)
        if not (has_setup and has_call and has_result):
            return False, "Missing one of: preconditions, exploit sequence, or concrete result"

    return True, ""


def _gate_q2_impact_in_scope(finding: Dict, code: str) -> Tuple[bool, str]:
    """Q2: Is the impact in the program's accepted impact list?
    Match the finding's impact to one of the Immunefi standard tiers."""
    sev = finding.get("severity", "Medium")
    desc = finding.get("description", "").lower()
    name = finding.get("name", "").lower()
    combined = name + " " + desc

    if sev == "Info":
        return False, "Info-level findings are excluded from vulnerability list"

    if sev == "Low" and "fix" not in finding:
        return False, "Low severity without suggested fix"

    # Check if impact matches accepted categories
    expected_keywords = _ACCEPTED_IMPACTS.get(sev, [])
    if sev in ("Critical", "High"):
        if not any(kw in combined for kw in expected_keywords):
            if not _has_impact_words(combined, sev):
                return False, f"Impact doesn't match expected {sev} categories: {expected_keywords}"

    return True, ""


def _gate_q3_root_contract_scope(finding: Dict, code: str) -> Tuple[bool, str]:
    """Q3: Is the root cause in an in-scope contract?
    Flag if the issue is in external dependencies (Aave, Uniswap, OpenZeppelin)."""
    name = finding.get("name", "").lower()
    desc = finding.get("description", "").lower()
    combined = name + " " + desc

    external_deps = [
        "openzeppelin", "aave", "uniswap", "compound", "maker",
        "chainlink", "pyth", "wormhole", "layerzero",
    ]
    for dep in external_deps:
        if dep in combined:
            # Check if it's really about a bug in the dependency vs using it
            if "vulnerability in" in combined or "bug in" in combined or f"{dep} " in combined:
                if "integration" not in combined:
                    return False, f"Root cause appears to be in external dependency ({dep}) — likely OOS"

    return True, ""


def _gate_q4_no_admin_abuse(finding: Dict, code: str) -> Tuple[bool, str]:
    """Q4: Does it require admin/privileged access?
    'Admin can drain' = centralization risk = usually out of scope.
    Check if exploitation works WITHOUT any privileged action."""
    name = finding.get("name", "").lower()
    desc = finding.get("description", "").lower()
    combined = name + " " + desc

    if _is_centralization_risk(finding):
        admin_phrases = ["admin can", "owner can", "governance can", "privileged"]
        admin_mentioned = any(p in combined for p in admin_phrases)
        non_admin_indicated = any(p in combined for p in ["non-admin", "unprivileged", "anyone can", "any user"])

        if admin_mentioned and not non_admin_indicated:
            return False, "Requires admin/privileged access — centralization risk typically OOS"

    return True, ""


def _gate_q5_not_known_acknowledged(finding: Dict, kb_patterns: List[Dict]) -> Tuple[bool, str]:
    """Q5: Is this already known/acknowledged in prior audits or KB?"""
    name = finding.get("name", "").lower()
    for p in kb_patterns:
        pname = p.get("name", "").lower()
        if name == pname or name.startswith(pname) or pname.startswith(name):
            return False, f"Duplicate of existing KB pattern: '{p.get('name')}'"
    return True, ""


def _gate_q6_economic_viable(finding: Dict, code: str) -> Tuple[bool, str]:
    """Q6: Is the economic attack viable? Profit > cost?
    For Critical/High findings, must show ROI analysis."""
    sev = finding.get("severity", "Medium")
    name = finding.get("name", "").lower()
    desc = finding.get("description", "").lower()
    combined = name + " " + desc

    if sev in ("Critical", "High"):
        if not _has_roi_assessment(combined):
            downgraded = _SEVERITY_DOWNGRADE.get(sev)
            if downgraded:
                return True, downgraded, f"Downgraded from {sev} to {downgraded}: no economic viability assessment"
            return False, None, "No economic viability assessment for {sev} finding"

    return True, None, ""


def _gate_q7_not_public(finding: Dict) -> Tuple[bool, str]:
    """Q7: Is this already public / disclosed?"""
    if _is_known_public(finding):
        return False, "Already known/acknowledged/public — not a new finding"
    return True, ""


def validate_finding(finding: Dict, code: str, kb_patterns: Optional[List[Dict]] = None) -> Tuple[bool, Optional[str], str]:
    """Run all 7 gates on a single finding. Returns (passed, downgraded_severity, reason)."""
    # Q1: Is It Real? — exploit path required
    passed, reason = _gate_q1_exploit_path(finding, code)
    if not passed:
        return False, None, reason

    # Q2: Impact In Scope?
    passed, reason = _gate_q2_impact_in_scope(finding, code)
    if not passed:
        return False, None, reason

    # Q3: Root Cause In Scope Contract?
    passed, reason = _gate_q3_root_contract_scope(finding, code)
    if not passed:
        return False, None, reason

    # Q4: No Admin Abuse Required?
    passed, reason = _gate_q4_no_admin_abuse(finding, code)
    if not passed:
        return False, None, reason

    # Q5: Not Duplicate?
    if kb_patterns:
        passed, reason = _gate_q5_not_known_acknowledged(finding, kb_patterns)
        if not passed:
            return False, None, reason

    # Q6: Economic Viability (Gate 3 in original — exploitability check)
    sev = finding.get("severity", "Medium")
    name = finding.get("name", "").lower()
    desc = finding.get("description", "").lower()
    combined = name + " " + desc

    if sev in ("Critical", "High"):
        if not _has_impact_words(combined, sev):
            cur_sev = finding.get("severity", "Medium")
            downgraded = _SEVERITY_DOWNGRADE.get(cur_sev)
            if downgraded:
                return True, downgraded, f"Downgraded from {cur_sev} to {downgraded}: no concrete fund loss impact"
            return False, None, f"No concrete fund loss impact described for {sev} finding"

        if not _has_exploit_path(combined):
            cur_sev = finding.get("severity", "Medium")
            downgraded = _SEVERITY_DOWNGRADE.get(cur_sev)
            if downgraded:
                return True, downgraded, f"Downgraded from {cur_sev} to {downgraded}: no exploit path"
            return False, None, "No exploit path described"

    # Q7: Not Already Public?
    passed, reason = _gate_q7_not_public(finding)
    if not passed:
        return False, None, reason

    return True, None, ""


def validate_report(report: str, code: str, kb_patterns: Optional[List[Dict]] = None) -> str:
    """Run 7-Question Gate validation on an entire report. Returns a cleaned report."""
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
        header = "### Overall Security Rating: A+\n\nNo vulnerabilities found after validation.\n"
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
