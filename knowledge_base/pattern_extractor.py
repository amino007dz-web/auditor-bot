"""
Pattern Extractor — parses AI audit reports to extract structured vulnerability data
and stores it in the Knowledge Base for future reference.
"""
import logging
import re
from typing import Dict, List, Optional, Tuple

from knowledge_base.db import KnowledgeBase

logger = logging.getLogger(__name__)

# Regex patterns for different report formats
RE_VULN_TABLE = re.compile(
    r'\|\s*\d+\s*\|\s*\*{0,2}([^*]+?)\*{0,2}\s*\|\s*(Critical|High|Medium|Low)\s*\|'
)

RE_VULN_CRITIC = re.compile(
    r'##\s+\[(C|H|M|L|Critical|High|Medium|Low)[^]]*\]\s*:\s*(.+?)(?:\n|$)'
)

RE_VULN_SIMPLE = re.compile(
    r'\*{0,2}Name\*{0,2}\s*:\s*(.+?)(?:\n|$)'
)

RE_FIX = re.compile(
    r'\*{0,2}(?:Fix|Remediation)\*{0,2}\s*:\s*(.+?)(?:\n{2,}|\Z)',
    re.DOTALL
)

RE_SEVERITY_MARKDOWN = re.compile(
    r'\*{0,2}(?:Severity)\*{0,2}\s*:\s*\*{0,2}(Critical|High|Medium|Low)\*{0,2}',
    re.IGNORECASE
)

SEVERITY_MAP = {
    "Critical": "Critical", "High": "High",
    "Medium": "Medium", "Low": "Low",
}


def _normalise_severity(s: str) -> str:
    return SEVERITY_MAP.get(s.strip(), "Medium")


def extract_from_table_format(report: str) -> List[Dict]:
    findings = []
    for m in RE_VULN_TABLE.finditer(report):
        name = m.group(1).strip()
        sev = _normalise_severity(m.group(2))
        findings.append({"name": name, "severity": sev})
    return findings


def extract_from_critic_format(report: str) -> List[Dict]:
    findings = []
    for m in RE_VULN_CRITIC.finditer(report):
        sev_code = m.group(1).upper()
        sev_map = {"C": "Critical", "H": "High", "M": "Medium", "L": "Low"}
        sev = sev_map.get(sev_code, "Medium")
        name = m.group(2).strip().split("\n")[0][:80]
        findings.append({"name": name, "severity": sev})
    return findings


def extract_from_simple_format(report: str) -> List[Dict]:
    findings = []
    lines = report.split("\n")
    current: Dict = {}
    for line in lines:
        s = line.strip()
        if s.startswith("- **Name**") or s.startswith("- **Name"):
            if current and current.get("name"):
                findings.append(current)
            current = {"name": s.split(":", 1)[1].strip() if ":" in s else s}
        elif s.startswith("- **Severity**") and current:
            sev = s.split(":", 1)[1].strip() if ":" in s else "Medium"
            current["severity"] = _normalise_severity(sev)
        elif s.startswith("- **Fix**") and current:
            current["fix"] = s.split(":", 1)[1].strip() if ":" in s else ""
    if current and current.get("name"):
        findings.append(current)
    return findings


def extract_all(report: str) -> List[Dict]:
    findings = extract_from_table_format(report)
    if not findings:
        findings = extract_from_critic_format(report)
    if not findings:
        findings = extract_from_simple_format(report)
    return findings


class PatternExtractor:
    """Extracts vulnerability patterns from AI reports and stores them in the KB."""

    def __init__(self, kb: KnowledgeBase):
        self.kb = kb

    def learn_from_report(self, report: str, code: str = "", protocol_name: str = "",
                          contract_type: str = "") -> int:
        findings = extract_all(report)
        stored = 0
        for f in findings:
            name = f.get("name", "Unknown").strip()
            if not name or len(name) < 3:
                continue
            severity = f.get("severity", "Medium")
            desc = f.get("description", "")
            if not desc:
                desc = name[:200]
            fix = f.get("fix", "")
            # Use cross-session learning: find-or-merge
            pid, is_new = self.kb.learn_cross_session(
                finding_name=name[:100],
                severity=severity,
                code_snippet=code[:500],
                description=desc[:500],
                protocol=protocol_name,
            )
            if pid and is_new:
                self.kb._update_pattern_extra(pid, severity, code[:500], fix[:500] if fix else "",
                                               contract_type or _detect_simple(code), report[:500])
                logger.info(f"KB: new pattern '{name}' [{severity}] (cross-session)")
            elif pid:
                logger.info(f"KB: merged pattern '{name}' (session #{pid})")
            if pid:
                stored += 1
        if stored:
            logger.info(f"KB auto-learn: {stored} patterns (cross-session)")
        return stored


def _detect_simple(code: str) -> str:
    if not code:
        return ""
    cl = code.lower()
    if "erc20" in cl or "ierc20" in cl:
        return "ERC20"
    if "erc721" in cl or "ierc721" in cl:
        return "ERC721"
    if "uniswap" in cl or "swap" in cl:
        return "DEX/AMM"
    if "lending" in cl or "lend" in cl or "borrow" in cl:
        return "Lending"
    return "General"
