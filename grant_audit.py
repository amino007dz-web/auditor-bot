import logging
import re
from typing import List, Dict

logger = logging.getLogger(__name__)

GITCOIN_CHECKS = [
    ("No withdrawal function", r"withdraw\s*\(", "Grant contract must allow recipient withdrawal"),
    ("Timelock present", r"timelock|TimeLock", "No timelock — funds may be locked forever"),
    ("Null address check", r"address\(0\)", "No zero-address protection"),
    ("Pausable", r"pause\b|Pausable", "Contract not pausable — upgrade risk"),
    ("Ownership renounce", r"renounceOwnership", "Ownership cannot be renounced"),
]


def gitcoin_audit(code: str) -> List[Dict]:
    findings = []
    for name, pattern, risk in GITCOIN_CHECKS:
        if not re.search(pattern, code, re.IGNORECASE):
            findings.append({
                "check": name,
                "risk": risk,
                "severity": "Medium" if name == "No withdrawal function" else "Low",
            })
    return findings


def allo_compliance_check(code: str) -> str:
    findings = gitcoin_audit(code)
    if not findings:
        return "✅ Grant passes basic compliance checks"
    lines = ["### Gitcoin / Allo Protocol Compliance\n"]
    for f in findings:
        lines.append(f"- [{f['severity']}] {f['check']}: {f['risk']}")
    return "\n".join(lines)