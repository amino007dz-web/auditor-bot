import time
from collections import Counter
from typing import Dict, List

from .opcode_tracer import analyze_opcodes, OPCODE_PATTERNS
from .storage_analyzer import analyze_storage_single, _extract_contracts_from_code, _find_unstructured_storage, _find_assembly_slots
from .inheritance_analyzer import analyze_inheritance

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

def generate_combined_report(code: str, protocol: str = "Protocol") -> str:
    contracts_data = _extract_contracts_from_code(code)
    all_findings = []
    all_findings.extend(_extract_opcode_findings(code))
    all_findings.extend(_extract_storage_findings(code, contracts_data))
    all_findings.sort(key=lambda f: SEVERITY_ORDER.get(f.get("severity", "INFO"), 99))
    counts = Counter(f.get("severity", "INFO") for f in all_findings if isinstance(f, dict))
    report = f"# {protocol} — Combined Report\n\n"
    report += f"**Generation Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    report += "**Sources:** Opcode Tracer + Storage Analyzer + Inheritance Analyzer\n\n"
    report += "## Vulnerability Summary\n\n| Severity | Count |\n|---------|------|\n"
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        report += f"| **{sev}** | {counts.get(sev, 0)} |\n"
    report += f"| **Total** | {len(all_findings)} |\n\n"
    if all_findings:
        report += "## List of Vulnerabilities (Sorted by Severity)\n\n"
        current_sev = None
        sev_headers = {"CRITICAL": "[CRITICAL]", "HIGH": "[HIGH]", "MEDIUM": "[MEDIUM]", "LOW": "[LOW]", "INFO": "[INFO]"}
        for i, f in enumerate(all_findings, 1):
            if not isinstance(f, dict):
                continue
            if f.get("severity") != current_sev:
                report += f"\n### {sev_headers.get(f.get('severity', 'INFO'), '')} {f.get('severity', 'INFO')}\n\n"
                current_sev = f.get("severity")
            report += f"**{i}. {f.get('title', 'Unknown')}** [{f.get('severity', 'INFO')}]\n"
            report += f"- **Details:** {f.get('description', 'N/A')}\n"
            if f.get("match"):
                report += f"- **Matched Text:** `{f['match']}`\n"
            if f.get("fix") and f.get("fix", "") != "—":
                report += f"- **Fix:** {f['fix']}\n"
            report += "\n"
    report += "---\n\n## Attachments\n\n"
    report += analyze_opcodes(code) + "\n"
    report += analyze_storage_single(code, contracts_data) + "\n"
    report += analyze_inheritance(code, contracts_data) + "\n"
    return report

def generate_combined_report_interactive(code: str, lang: str = "english",
                                          protocol_name: str = "Smart Contract") -> str:
    return generate_combined_report(code, protocol_name)

def _extract_opcode_findings(code: str) -> List[Dict]:
    import re
    findings = []
    for name, info in OPCODE_PATTERNS.items():
        matches = re.findall(info["pattern"], code, re.IGNORECASE)
        for match in matches:
            findings.append({
                "name": name, "title": f"{name}: {info['description'][:60]}",
                "severity": info["severity"], "description": info["description"],
                "match": str(match)[:100], "fix": info["fix"], "source": "opcode"
            })
    return findings

def _extract_storage_findings(code: str, contracts_data: Dict[str, Dict]) -> List[Dict]:
    findings = []
    for f in _find_unstructured_storage(code):
        findings.append({
            "name": f"storage_{f['name']}", "title": f"Unstructured Storage: {f['name']}",
            "severity": f["severity"], "description": f["description"],
            "fix": "Use the dedicated Solidity compiler slot instead of manual", "source": "storage"
        })
    for f in _find_assembly_slots(code):
        findings.append({
            "name": f"asm_{f['name']}", "title": f"Assembly Storage: {f['name']}",
            "severity": "MEDIUM", "description": f["description"],
            "fix": "Minimize the use of assembly for storage", "source": "storage"
        })
    return findings
