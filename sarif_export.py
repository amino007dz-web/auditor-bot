"""sarif_export — converts audit reports to SARIF format (GitHub Security Tab compatible)."""

import json
import os
import re
from datetime import datetime, timezone
from typing import List, Dict, Optional

FINDING_RE = re.compile(
    r'(?:#{1,3}\s*)?(Critical|High|Medium|Low|Info)[:\s-]*\s*(.+?)$',
    re.IGNORECASE | re.MULTILINE,
)

SEVERITY_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

LEVEL_MAP = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 5.0,
    "low": 2.0,
    "info": 0.0,
}

LINE_RE = re.compile(r'[Ll]ine\s*:?\s*(\d+)', re.IGNORECASE)


def _parse_findings(report: str) -> List[Dict]:
    findings = []
    current = None
    for line in report.split("\n"):
        m = FINDING_RE.match(line.strip())
        if m:
            if current:
                findings.append(current)
            sev = m.group(1).lower()
            current = {
                "severity": sev,
                "title": m.group(2).strip().rstrip(":"),
                "description": line.strip(),
                "lines": [],
            }
        elif current and line.strip():
            current["description"] += "\n" + line.strip()
            lm = LINE_RE.search(line)
            if lm:
                current["lines"].append(int(lm.group(1)))
    if current:
        findings.append(current)
    return findings


def _rule_id(idx: int, finding: Dict) -> str:
    name = finding.get("title", f"finding-{idx}")[:40]
    safe = re.sub(r'[^a-zA-Z0-9]', '-', name).strip("-").lower()
    return f"SCA-{idx:03d}-{safe}" if safe else f"SCA-{idx:03d}"


def report_to_sarif(report: str, code: str = "", label: str = "Smart Contract") -> str:
    findings = _parse_findings(report)
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2-1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Smart Contract Auditor",
                        "version": "2.1.0",
                        "informationUri": "https://github.com/amino007dz-web/auditor-bot",
                        "rules": [],
                    }
                },
                "artifacts": [
                    {
                        "location": {"uri": f"file:///{label}.sol"},
                        "contents": {"text": code or "// source not provided"},
                    }
                ],
                "results": [],
                "columnKind": "unicodeCodePoints",
            }
        ],
    }

    driver = sarif["runs"][0]["tool"]["driver"]
    results = sarif["runs"][0]["results"]

    for i, f in enumerate(findings):
        rid = _rule_id(i, f)
        driver["rules"].append({
            "id": rid,
            "name": f.get("title", f"Finding {i+1}"),
            "shortDescription": {"text": f.get("title", "")[:200]},
            "fullDescription": {"text": f.get("description", "")[:1000]},
            "defaultConfiguration": {"level": SEVERITY_MAP.get(f["severity"], "warning")},
            "properties": {
                "security-severity": str(LEVEL_MAP.get(f["severity"], 5.0)),
                "tags": ["security", f["severity"]],
            },
        })

        locations = []
        lines = f.get("lines", [])
        if lines:
            for ln in lines:
                locations.append({
                    "physicalLocation": {
                        "artifactLocation": {"uri": f"file:///{label}.sol"},
                        "region": {
                            "startLine": ln,
                            "snippet": {"text": code.split("\n")[ln - 1][:120] if code else ""},
                        },
                    }
                })
        else:
            locations.append({
                "physicalLocation": {
                    "artifactLocation": {"uri": f"file:///{label}.sol"},
                    "region": {"startLine": 1},
                }
            })

        results.append({
            "ruleId": rid,
            "ruleIndex": i,
            "level": SEVERITY_MAP.get(f["severity"], "warning"),
            "message": {"text": f.get("description", "")[:500]},
            "locations": locations,
        })

    return json.dumps(sarif, indent=2)


def generate_sarif(findings: list, output_path: str = "") -> str:
    """Converts a list of Finding dataclass objects to SARIF format.

    Each finding must have: agent_name, severity, category, file, description, fix, line.
    """
    SEVERITY_MAP = {
        "Critical": "error",
        "High": "error",
        "Medium": "warning",
        "Low": "note",
    }

    def _make_rule(finding) -> dict:
        return {
            "id": finding.agent_name,
            "shortDescription": {"text": finding.agent_name},
            "fullDescription": {"text": finding.description},
            "defaultConfiguration": {"level": SEVERITY_MAP.get(finding.severity, "note")},
            "properties": {"category": finding.category, "severity": finding.severity},
        }

    def _make_result(finding, rule_index: int) -> dict:
        location = {}
        if finding.file:
            loc = {"uri": finding.file}
            if os.path.exists(finding.file):
                loc["uriBaseId"] = os.path.dirname(os.path.abspath(finding.file))
            location["physicalLocation"] = {"artifactLocation": loc}
            if finding.line:
                location["physicalLocation"]["region"] = {
                    "startLine": finding.line,
                    "startColumn": 1,
                }
        result = {
            "ruleId": finding.agent_name,
            "ruleIndex": rule_index,
            "level": SEVERITY_MAP.get(finding.severity, "note"),
            "message": {"text": finding.description},
            "properties": {
                "severity": finding.severity,
                "category": finding.category,
                "fix": finding.fix,
            },
        }
        if location:
            result["locations"] = [location]
        return result

    rules = {}
    for f in findings:
        if f.agent_name not in rules:
            rules[f.agent_name] = _make_rule(f)
    rules_list = list(rules.values())

    results = []
    for f in findings:
        rule_idx = rules_list.index(rules[f.agent_name])
        results.append(_make_result(f, rule_idx))

    doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Smart Contract Auditor",
                        "version": "2.0.0",
                        "informationUri": "https://github.com/amino007dz-web/auditor-bot",
                        "rules": rules_list,
                    }
                },
                "results": results,
                "columnKind": "utf16CodeUnits",
                "properties": {
                    "analyzedAt": datetime.now(timezone.utc).isoformat(),
                    "totalFindings": len(findings),
                },
            }
        ],
    }

    text = json.dumps(doc, indent=2, ensure_ascii=False)
    if output_path:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(text)
    return text
