import json
import os
from datetime import datetime, timezone
from typing import List

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"

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


def generate_sarif(findings: list, output_path: str = "") -> str:
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
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
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
