"""sarif_export — converts audit reports to SARIF format (GitHub Security Tab compatible)."""

import json
import re
import uuid
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
