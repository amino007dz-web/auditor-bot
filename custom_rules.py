"""Custom Rules - user-defined detection patterns."""
import os
import re
import json
from typing import List, Dict


RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")
os.makedirs(RULES_DIR, exist_ok=True)
RULES_FILE = os.path.join(RULES_DIR, "custom_rules.json")


class CustomRule:
    """A custom detection rule."""

    def __init__(self, name: str, pattern: str, severity: str = "medium",
                 description: str = "", lang: str = "solidity"):
        self.name = name
        self.pattern = pattern
        self.severity = severity
        self.description = description
        self.lang = lang

    def to_dict(self) -> dict:
        return {"name": self.name, "pattern": self.pattern,
                "severity": self.severity, "description": self.description,
                "lang": self.lang}

    @classmethod
    def from_dict(cls, d: dict) -> "CustomRule":
        return cls(d["name"], d["pattern"], d.get("severity", "medium"),
                    d.get("description", ""), d.get("lang", "solidity"))


class CustomRulesEngine:
    """Custom rules engine."""

    def __init__(self):
        self.rules: List[CustomRule] = []
        self._load()

    def _load(self):
        if os.path.isfile(RULES_FILE):
            try:
                with open(RULES_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.rules = [CustomRule.from_dict(d) for d in data]
            except Exception:
                self.rules = []

    def _save(self):
        with open(RULES_FILE, "w", encoding="utf-8") as f:
            json.dump([r.to_dict() for r in self.rules], f, ensure_ascii=False, indent=2)

    def add_rule(self, rule: CustomRule):
        self.rules.append(rule)
        self._save()

    def remove_rule(self, name: str):
        self.rules = [r for r in self.rules if r.name != name]
        self._save()

    def list_rules(self) -> List[dict]:
        return [r.to_dict() for r in self.rules]

    def scan(self, code: str, lang: str = "solidity") -> List[Dict]:
        """Scan code with all custom rules and return findings."""
        findings = []
        for rule in self.rules:
            if rule.lang != "all" and rule.lang != lang:
                continue
            try:
                for match in re.finditer(rule.pattern, code, re.IGNORECASE):
                    line_no = code[:match.start()].count("\n") + 1
                    findings.append({
                        "rule": rule.name,
                        "severity": rule.severity,
                        "line": line_no,
                        "match": match.group()[:100],
                        "description": rule.description,
                    })
            except re.error as e:
                continue
        return findings

    def scan_to_text(self, code: str, lang: str = "solidity") -> str:
        """Scan + return report text."""
        findings = self.scan(code, lang)
        if not findings:
            return "## Custom Rules\n\n_No custom rule matches found._"
        lines = ["# Custom Rules Scan\n"]
        by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        for f in findings:
            by_severity.setdefault(f["severity"], []).append(f)
        for sev in ["critical", "high", "medium", "low", "info"]:
            items = by_severity.get(sev, [])
            if not items:
                continue
            lines.append(f"### {sev.upper()} ({len(items)})")
            for it in items:
                lines.append(f"- Line {it['line']}: [{it['rule']}] {it['description']}")
                lines.append(f"  `{it['match']}`")
            lines.append("")
        return "\n".join(lines)


_ENGINE = CustomRulesEngine()


def get_rules_engine() -> CustomRulesEngine:
    return _ENGINE
