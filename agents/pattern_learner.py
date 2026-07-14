"""
Pattern Learner — discovers new vulnerability patterns from LLM audit findings
that the static grep-based pre-scan missed, and persists them for future scans.
"""

import json
import logging
import os
import re

from agents.llm_client import call_model_with_fallback

logger = logging.getLogger(__name__)

LEARNED_PATTERNS_PATH = os.path.join(os.path.dirname(__file__), "..", "learned_patterns.json")


def _load_learned() -> list:
    if not os.path.isfile(LEARNED_PATTERNS_PATH):
        return []
    try:
        with open(LEARNED_PATTERNS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def _save_learned(patterns: list):
    with open(LEARNED_PATTERNS_PATH, "w", encoding="utf-8") as f:
        json.dump(patterns, f, indent=2, ensure_ascii=False)


def patterns_text() -> str:
    """Return learned patterns as formatted text for pre-scan context."""
    patterns = _load_learned()
    if not patterns:
        return ""
    parts = ["### Pre-Scan: Learned Patterns (from past AI audits)"]
    for p in patterns[-10:]:  # show last 10
        parts.append(f"- [{p['severity']}] {p['name']}: {p['description']}")
    return "\n".join(parts)


def get_learned_bug_classes() -> dict:
    """Return learned patterns as _BUG_CLASSES-compatible dict for bug_detector."""
    patterns = _load_learned()
    classes = {}
    for i, p in enumerate(patterns):
        key = f"learned_{i}"
        pats = p.get("patterns", [])
        if not pats:
            continue
        classes[key] = {
            "name": p["name"],
            "rank": 99,
            "frequency": "Learned from past audits",
            "description": p["description"],
            "grep_patterns": [],
            "vulnerable_patterns": pats,
            "kill_signals": [],
            "severity_hint": p["severity"],
            "detect": lambda code, _key=key, _pats=pats: _run_learned(code, _key, _pats),
        }
    return classes


def _run_learned(code: str, class_key: str, patterns: list) -> list:
    """Run learned patterns against code (single-line + multi-line check)."""
    matches = []
    lines = code.split("\n")
    for pat in patterns:
        try:
            regex = re.compile(pat, re.IGNORECASE)
            for i, line in enumerate(lines):
                if regex.search(line):
                    matches.append({
                        "line": i + 1,
                        "content": line.strip(),
                        "pattern": pat,
                        "class": class_key,
                    })
            # multi-line fallback
            for m in regex.finditer(code):
                if "\n" in m.group():
                    line_no = code[:m.start()].count("\n") + 1
                    dup = any(x["line"] == line_no and x["pattern"] == pat for x in matches)
                    if not dup:
                        matches.append({
                            "line": line_no,
                            "content": m.group()[:80].replace("\n", "\\n"),
                            "pattern": pat,
                            "class": class_key,
                        })
        except re.error:
            continue
    return matches


def learn_from_audit(code: str, llm_report: str, pre_scan_summary: str):
    """Call LLM to extract novel vulnerability patterns from this audit."""
    prompt = f"""You are a security pattern miner. Given Solidity code and an AI audit report,
extract NEW vulnerability patterns that a simple regex-based grep scanner would NOT catch.
Return ONLY a JSON array of objects, each with:
- "name": short vulnerability name
- "description": 1-sentence description
- "severity": "Critical", "High", or "Medium"
- "patterns": array of 1-2 Python regex patterns that would detect this vulnerability

Rules:
- Each regex must be a valid Python regex matching Solidity code
- Prefer multi-line patterns using [^}}]* to span function bodies
- Focus on patterns the pre-scan already missed (not standard reentrancy, access control, etc.)
- Return [] if no novel patterns found

### Pre-Scan Results (static analysis already caught these)
{pre_scan_summary or "No pre-scan results"}

### Code
```solidity
{code[:2000]}
```

### AI Audit Report
{llm_report[:3000]}

### JSON output:
```json
"""
    try:
        raw = call_model_with_fallback(prompt, timeout=120)
    except Exception as e:
        logger.debug(f"Pattern learning LLM call failed: {e}")
        return

    json_str = _extract_json(raw)
    if not json_str:
        return

    try:
        new_patterns = json.loads(json_str)
        if not isinstance(new_patterns, list):
            return
    except json.JSONDecodeError:
        return

    # validate each pattern has required fields
    validated = []
    for p in new_patterns:
        if not all(k in p for k in ("name", "description", "severity", "patterns")):
            continue
        if not isinstance(p["patterns"], list) or not p["patterns"]:
            continue
        if p["severity"] not in ("Critical", "High", "Medium"):
            p["severity"] = "Medium"
        validated.append(p)

    if not validated:
        return

    existing = _load_learned()
    names = {e["name"] for e in existing}
    added = 0
    for p in validated:
        if p["name"] not in names:
            existing.append(p)
            names.add(p["name"])
            added += 1

    if added:
        _save_learned(existing)
        logger.info(f"Pattern learner: saved {added} new pattern(s) (total: {len(existing)})")


def _extract_json(text: str) -> str:
    """Extract JSON array from LLM response (handles markdown fences)."""
    if not text:
        return ""
    m = re.search(r"```(?:json)?\s*\n(\[.*?\])\s*\n```", text, re.DOTALL)
    if m:
        return m.group(1)
    m = re.search(r"(\[.*?\])", text, re.DOTALL)
    if m:
        return m.group(1)
    return ""
