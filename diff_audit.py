"""
Diff Audit — compare two versions of a contract and verify fixes.
Generates a visual HTML diff with green/red lines + AI analysis.
"""
import difflib
import logging
from dataclasses import dataclass, field
from typing import List, Optional

from agents import call_model_with_fallback

logger = logging.getLogger(__name__)


@dataclass
class CodeDiff:
    added_lines: List[str] = field(default_factory=list)
    removed_lines: List[str] = field(default_factory=list)
    changed_functions: List[str] = field(default_factory=list)
    summary: str = ""


def compute_diff(v1: str, v2: str) -> CodeDiff:
    """Compute diff between two code versions."""
    lines1 = v1.splitlines(keepends=True)
    lines2 = v2.splitlines(keepends=True)
    differ = difflib.unified_diff(lines1, lines2, fromfile="v1", tofile="v2", lineterm="")

    added: List[str] = []
    removed: List[str] = []
    for line in differ:
        if line.startswith("+") and not line.startswith("+++"):
            added.append(line[1:].strip())
        elif line.startswith("-") and not line.startswith("---"):
            removed.append(line[1:].strip())

    # Detect changed functions (Solidity + Move)
    import re
    pat = r'(?:function|fun|public\s+(?:entry\s+)?fun)\s+(\w+)'
    funcs1 = set(re.findall(pat, v1))
    funcs2 = set(re.findall(pat, v2))
    added_funcs = funcs2 - funcs1
    removed_funcs = funcs1 - funcs2
    changed = set()
    for fn in (funcs1 & funcs2):
        # Solidity: function name(...) ... {   ; Move: fun name(...): ... {
        m1 = re.search(rf'(?:function|fun)\s+{re.escape(fn)}\s*\([^)]*\)', v1)
        m2 = re.search(rf'(?:function|fun)\s+{re.escape(fn)}\s*\([^)]*\)', v2)
        if m1 and m2:
            # Extract each function body (find the next {)
            start1 = v1.find("{", m1.end())
            start2 = v2.find("{", m2.end())
            if start1 == -1 or start2 == -1:
                continue
            body1 = v1[start1 + 1:]
            body2 = v2[start2 + 1:]
            depth = 1; pos = 0
            while pos < len(body1) and depth > 0:
                if body1[pos] == '{': depth += 1
                elif body1[pos] == '}': depth -= 1
                pos += 1
            body1 = body1[:pos]
            depth = 1; pos = 0
            while pos < len(body2) and depth > 0:
                if body2[pos] == '{': depth += 1
                elif body2[pos] == '}': depth -= 1
                pos += 1
            body2 = body2[:pos]
            if body1.strip() != body2.strip():
                changed.add(fn)

    summary_parts = []
    if added_funcs:
        summary_parts.append(f"New functions: {', '.join(added_funcs)}")
    if removed_funcs:
        summary_parts.append(f"Removed functions: {', '.join(removed_funcs)}")
    if changed:
        summary_parts.append(f"Modified functions: {', '.join(changed)}")
    if added:
        summary_parts.append(f"Added lines: {len(added)}")
    if removed:
        summary_parts.append(f"Removed lines: {len(removed)}")

    return CodeDiff(
        added_lines=added[:50],
        removed_lines=removed[:50],
        changed_functions=list(changed),
        summary="; ".join(summary_parts) or "No differences",
    )


def run_diff_audit(v1: str, v2: str, lang: str = "english") -> str:
    """Analyze differences between two versions and verify fixes."""
    diff = compute_diff(v1, v2)

    # Build prompt for diff analysis
    diff_text = f"## Summary of Changes\n{diff.summary}\n\n"
    if diff.changed_functions:
        diff_text += "### Modified Functions\n" + "\n".join(f"- {fn}" for fn in diff.changed_functions) + "\n\n"
    if diff.added_lines:
        diff_text += "### Added Lines\n```\n" + "\n".join(diff.added_lines[:30]) + "\n```\n\n"
    if diff.removed_lines:
        diff_text += "### Removed Lines\n```\n" + "\n".join(diff.removed_lines[:30]) + "\n```\n"

    prompt = f"""You are a smart contract security expert. Compare two versions of a contract and answer two questions:

1. Did the new changes actually fix the existing vulnerabilities?
2. Did the changes introduce new vulnerabilities that were not present? (Regression Testing)

{diff_text}

Output the result in the following format:
## Fix Assessment
### Fixed Vulnerabilities: [list]
### Potential New Vulnerabilities: [list]
### Overall Assessment: [Safe / Needs Improvement / Unsafe]"""

    report = call_model_with_fallback(prompt, timeout=300)
    return report or "Diff analysis failed"


def generate_diff_html(v1: str, v2: str, ai_report: str = "") -> str:
    """Generate a visual HTML diff with green (added) and red (removed) lines."""
    lines1 = v1.splitlines()
    lines2 = v2.splitlines()
    differ = difflib.unified_diff(lines1, lines2, fromfile="v1", tofile="v2", lineterm="")
    diff_lines = list(differ)

    rows = []
    for line in diff_lines:
        css = ""
        if line.startswith("+"):
            css = 'style="background:#1a3a1a;color:#3fb950;"'
        elif line.startswith("-"):
            css = 'style="background:#3a1a1a;color:#f85149;"'
        elif line.startswith("@@"):
            css = 'style="background:#1c2128;color:#58a6ff;"'
        rows.append(f"<tr><td><pre {css}>{_escape(line)}</pre></td></tr>")

    ai_section = f"""
    <div class="ai-report">
      <h2>AI Analysis</h2>
      <pre>{_escape(ai_report)}</pre>
    </div>""" if ai_report else ""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Diff Audit Report</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:'Courier New',monospace; background:#0d1117; color:#c9d1d9; padding:2rem; }}
h1 {{ color:#58a6ff; margin-bottom:1rem; }}
table {{ width:100%; border-collapse:collapse; }}
td {{ padding:0.25rem 1rem; border-bottom:1px solid #30363d; }}
.summary {{ background:#161b22; padding:1rem; border-radius:8px; margin-bottom:1rem; }}
.ai-report {{ background:#161b22; padding:1rem; border-radius:8px; margin-top:1rem; }}
.ai-report h2 {{ color:#58a6ff; margin-bottom:0.5rem; }}
</style></head>
<body>
<h1>Visual Diff Audit</h1>
<div class="summary">
  <p>Added: <span style="color:#3fb950;">{len([l for l in diff_lines if l.startswith('+') and not l.startswith('+++')])}</span>
  | Removed: <span style="color:#f85149;">{len([l for l in diff_lines if l.startswith('-') and not l.startswith('---')])}</span>
  | Total changes: {len(diff_lines)}</p>
</div>
<table>{"".join(rows)}</table>
{ai_section}
</body></html>"""
    return html


def _escape(text: str) -> str:
    if not text:
        return ""
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))
