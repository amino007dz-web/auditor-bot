"""diff_auditor — focuses LLM analysis on code changes between old and new versions of a contract."""

import difflib
import logging

from agents.llm_client import call_model_with_fallback
from agents.prompts import SYSTEM_PROMPT

logger = logging.getLogger(__name__)

DIFF_PROMPT = """You are a smart contract security auditor reviewing an UPGRADE.
Only focus on the CHANGED lines and how they affect security.

## Instructions
1. Identify each changed function or modifier
2. Determine if the change introduces a vulnerability
3. Determine if the change fixes an existing vulnerability
4. Pay special attention to:
   - Storage layout changes (can cause slot collisions in proxies)
   - Access control changes
   - State variable initialization changes
   - New external entry points
   - Removed require() checks

## Format
For each important change:
- **File/Function**: name
- **Change**: what changed
- **Impact**: security impact assessment
- **Severity**: Critical / High / Medium / Low / Info
"""


def compute_diff(old_code: str, new_code: str) -> str:
    """Generate a unified diff between old and new code."""
    old_lines = old_code.splitlines(keepends=True)
    new_lines = new_code.splitlines(keepends=True)
    diff = difflib.unified_diff(
        old_lines, new_lines,
        fromfile="contract_old.sol",
        tofile="contract_new.sol",
        n=3,
    )
    return "".join(diff)


def analyze_diff(old_code: str, new_code: str) -> str:
    """Analyze differences between old and new contract code for security impact."""
    diff_text = compute_diff(old_code, new_code)
    if not diff_text.strip():
        return "## Diff Analysis\n\n_No differences found between old and new code._\n"

    if len(diff_text) > 8000:
        diff_text = diff_text[:4000] + "\n... (diff truncated)\n" + diff_text[-4000:]

    prompt = f"""{SYSTEM_PROMPT}

{DIFF_PROMPT}

### Code Diff
```diff
{diff_text}
```

Focus ONLY on the changed lines. Ignore unchanged code.
"""
    try:
        result = call_model_with_fallback(prompt, timeout=300)
        return f"## Diff Security Analysis\n\n{result}\n"
    except Exception as e:
        logger.error(f"Diff analysis failed: {e}")
        return f"## Diff Analysis\n\n_Diff analysis failed: {e}_\n"


def summarize_diff(diff_text: str) -> str:
    """Quick summary of diff statistics."""
    lines = diff_text.split("\n")
    added = sum(1 for l in lines if l.startswith("+") and not l.startswith("+++"))
    removed = sum(1 for l in lines if l.startswith("-") and not l.startswith("---"))
    changed_files = sum(1 for l in lines if l.startswith("--- "))
    return (
        f"### Diff Summary\n"
        f"- Files changed: {changed_files}\n"
        f"- Lines added: {added}\n"
        f"- Lines removed: {removed}\n"
    )
