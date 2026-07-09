import logging
import re
from typing import List

logger = logging.getLogger(__name__)

INVARIANT_PATTERNS = [
    (r"totalSupply\s*==", "Total supply must equal sum of balances"),
    (r"balanceOf\(|balances\(", "Balance sum invariant"),
    (r"_\s*<\s*_?\s*max", "Maximum bound check"),
    (r"require\s*\(\s*\w+\s*[<>!]=", "Invariant check via require"),
    (r"assert\s*\(", "Explicit invariant assertion"),
]


def extract_invariants(code: str) -> list:
    invariants = []
    for pattern, desc in INVARIANT_PATTERNS:
        for m in re.finditer(pattern, code, re.IGNORECASE):
            context_start = max(0, m.start() - 60)
            context = code[context_start:m.end() + 60].strip()
            invariants.append({
                "description": desc,
                "code_snippet": context[:120],
                "line": code[:m.start()].count("\n") + 1,
            })
    return invariants


def generate_invariant_tests(code: str) -> str:
    from agents import call_model_with_fallback
    invariants = extract_invariants(code)
    if not invariants:
        return ""

    prompt = f"""You are an expert in Solidity fuzzing with Foundry.
Based on the invariants below, write fuzz tests for each invariant using Foundry's `vm.assume` and `assert`.

Code:
```solidity
{code[:2000]}
```

Invariants found:
"""
    for i, inv in enumerate(invariants):
        prompt += f"{i + 1}. {inv['description']} (line {inv['line']}): `{inv['code_snippet']}`\n"

    prompt += """
Output ONLY a complete `.t.sol` file with a contract named `InvariantTests` that:
- Extends `forge-std/Test.sol`
- Has one `function invariant_*()` per invariant using `vm.assume()` and `assert`
- Does NOT call the real contract directly—use `vm.prank` with random addresses"""

    try:
        result = call_model_with_fallback(prompt)
        result = re.sub(r"^```solidity\s*", "", result, flags=re.MULTILINE)
        result = re.sub(r"```\s*$", "", result, flags=re.MULTILINE)
        return result.strip() or ""
    except Exception as e:
        logger.warning(f"Invariant test generation failed: {e}")
        return ""


def run_invariant_tests(test_code: str, project_dir: str = ".") -> dict:
    import tempfile, subprocess, os
    tmp = tempfile.NamedTemporaryFile(suffix=".t.sol", delete=False, mode="w")
    tmp.write(test_code)
    tmp.close()
    try:
        proc = subprocess.run(
            ["forge", "test", "--match-path", os.path.basename(tmp.name), "--no-match-coverage"],
            capture_output=True, text=True, timeout=180, cwd=project_dir,
        )
        return {"passed": proc.returncode == 0, "output": (proc.stdout + proc.stderr)[:1000]}
    except FileNotFoundError:
        return {"passed": False, "output": "forge not installed"}
    finally:
        os.unlink(tmp.name)