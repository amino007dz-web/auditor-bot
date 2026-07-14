"""Permission Analysis - full permission matrix for each contract."""
import re
from typing import List, Dict, Optional


ROLE_PATTERNS = [
    r"onlyOwner\b",
    r"onlyRole\s*\(\s*(\w+)\s*\)",
    r"hasRole\s*\(\s*(\w+)\s*",
    r"\bmodifier\s+(\w+)\s*\([^)]*\)\s*\{[^}]*require\s*\([^;]*msg\.sender[^;]*\)",
    r"\brequire\s*\(\s*msg\.sender\s*==\s*(\w+)",
    r"\brequire\s*\(\s*[\w.]+\s*==\s*msg\.sender\s*\)",
    r"\bif\s*\(\s*msg\.sender\s*!=\s*(\w+)",
    r"\b_checkRole\s*\(\s*(\w+)",
    r"\bauthorizer\.\w+\s*\(",
    r"\bonlyGovernance\b",
    r"\bonlyAdmin\b",
    r"\bonlyOperator\b",
]

FUNCTION_VISIBILITIES = [
    (r"(public|external)\s+function\s+(\w+)", "writable"),
    (r"function\s+(\w+)\s*\([^)]*\)\s*(?:public|external)", "writable"),
    (r"function\s+(\w+)\s*\([^)]*\)\s*(?:internal|private)", "internal"),
    (r"function\s+(\w+)\s*\([^)]*\)\s*(?:public|external)\s*(?:view|pure)", "readable"),
    (r"function\s+(\w+)\s*\([^)]*\)\s*(?:view|pure)\s*(?:public|external)", "readable"),
]


def analyze_permissions(code: str) -> str:
    """Comprehensive permission matrix analysis."""
    lines = code.split("\n")
    roles = set()
    functions: List[Dict] = []
    state_vars: List[str] = []
    role_assignments: List[str] = []

    # Detect roles
    for pat in ROLE_PATTERNS:
        for match in re.finditer(pat, code, re.IGNORECASE):
            if match.lastindex and match.group(1):
                roles.add(match.group(1))
            else:
                if "onlyOwner" in match.group() or "onlyGovernance" in match.group() or \
                   "onlyAdmin" in match.group() or "onlyOperator" in match.group():
                    roles.add(match.group().replace("modifier ", "").strip())

    # Detect functions and permissions
    seen_fns = set()
    for pat, access in FUNCTION_VISIBILITIES:
        for match in re.finditer(pat, code, re.IGNORECASE):
            name = match.group(1) if match.lastindex else match.group(1)
            if name not in seen_fns:
                seen_fns.add(name)
                functions.append({"name": name, "access": access})

    # Public state variables
    for m in re.finditer(r"(public|internal|private)\s+(\w+\s+\w+)\s*;", code):
        var = m.group(2).strip()
        state_vars.append(var)

    # Custom functions
    for m in re.finditer(r"function\s+(\w+)\s*\(", code):
        fn_name = m.group(1)
        if fn_name not in [f["name"] for f in functions]:
            # Collect the following lines to find modifier
            fn_line = None
            for i, line in enumerate(lines):
                if f"function {fn_name}" in line:
                    fn_line = i
                    break
            if fn_line is not None:
                combined = " ".join(lines[fn_line:fn_line+5])
                access = "writable"
                if "view" in combined or "pure" in combined:
                    access = "readable"
                if "internal" in combined or "private" in combined:
                    access = "internal"
                modifiers = re.findall(r"(only\w+|hasRole|whenNotPaused|whenPaused)", combined)
                functions.append({
                    "name": fn_name,
                    "access": access,
                    "modifiers": modifiers,
                })

    # Match each function with modifiers
    # --- Build report ---
    result = ["# Permission Analysis Matrix\n"]

    # Summary
    result.append("## Summary")
    result.append(f"- Roles detected: {len(roles)}")
    result.append(f"- Functions: {len(functions)} total")
    result.append(f"  - Writable: {sum(1 for f in functions if f['access']=='writable')}")
    result.append(f"  - Readable: {sum(1 for f in functions if f['access']=='readable')}")
    result.append(f"  - Internal: {sum(1 for f in functions if f['access']=='internal')}")
    result.append("")

    # Roles
    if roles:
        result.append("## Roles / Modifiers")
        for r in sorted(roles):
            result.append(f"- `{r}`")
        result.append("")

    # Function matrix
    result.append("## Function Matrix")
    result.append("| Function | Access | Role Protection |")
    result.append("|----------|--------|-----------------|")
    for f in sorted(functions, key=lambda x: x["name"]):
        mods = ", ".join(f.get("modifiers", [])) if f.get("modifiers") else "none"
        icon = {"writable": "✏️", "readable": "👁", "internal": "🔒"}.get(f["access"], "❓")
        result.append(f"| {icon} `{f['name']}` | {f['access']} | {mods} |")
    result.append("")

    # Security recommendations
    result.append("## Security Recommendations")
    writable_unprotected = [f for f in functions
                            if f["access"] == "writable" and not f.get("modifiers")]
    if writable_unprotected:
        result.append(f"⚠️ **{len(writable_unprotected)} writable function(s) without role protection:**")
        for f in writable_unprotected[:10]:
            result.append(f"- `{f['name']}` — consider adding onlyOwner/onlyRole modifier")
        result.append("")
    else:
        result.append("✅ All writable functions are role-protected")
        result.append("")

    # Public variables
    public_vars = [v for v in state_vars if v.startswith("public")]
    if public_vars:
        result.append(f"ℹ️ {len(public_vars)} public state variable(s) — consider private + getter")
        for v in public_vars[:5]:
            result.append(f"- `{v}`")
        result.append("")

    return "\n".join(result)
