from typing import Dict
from .storage_analyzer import _extract_contracts_from_code

def analyze_inheritance(code: str, contracts_data: Dict[str, Dict] = None) -> str:
    if contracts_data is None:
        contracts_data = _extract_contracts_from_code(code)
    report = "## Inheritance Analysis\n\n"
    if not contracts_data:
        report += "⚠️ No contracts found.\n"
        return report
    report += "### Inheritance Tree\n\n"
    for cname, cdata in contracts_data.items():
        parent_str = ", ".join(cdata["parents"]) if cdata["parents"] else "(no parents)"
        indent = "  " * len(cdata.get("parents", []))
        report += f"{indent}**{cname}** ← {parent_str}\n"
    report += "\n### Diamond Inheritance Analysis\n\n"
    diamond_found = False
    for cname, cdata in contracts_data.items():
        seen = set(); duplicates = []
        for p in cdata.get("parents", []):
            if p in seen: duplicates.append(p)
            seen.add(p)
        if duplicates:
            diamond_found = True
            report += f"⚠️ **{cname}** inherits from {', '.join(duplicates)} directly — verify C3 linearization\n"
    if not diamond_found:
        report += "✅ No direct diamond inheritance.\n"
    report += "\n### Inheritance Depth\n\n"
    for cname, cdata in contracts_data.items():
        depth = 0
        stack = list(cdata.get("parents", []))
        while stack:
            parent = stack.pop(0)
            depth += 1
            pc = contracts_data.get(parent)
            if pc:
                stack.extend(pc.get("parents", []))
        if depth > 3:
            report += f"⚠️ **{cname}** has inheritance depth {depth} — complex and increases shadowing risk\n"
        else:
            report += f"✅ **{cname}** depth {depth}\n"
    report += "\n### Interface/Implementation Mixing Analysis\n\n"
    for cname, cdata in contracts_data.items():
        if cdata.get("type") in ("interface", "library"):
            continue
        for p in cdata.get("parents", []):
            pc = contracts_data.get(p)
            if pc and pc.get("type") == "interface":
                report += f"ℹ️ **{cname}** inherits `{p}` (interface) — ensure all functions are implemented\n"
    report += "\n"
    return report
