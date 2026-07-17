import re
from typing import Dict, List
from analyzers.base import TYPE_SIZES

SLOT_SIZE = 32

def _parse_state_var_type(raw_type: str) -> int:
    t = raw_type.strip()
    if t.startswith("mapping") or t in ("string", "bytes") or (t.startswith("bytes") and t[5:].isdigit() and int(t[5:]) > 32):
        return 32
    if t in TYPE_SIZES:
        return TYPE_SIZES[t]
    return 32

def _extract_contracts_from_code(code: str) -> Dict[str, Dict]:
    contracts = {}
    lines = code.split("\n")
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        is_match = re.match(r"(abstract\s+)?(contract|interface|library)\s+(\w+)(?:\s+is\s+([^{]+))?", stripped)
        if is_match:
            ctype = is_match.group(2)
            cname = is_match.group(3)
            parents_raw = is_match.group(4) or ""
            j = i
            while "{" not in lines[j] and "{" not in parents_raw and j < len(lines):
                parents_raw += " " + lines[j].strip()
                j += 1
            if "{" in parents_raw:
                parents_raw = parents_raw.split("{")[0]
            parents = [p.strip() for p in parents_raw.split(",") if p.strip() and p.strip() != "is"]
            start = i
            depth = 0
            j = i
            found_open = False
            while j < len(lines):
                for ch in lines[j]:
                    if ch == "{": depth += 1; found_open = True
                    elif ch == "}": depth -= 1
                if found_open and depth <= 0:
                    break
                j += 1
            body = "\n".join(lines[start:j+1])
            state_vars = _extract_state_variables_simple(body)
            contracts[cname] = {
                "type": ctype, "parents": parents,
                "state_vars": state_vars,
                "start_line": start, "end_line": j, "code": body,
            }
            i = j
        i += 1
    return contracts

def _extract_state_variables_simple(code: str) -> List[Dict]:
    vars = []
    body = re.sub(r"function\s+[^;{]*\{[^}]*\}", "", code)
    body = re.sub(r"modifier\s+\w+[^{]*\{[^}]*\}", "", body)
    body = re.sub(r"event\s+[^;]+;", "", body)
    body = re.sub(r"error\s+[^;]+;", "", body)
    for line in body.split("\n"):
        s = line.strip()
        if ";" not in s:
            continue
        if "constant" in s or "immutable" in s:
            continue
        if s.startswith("using ") or s.startswith("import ") or s.startswith("//"):
            continue
        if s.startswith("struct ") or s.startswith("enum "):
            continue
        m = re.match(
            r"(mapping\s*\([^)]+\)|uint\d*|int\d*|address|bool|string|bytes\d*|bytes|"
            r"struct\s+\w+)\s*(public|private|internal)?\s*(\w+)\s*;", s
        )
        if m:
            raw_type = m.group(1).strip()
            var_name = m.group(3)
            if var_name:
                vars.append({"name": var_name, "type": raw_type, "size": _parse_state_var_type(raw_type)})
    return vars

def _compute_storage_layout(contracts: Dict[str, Dict], root_name: str) -> List[Dict]:
    visited = set()
    linearized = []
    def dfs(name):
        if name in visited:
            return
        visited.add(name)
        c = contracts.get(name)
        if not c:
            return
        for parent in c.get("parents", []):
            dfs(parent)
        linearized.append(name)
    dfs(root_name)
    slots = []
    current_slot = 0
    offset = 0
    for cname in reversed(linearized):
        c = contracts.get(cname)
        if not c:
            continue
        for var in c.get("state_vars", []):
            sz = var["size"]
            is_dynamic = var["type"].startswith("mapping") or var["type"] in ("string", "bytes")
            if is_dynamic:
                if offset > 0:
                    current_slot += 1
                    offset = 0
                current_slot += 1
                offset = 0
            elif sz == 32 or offset + sz > SLOT_SIZE:
                if offset > 0:
                    current_slot += 1
                offset = sz if sz < 32 else 0
            else:
                offset += sz
            slots.append({
                "contract": cname, "slot": current_slot,
                "name": var["name"], "type": var["type"], "size": sz,
            })
    return slots

def _find_unstructured_storage(code: str) -> List[Dict]:
    findings = []
    for m in re.finditer(r"bytes32\s+(constant|immutable)?\s*(private|public|internal)?\s*(\w+)\s*=\s*0x([0-9a-fA-F]+)", code):
        name = m.group(3); val = m.group(4)
        findings.append({"name": name, "value": f"0x{val}", "type": "Unstructured Storage Slot", "severity": "MEDIUM",
                         "description": f"bytes32 constant '{name}' = 0x{val[:16]}..."})
    for m in re.finditer(r"sstore\(\s*(0x[0-9a-fA-F]+)\s*,", code):
        slot = m.group(1)
        findings.append({"name": f"sstore({slot})", "value": slot, "type": "Assembly sstore",
                         "severity": "HIGH",
                         "description": f"Direct storage write to slot {slot}"})
    known_safe = [
        "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
        "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
        "0xf720d7b7a76707a9f6a8e0cfa3a74ab771c27a7b6e3d6b88f64743e4f54",
        "0x4910fdfa16fed3260ed0e7147f7cc6da11a60208b5b9406d12a635614ffd9143",
    ]
    for f in findings:
        if f["value"] in known_safe:
            f["severity"] = "INFO"
            f["description"] += " (known EIP-1967/UUPS pattern)"
    return findings

def _find_assembly_slots(code: str) -> List[Dict]:
    findings = []
    for m in re.finditer(r"sload\(\s*(0x[0-9a-fA-F]+)\s*\)|sstore\(\s*(0x[0-9a-fA-F]+)\s*,", code):
        slot = m.group(1) or m.group(2)
        op = "sload" if m.group(1) else "sstore"
        findings.append({"name": f"{op}({slot})", "slot": slot, "severity": "MEDIUM",
                         "description": f"{op} on slot {slot}"})
    return findings

def analyze_storage_single(code: str, contracts_data: Dict[str, Dict] = None) -> str:
    if contracts_data is None:
        contracts_data = _extract_contracts_from_code(code)
    report = "## Storage Analysis (Storage Layout)\n\n"
    if not contracts_data:
        report += "⚠️ No contracts found in the code.\n"
        return report
    report += "### Estimated storage layout per contract\n\n"
    all_layouts = {cname: _compute_storage_layout(contracts_data, cname) for cname in contracts_data}
    for cname, layout in all_layouts.items():
        cdata = contracts_data.get(cname, {})
        report += f"**{cname}** (parents: {', '.join(cdata.get('parents', [])) if cdata.get('parents') else '—'})\n\n"
        if layout:
            report += "| Slot | Contract | Name | Type | Size |\n|------|----------|------|------|------|\n"
            for v in layout:
                report += f"| {v['slot']} | {v['contract']} | {v['name']} | {v['type']} | {v['size']}B |\n"
            report += "\n"
        else:
            report += "  (No state variables)\n\n"
    cnames = list(all_layouts.keys())
    report += "### Storage Slot Collision Check\n\n"
    collisions_found = False
    for i in range(len(cnames)):
        for j in range(i + 1, len(cnames)):
            a_name, b_name = cnames[i], cnames[j]
            a_layout, b_layout = all_layouts[a_name], all_layouts[b_name]
            if not a_layout or not b_layout:
                continue
            for a_var in a_layout:
                for b_var in b_layout:
                    if (a_var["slot"] == b_var["slot"] and a_var["name"] != b_var["name"]
                            and a_var["contract"] != b_var["contract"]):
                        collisions_found = True
                        report += (f"⚠️ Slot collision {a_var['slot']}: `{a_var['contract']}.{a_var['name']}` "
                                   f"({a_var['type']}) ↔ `{b_var['contract']}.{b_var['name']}` ({b_var['type']})\n"
                                   f"    → If used in the same proxy via delegatecall, they will corrupt each other's data!\n")
    if not collisions_found:
        report += "✅ No obvious storage slot collisions.\n"
    report += "\n"
    unstructured = _find_unstructured_storage(code)
    if unstructured:
        report += "### Unstructured Storage Patterns\n\n"
        for f in unstructured:
            report += f"- **[{f['severity']}]** {f['type']}: `{f['name']}`\n  {f['description']}\n\n"
    asm_slots = _find_assembly_slots(code)
    if asm_slots:
        report += "### Assembly Storage Operations\n\n"
        for f in asm_slots:
            report += f"- **[{f['severity']}]** `{f['name']}`\n  {f['description']}\n\n"
    return report
