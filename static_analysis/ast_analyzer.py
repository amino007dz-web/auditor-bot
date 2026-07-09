"""
AST-based Static Analysis — Solidity
Uses solcast to analyze storage and inheritance instead of Regex
"""
import re
import logging
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

try:
    from analyzers.solidity_ast import compile_to_ast, analyze_contracts, _get_node_type, _get_name, _traverse, HAS_SOLCAST
except ImportError:
    HAS_SOLCAST = False

TYPE_SIZES = {
    "uint8": 1, "uint16": 2, "uint24": 3, "uint32": 4,
    "uint40": 5, "uint48": 6, "uint56": 7, "uint64": 8,
    "uint72": 9, "uint80": 10, "uint88": 11, "uint96": 12,
    "uint104": 13, "uint112": 14, "uint120": 15, "uint128": 16,
    "uint136": 17, "uint144": 18, "uint152": 19, "uint160": 20,
    "uint168": 21, "uint176": 22, "uint184": 23, "uint192": 24,
    "uint200": 25, "uint208": 26, "uint216": 27, "uint224": 28,
    "uint232": 29, "uint240": 30, "uint248": 31, "uint256": 32,
    "int8": 1, "int16": 2, "int24": 3, "int32": 4,
    "int40": 5, "int48": 6, "int56": 7, "int64": 8,
    "int72": 9, "int80": 10, "int88": 11, "int96": 12,
    "int104": 13, "int112": 14, "int120": 15, "int128": 16,
    "int136": 17, "int144": 18, "int152": 19, "int160": 20,
    "int168": 21, "int176": 22, "int184": 23, "int192": 24,
    "int200": 25, "int208": 26, "int216": 27, "int224": 28,
    "int232": 29, "int240": 30, "int248": 31, "int256": 32,
    "address": 20, "bool": 1,
    "bytes1": 1, "bytes2": 2, "bytes3": 3, "bytes4": 4,
    "bytes8": 8, "bytes16": 16, "bytes32": 32,
}
SLOT_SIZE = 32


def _type_size(raw_type: str) -> int:
    t = raw_type.strip()
    if t.startswith("mapping") or t in ("string", "bytes") or (t.startswith("bytes") and t[5:].isdigit() and int(t[5:]) > 32):
        return SLOT_SIZE
    if t in TYPE_SIZES:
        return TYPE_SIZES[t]
    return SLOT_SIZE


def analyze_storage_with_ast(code: str) -> str:
    """Analyze storage using AST instead of Regex"""
    if not HAS_SOLCAST:
        return "# AST not available — use solcast"

    units = compile_to_ast(code)
    if not units:
        return "# Failed to convert code to AST"

    contracts = analyze_contracts(units)
    report_parts = ["## Storage Analysis (AST-based)\n"]

    for c in contracts:
        report_parts.append(f"\n### {c.name} ({c.kind})")
        if not c.state_vars:
            report_parts.append("No state variables.")
            continue

        report_parts.append(f"\n| # | Variable | Type | Size (bytes) | Slot | Notes |")
        report_parts.append(f"|--|---------|------|-------------|------|---------|")

        slot = 0
        offset = 0
        for idx, var in enumerate(c.state_vars):
            vname = var.get("name", "?")
            vtype = var.get("type", "?")
            size = _type_size(vtype)

            if offset + size > SLOT_SIZE or vtype.startswith("mapping"):
                if offset > 0:
                    slot += 1
                notes = "New slot start" if vtype.startswith("mapping") else "Exceeds slot boundary"
                start_slot = slot
                report_parts.append(f"| {idx} | `{vname}` | `{vtype}` | {size} | {start_slot} | {notes}")
                slot += 1
                offset = 0
            else:
                report_parts.append(f"| {idx} | `{vname}` | `{vtype}` | {size} | {slot} (offset={offset}) |")
                offset += size
                if offset >= SLOT_SIZE:
                    slot += 1
                    offset = 0

        if offset > 0:
            slot += 1

        total_slots = slot
        report_parts.append(f"\nTotal slots: {total_slots}")
        if total_slots > 10:
            report_parts.append(f"⚠️ Warning: The contract uses {total_slots} slots — expensive to deploy")

        # detect immutable/constant variables
        const_vars = [v for v in c.state_vars if "constant" in str(v.get("type", "")).lower()]
        if const_vars:
            report_parts.append(f"\n🔒 Constant variables ({len(const_vars)}): Do not consume slots — stored in bytecode")

    return "\n".join(report_parts)


def _get_contract_modifiers(units, contract_name: str) -> List[str]:
    """Extract modifiers from a given contract using AST"""
    for c in analyze_contracts(units):
        if c.name == contract_name:
            return c.modifiers
    return []


def analyze_inheritance_with_ast(code: str) -> str:
    """Analyze inheritance using AST instead of Regex"""
    if not HAS_SOLCAST:
        return "# AST not available — use solcast"

    units = compile_to_ast(code)
    if not units:
        return "# Failed to convert code to AST"

    contracts = analyze_contracts(units)
    report_parts = ["## Inheritance Analysis (AST-based)\n"]

    if not contracts:
        report_parts.append("⚠️ No contracts found.")
        return "\n".join(report_parts)

    contract_map = {c.name: c for c in contracts}

    # Inheritance tree
    report_parts.append("### Inheritance Tree\n")
    for c in contracts:
        parent_str = ", ".join(c.base_contracts) if c.base_contracts else "(no parents)"
        report_parts.append(f"**{c.name}** ← {parent_str}")

    # Diamond inheritance
    report_parts.append("\n### Diamond Inheritance Analysis\n")
    diamond_found = False
    for c in contracts:
        seen = set()
        duplicates = []
        for p in c.base_contracts:
            if p in seen:
                duplicates.append(p)
            seen.add(p)
        if duplicates:
            diamond_found = True
            report_parts.append(f"⚠️ **{c.name}** inherits from {', '.join(duplicates)} directly — verify C3 linearization")
    if not diamond_found:
        report_parts.append("✅ No direct diamond inheritance.")

    # Inheritance depth
    report_parts.append("\n### Inheritance Depth\n")
    for c in contracts:
        depth = 0
        stack = list(c.base_contracts)
        while stack:
            parent = stack.pop(0)
            depth += 1
            pc = contract_map.get(parent)
            if pc:
                stack.extend(pc.base_contracts)
        if depth > 3:
            report_parts.append(f"⚠️ **{c.name}** has inheritance depth {depth} — complex and increases shadowing risk")
        else:
            report_parts.append(f"✅ **{c.name}** depth {depth}")

    # Interface/Implementation mixing
    report_parts.append("\n### Interface/Implementation Mixing Analysis\n")
    for c in contracts:
        if c.kind in ("interface", "library"):
            continue
        for p in c.base_contracts:
            pc = contract_map.get(p)
            if pc and pc.kind == "interface":
                report_parts.append(f"ℹ️ **{c.name}** inherits `{p}` (interface) — ensure all functions are implemented")

    # Storage collision risk
    report_parts.append("\n### Storage Collision Analysis (Delegatecall)\n")
    for c in contracts:
        if c.uses_delegatecall:
            report_parts.append(f"⚠️ **{c.name}** uses DELEGATECALL — storage collision risk")
        for fn in c.functions:
            if fn.uses_delegatecall:
                report_parts.append(f"⚠️ **{c.name}.{fn.name}** uses DELEGATECALL — ensure storage layout compatibility")

    # function shadowing
    report_parts.append("\n### Function Shadowing Analysis\n")
    for c in contracts:
        for pname in c.base_contracts:
            pc = contract_map.get(pname)
            if not pc:
                continue
            c_fn_names = {f.name for f in c.functions}
            p_fn_names = {f.name for f in pc.functions}
            overlap = c_fn_names & p_fn_names
            if overlap:
                for fn_name in overlap:
                    report_parts.append(f"⚠️ **{c.name}.{fn_name}** shadows **{pname}.{fn_name}**")

    return "\n".join(report_parts)


def generate_combined_ast_report(code: str, protocol_name: str = "Unknown") -> str:
    """Combined AST report: Storage + Inheritance"""
    storage = analyze_storage_with_ast(code)
    inheritance = analyze_inheritance_with_ast(code)
    return f"# AST Analysis: {protocol_name}\n\n{storage}\n\n{inheritance}"
