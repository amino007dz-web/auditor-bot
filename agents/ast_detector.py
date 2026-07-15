"""
Level 2 AST Detector — semantic code analysis using solcast AST + hybrid text scanning.

Detects vulnerabilities that regex cannot reliably catch:
  - CEI (Checks-Effects-Interactions) violation
  - Unprotected flash loan receiver (anyone drains fees)
  - balanceOf-based accounting (donation attack on vaults)
  - Arbitrary external call via user-supplied target+data
  - Cross-function reentrancy (shared state + external calls)
"""

import logging
import re

logger = logging.getLogger(__name__)

_has_ast = False
_has_cfg = False
try:
    from analyzers.solidity_ast import compile_to_ast, analyze_contracts, _get_name, _get_node_type
    _has_ast = True
except ImportError:
    pass
try:
    from analyzers.cfg_analyzer import analyze_flow as _run_cfg
    _has_cfg = True
except ImportError:
    pass


def _get_function_body(code: str, func_name: str, params: list) -> str:
    """Extract function source code from full contract code using function name."""
    pattern = rf"function\s+{re.escape(func_name)}\s*\([^)]*\)\s*(?:public|external|internal|private|view|pure|payable)?[^{{]*\{{"
    for m in re.finditer(pattern, code, re.DOTALL):
        start = m.end()
        brace_count = 1
        i = start
        while i < len(code) and brace_count > 0:
            if code[i] == '{':
                brace_count += 1
            elif code[i] == '}':
                brace_count -= 1
            i += 1
        return code[m.start():i]
    return ""


def _find_external_calls(body: str) -> list:
    """Find all external calls in a function body with their positions."""
    calls = []
    patterns = [
        (r"\.call\s*\{value[^}]*\}\s*\([^)]*\)", "low_level_call"),
        (r"\.delegatecall\s*\([^)]*\)", "delegatecall"),
        (r"\.transfer\s*\([^)]*\)", "transfer"),
        (r"\.send\s*\([^)]*\)", "send"),
        (r"\.functionCall\s*\([^)]*\)", "function_call"),
        (r"\.call\s*\([^)]*\)", "raw_call"),
    ]
    for pat, kind in patterns:
        for m in re.finditer(pat, body, re.DOTALL):
            line_no = body[:m.start()].count("\n") + 1
            calls.append((m.start(), kind, m.group()[:60], line_no))
    return sorted(calls, key=lambda x: x[0])


def _find_state_writes(body: str, state_vars: list) -> list:
    """Find state variable assignments in function body."""
    writes = []
    var_names = [sv.get("name", "") for sv in state_vars if sv.get("name")]
    for v in var_names:
        # Match: var = ..., var += ..., var -= ..., var[index] = ..., mapping[v].field = ...
        pat = rf"(?:{re.escape(v)}\s*\[[^\]]*\]\s*=|{re.escape(v)}\s*=|mapping|balances?\s*\[)"
        for m in re.finditer(pat, body):
            line_no = body[:m.start()].count("\n") + 1
            writes.append((m.start(), f"state_write:{v}", m.group()[:40], line_no))
    return sorted(writes, key=lambda x: x[0])


def _cei_violation(body: str, func_name: str, state_vars: list) -> tuple:
    """Detect CEI (Checks-Effects-Interactions) violation."""
    calls = _find_external_calls(body)
    writes = _find_state_writes(body, state_vars)
    if not calls or not writes:
        return False, ""
    first_call_pos = calls[0][0]
    first_write_pos = writes[0][0]
    if first_call_pos < first_write_pos:
        return True, (
            f"CEI violation in '{func_name}': external call at line {calls[0][3]} "
            f"({calls[0][2]}) before state write at line {writes[0][3]} ({writes[0][2]})"
        )
    return False, ""


def _unprotected_flash_loan(code: str, func, body: str) -> tuple:
    """Detect flashLoan where receiver is a parameter without msg.sender check."""
    if "flash" not in func.name.lower() and "flash" not in body.lower():
        return False, ""
    has_receiver_param = any(
        p in ("receiver", "borrower", "recipient", "_receiver", "_borrower")
        for p in func.parameters
    )
    if not has_receiver_param:
        return False, ""
    # Check if any external call targets the receiver (receiver.call{value}() or receiver.transfer())
    has_transfer_to_receiver = bool(re.search(
        r"\b(receiver|borrower|recipient)\s*\.\w+(?:\{[^}]*\})?\s*\([^)]*\)", body, re.IGNORECASE
    ))
    if not has_transfer_to_receiver:
        return False, ""
    # Check if msg.sender == receiver constraint exists
    if re.search(r"(?:msg\.sender|_msgSender\(\))\s*==\s*(?:address\s*\(\s*)?(?:receiver|borrower|recipient)",
                 body, re.IGNORECASE):
        return False, ""
    # Also check if caller must be receiver via require (only if checking msg.sender == receiver)
    if re.search(r"require\s*\([^)]*(?:msg\.sender|_msgSender)\s*==\s*(?:address\s*\(\s*)?(?:receiver|borrower|recipient)",
                 body, re.IGNORECASE):
        return False, ""
    return True, (
        f"Unprotected flash loan receiver in '{func.name}': anyone can trigger "
        f"flash loan on behalf of another address, draining their funds via fees"
    )


def _balanceof_accounting(contract) -> tuple:
    """Detect totalAssets() returning balanceOf(address(this))."""
    for func in contract.functions:
        if func.name == "totalAssets":
            # Check if function body uses balanceOf(address(this))
            # We need to scan the function — use the contract's source
            # Since we don't have the body text here, we check AST flags
            if not hasattr(func, 'external_calls') or 'balanceOf' not in func.external_calls:
                continue
            # Flag based on return pattern using contract source code context
            return True, (
                f"totalAssets() relies on balanceOf(address(this)) in '{contract.name}' — "
                f"anyone can inflate totalAssets via direct token transfer, "
                f"breaking ERC4626 invariant checks"
            )
    return False, ""


def _arbitrary_call(func, body: str) -> tuple:
    """Detect user-supplied target+data executed as external call."""
    has_target_param = any(
        p in ("target", "to", "addr", "contract", "implementation", "_target", "_to", "_addr")
        for p in func.parameters
    )
    has_data_param = any(
        p in ("data", "calldata", "payload", "_data", "_calldata", "_payload")
        for p in func.parameters
    )
    if not (has_target_param or has_data_param):
        return False, ""
    if has_target_param and has_data_param:
        return True, (
            f"Arbitrary external call in '{func.name}': both target and data "
            f"are user-supplied parameters — attacker controls both destination and logic"
        )
    return False, ""


def _cross_function_reentrancy(contract) -> tuple:
    """Detect cross-function reentrancy risk: 2+ functions sharing state + external calls."""
    ext_call_fns = []
    for func in contract.functions:
        if func.external_calls and not any(
            mod in func.modifiers for mod in ("nonReentrant", "reentrancyGuard")
        ):
            ext_call_fns.append(func.name)
    shared_state = {}
    for func in contract.functions:
        if func.name in ext_call_fns:
            for sv in contract.state_vars:
                sv_name = sv.get("name", "")
                if sv_name:
                    shared_state.setdefault(sv_name, []).append(func.name)
    risky_pairs = [(s, fns) for s, fns in shared_state.items() if len(fns) >= 2]
    if risky_pairs:
        details = "; ".join(f"{s}: {', '.join(fns)}" for s, fns in risky_pairs[:3])
        return True, (
            f"Cross-function reentrancy in '{contract.name}': "
            f"{len(ext_call_fns)} unprotected external-call functions share state ({details})"
        )
    return False, ""


_FUNCTION_RULES = [
    ("CEI Violation", _cei_violation, "High"),
    ("Unprotected Flash Loan Receiver", _unprotected_flash_loan, "High"),
    ("Arbitrary External Call (AST)", _arbitrary_call, "Critical"),
]

_CONTRACT_RULES = [
    ("balanceOf-based Accounting", _balanceof_accounting, "High"),
]


def analyze_ast(code: str) -> str:
    """Run Level 2 AST semantic analysis. Returns formatted text for pre-scan."""
    if not _has_ast:
        return ""
    units = compile_to_ast(code)
    if not units:
        return ""
    contracts = analyze_contracts(units)
    if not contracts:
        return ""

    findings = []
    for contract in contracts:
        for rule_name, rule_fn, severity in _CONTRACT_RULES:
            ok, msg = rule_fn(contract)
            if ok:
                findings.append(f"- [{severity}] {rule_name}: {msg}")

        for func in contract.functions:
            body = _get_function_body(code, func.name, func.parameters)
            if not body:
                continue
            for rule_name, rule_fn, severity in _FUNCTION_RULES:
                if rule_name == "CEI Violation":
                    ok, msg = rule_fn(body, func.name, contract.state_vars)
                elif rule_name == "Unprotected Flash Loan Receiver":
                    ok, msg = rule_fn(code, func, body)
                elif rule_name == "Arbitrary External Call (AST)":
                    ok, msg = rule_fn(func, body)
                if ok:
                    findings.append(f"- [{severity}] {rule_name}: {msg}")

        ok, msg = _cross_function_reentrancy(contract)
        if ok:
            findings.append(f"- [Critical] Cross-function Reentrancy: {msg}")

    # Level 3 CFG flow analysis
    if _has_cfg:
        try:
            cfg_findings = _run_cfg(code)
            if cfg_findings:
                findings.extend(cfg_findings)
        except Exception as e:
            logger.debug(f"CFG analysis skipped: {e}")

    if not findings:
        return ""
    parts = ["### Pre-Scan: AST Semantic Analysis (Level 2)"] + findings
    logger.info(f"AST detector: {len(findings)} semantic finding(s)")
    return "\n".join(parts)
