"""
Vyper AST parser — using vyper compiler or Regex fallback
"""
import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set

logger = logging.getLogger(__name__)

try:
    import vyper
    from vyper.compiler import compile_code
    HAS_VYPER = True
except ImportError:
    HAS_VYPER = False


@dataclass
class VyperFunction:
    name: str
    decorators: List[str]
    body: str
    line_start: int
    line_end: int
    params: List[str] = field(default_factory=list)
    calls: Set[str] = field(default_factory=set)
    has_raw_call: bool = False
    has_send: bool = False
    has_loop: bool = False
    uses_block: bool = False
    uses_tx: bool = False


@dataclass
class VyperContract:
    name: str
    functions: List[VyperFunction]
    events: List[str]
    state_vars: List[Dict[str, str]]
    version: str = ""
    interfaces: List[str] = field(default_factory=list)
    code: str = ""
    uses_delegatecall: bool = False
    uses_selfdestruct: bool = False


def _vyper_compile_ast(code: str) -> Optional[List[VyperContract]]:
    """AST parsing using vyper compiler."""
    if not HAS_VYPER:
        return None
    try:
        ast_data = compile_code(code, ["ast"])["ast"]
        contracts = []
        body = ast_data.get("body", [])
        current_name = ""
        current_events = []
        current_vars = []
        current_ifaces = []
        functions = []
        version = ""
        for node in body:
            if node.get("ast_type") == "Pragma":
                for child in node.get("body", []):
                    if child.get("ast_type") == "VersionLiteral":
                        version = child.get("value", "")
            elif node.get("ast_type") in ("ContractDef", "InterfaceDef"):
                current_name = node.get("name", "Unknown")
                current_events = []
                current_vars = []
                functions = []
                for child in node.get("body", []):
                    ct = child.get("ast_type", "")
                    if ct == "FunctionDef":
                        fname = child.get("name", "")
                        decs = [d.get("func_name", "") for d in child.get("decorator_list", [])]
                        args = child.get("args", {})
                        params = [a.get("arg", "") for a in args.get("args", [])]
                        f = VyperFunction(
                            name=fname, decorators=decs, line_start=child.get("lineno", 1),
                            line_end=child.get("end_lineno", 1), params=params,
                            body="",
                        )
                        functions.append(f)
                    elif ct == "EventDef":
                        current_events.append(child.get("name", ""))
                    elif ct == "AnnAssign":
                        target = child.get("target", {})
                        vname = target.get("value", "") if isinstance(target, dict) else ""
                        annotation = child.get("annotation", {})
                        vtype = annotation.get("value", "") if isinstance(annotation, dict) else ""
                        current_vars.append({"name": vname, "type": vtype})
                contracts.append(VyperContract(
                    name=current_name, functions=functions, events=current_events,
                    state_vars=current_vars, version=version, interfaces=current_ifaces,
                    code=code, uses_delegatecall=False, uses_selfdestruct=False,
                ))
        return contracts or None
    except Exception as e:
        logger.debug(f"Vyper AST compilation failed: {e}")
        return None


def _is_vyper_decorator(line: str) -> bool:
    return bool(re.match(r'^\s*@\w+', line))


def _find_fn_end(lines: List[str], start: int) -> int:
    if start >= len(lines):
        return start
    first_line = lines[start]
    indent_len = len(first_line) - len(first_line.lstrip())
    paren_depth = first_line.count("(") - first_line.count(")")
    triple_quotes = False
    for i in range(start + 1, len(lines)):
        line = lines[i]
        stripped = line.strip()
        if triple_quotes:
            if stripped.count('"""') % 2 == 1 or stripped.count("'''") % 2 == 1:
                triple_quotes = False
            continue
        if stripped.startswith('"""') or stripped.startswith("'''"):
            if stripped.count('"""') % 2 == 1 or stripped.count("'''") % 2 == 1:
                triple_quotes = True
            continue
        if stripped.startswith("#"):
            continue
        paren_depth += line.count("(") - line.count(")")
        if paren_depth > 0:
            continue
        if stripped and not stripped.startswith(("@", "#", '"""', "'''")):
            current_indent = len(line) - len(line.lstrip())
            if current_indent <= indent_len:
                return i
    return len(lines)


def _regex_parse(code: str) -> List[VyperContract]:
    """Fallback: regex-based Vyper parsing."""
    lines = code.split("\n")
    contracts = []
    current_events = []
    current_vars = []
    functions = []
    cname = ""
    version = ""
    i = 0
    while i < len(lines):
        line = lines[i]
        s = line.strip()
        vm = re.match(r"@version\s+(\S+)", s)
        if vm:
            version = vm.group(1)
        im = re.match(r"#\s*(@version|@license|@notice|@dev|@param|@return)", s)
        im2 = re.match(r"import\s+(~[\w.]+|(\w+\.)*\w+)", s)
        sm = re.match(r"struct\s+(\w+)", s)
        em = re.match(r"event\s+(\w+)", s)
        if em:
            current_events.append(em.group(1))
        if sm:
            current_vars.append({"name": sm.group(1), "type": "struct"})
        if im2:
            continue
        if s.startswith(("@external", "@public", "@internal", "@view", "@pure",
                         "@payable", "@nonreentrant", "@decorator")):
            dec_lines = []
            while i < len(lines) and _is_vyper_decorator(lines[i].strip()):
                s_dec = lines[i].strip()
                if s_dec.startswith("@"):
                    dec_lines.append(s_dec.lstrip("@"))
                i += 1
            if i < len(lines):
                fm = re.match(r"def\s+(\w+)\s*\((.*?)\)", lines[i])
                if fm:
                    fname = fm.group(1)
                    params = [p.strip() for p in fm.group(2).split(",") if p.strip()]
                    fn_start = i
                    fn_end = _find_fn_end(lines, i)
                    body = "\n".join(lines[i:fn_end])
                    calls = set()
                    for m in re.finditer(r'(\w+)\s*\(', body):
                        calls.add(m.group(1))
                    functions.append(VyperFunction(
                        name=fname, decorators=dec_lines, body=body,
                        line_start=fn_start + 1, line_end=fn_end,
                        params=params, calls=calls,
                        has_raw_call="raw_call" in body,
                        has_send="send" in body,
                        has_loop="for " in body or "while " in body,
                        uses_block="block." in body,
                        uses_tx="tx." in body,
                    ))
                    i = fn_end
                    continue
        i += 1

    if functions or current_events or current_vars:
        cname = "Contract"
        contracts.append(VyperContract(
            name=cname, functions=functions, events=current_events,
            state_vars=current_vars, version=version, code=code,
        ))
    elif code.strip():
        contracts.append(VyperContract(
            name="Contract", functions=functions, events=current_events,
            state_vars=current_vars, version=version, code=code,
        ))
    return contracts


def parse_vyper_code(code: str) -> List[VyperContract]:
    """Parse Vyper code — uses compiler AST if available, else regex."""
    contracts = _vyper_compile_ast(code)
    if contracts:
        return contracts
    return _regex_parse(code)


def check_vyper(pattern: str, code: str) -> bool:
    return bool(re.search(pattern, code))
