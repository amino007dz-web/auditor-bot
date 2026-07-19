"""
Solidity AST parser — using solcx + solcast instead of Regex
"""
import os
import re
import logging
from typing import List, Dict, Optional, Any, Callable
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

try:
    import solcx
    from solcast import from_ast
    HAS_SOLCAST = True
except ImportError:
    solcx = None
    from_ast = None
    HAS_SOLCAST = False

SOLC_VERSION = "0.8.25"


@dataclass
class ASTContract:
    name: str
    kind: str  # contract / library / interface
    functions: List[Dict] = field(default_factory=list)
    state_vars: List[Dict] = field(default_factory=list)
    modifiers: List[str] = field(default_factory=list)
    base_contracts: List[str] = field(default_factory=list)
    uses_delegatecall: bool = False
    uses_assembly: bool = False
    uses_selfdestruct: bool = False
    has_initializer: bool = False
    has_initialized_var: bool = False


@dataclass
class ASTFunction:
    name: str = ""
    visibility: str = "public"
    state_mutability: str = "nonpayable"
    modifiers: List[str] = field(default_factory=list)
    calls: List[str] = field(default_factory=list)
    has_require: bool = False
    has_assert: bool = False
    uses_assembly: bool = False
    has_loop: bool = False
    uses_call_value: bool = False
    uses_delegatecall: bool = False
    uses_tx_origin: bool = False
    uses_block_timestamp: bool = False
    uses_selfdestruct: bool = False
    external_calls: List[str] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)
    return_count: int = 0
    is_constructor: bool = False
    is_fallback: bool = False
    is_receive: bool = False
    has_unchecked_block: bool = False
    variables: List[str] = field(default_factory=list)
    body: str = ""


IMPORT_RE = re.compile(r'import\s+(?:\{[^}]*\}\s+from\s+)?["\']([^"\']+)["\']\s*;')


def resolve_imports(code: str, file_path: str = "", search_paths: list = None) -> str:
    """Resolve import statements and inline imported files."""
    imported_code = ""

    def _resolve_one(path: str) -> str:
        if os.path.isabs(path) or ".." in path:
            logger.warning(f"Blocked suspicious import path: {path}")
            return ""
        allowed_exts = {".sol", ".vy", ".move"}
        ext = os.path.splitext(path)[1].lower()
        if ext and ext not in allowed_exts:
            logger.warning(f"Blocked import with disallowed extension: {path}")
            return ""
        candidates = []
        if file_path:
            candidates.append(os.path.join(os.path.dirname(os.path.abspath(file_path)), path))
        if search_paths:
            for sp in search_paths:
                candidates.append(os.path.join(sp, path))
        if not candidates:
            return ""
        base_dir = os.path.commonpath(candidates)
        for cp in candidates:
            norm = os.path.normpath(cp)
            if not norm.startswith(base_dir):
                logger.warning(f"Blocked path traversal outside search paths: {norm}")
                return ""
            if os.path.exists(norm):
                try:
                    with open(norm, "r", encoding="utf-8") as fh:
                        return fh.read()
                except Exception:
                    pass
        return ""

    for m in IMPORT_RE.finditer(code):
        imp_path = m.group(1)
        resolved = _resolve_one(imp_path)
        if resolved:
            imported_code += f"\n// === Import: {imp_path} ===\n{resolved}\n"

    if imported_code:
        return code + "\n" + imported_code
    return code


def compile_to_ast(code: str, file_path: str = "", search_paths: list = None) -> Optional[List]:
    """Compile Solidity code to AST using solcx + solcast, with import resolution"""
    try:
        resolved = resolve_imports(code, file_path, search_paths) if file_path else code
        if SOLC_VERSION not in solcx.get_installed_solc_versions():
            solcx.install_solc(SOLC_VERSION, show_progress=False)
        result = solcx.compile_source(resolved, output_values=['ast'], solc_version=SOLC_VERSION)
        if not result:
            return None
        key = list(result.keys())[0]
        ast_json = result[key]['ast']
        return from_ast(ast_json)
    except Exception as e:
        logger.warning(f"Failed AST compilation: {e}")
        return None


def _get_node_type(node) -> str:
    return type(node).__name__


def _get_name(node) -> str:
    return getattr(node, 'name', '') or ''


def _has_modifier(func_node, modifier_name: str) -> bool:
    for mod_node in func_node.children():
        if _get_node_type(mod_node) == 'ModifierInvocation':
            mod_name = _get_name(mod_node)
            if mod_name == modifier_name:
                return True
    return False


def _traverse(node, predicate: Callable, _depth: int = 0) -> List:
    """Traverse AST searching for nodes matching predicate"""
    if _depth > 500:
        logger.warning("AST traversal exceeded max depth 500 — stopping recursion")
        return []
    results = []
    if predicate(node):
        results.append(node)
    try:
        for child in node.children():
            results.extend(_traverse(child, predicate, _depth + 1))
    except Exception:
        logger.debug(f"AST traversal error at depth {_depth}", exc_info=True)
    return results


def analyze_contracts(ast_units: List) -> List[ASTContract]:
    """Analyze AST and extract contract information"""
    contracts = []
    for unit in ast_units:
        if _get_node_type(unit) != 'ContractDefinition':
            continue
        c = ASTContract(name=getattr(unit, 'name', ''), kind=getattr(unit, 'contractKind', 'contract'))
        c.base_contracts = [getattr(b, 'name', '') for b in getattr(unit, 'baseContracts', [])]

        for node in getattr(unit, 'nodes', []):
            ntype = _get_node_type(node)

            if ntype == 'FunctionDefinition':
                fn = _extract_function(node)
                c.functions.append(fn)
                if fn.uses_delegatecall:
                    c.uses_delegatecall = True
                if fn.uses_selfdestruct:
                    c.uses_selfdestruct = True
                if fn.uses_assembly:
                    c.uses_assembly = True
                if fn.name == 'initialize' or fn.name.startswith('__init__'):
                    c.has_initializer = True
                if any('initialized' in m.lower() for m in fn.modifiers) or \
                   any('initialized' in v.lower() for v in fn.variables + [fn.name]):
                    c.has_initialized_var = True

            elif ntype == 'VariableDeclaration':
                var_name = _get_name(node)
                c.state_vars.append({'name': var_name, 'type': _get_name(node)})

            elif ntype == 'ModifierDefinition':
                c.modifiers.append(_get_name(node))

        contracts.append(c)
    return contracts


def _extract_function(func_node) -> ASTFunction:
    """Extract function info from AST + Text fallback for calls"""
    fn = ASTFunction(name=_get_name(func_node))
    fn.visibility = getattr(func_node, 'visibility', 'public')
    fn.state_mutability = getattr(func_node, 'stateMutability', 'nonpayable')
    fn.is_constructor = getattr(func_node, 'isConstructor', False) or fn.name == 'constructor'
    fn.is_fallback = getattr(func_node, 'isFallback', False)
    fn.is_receive = getattr(func_node, 'isReceive', False)

    # Parameters
    params = getattr(func_node, 'parameters', None)
    if params:
        for p in params.children():
            if _get_node_type(p) == 'VariableDeclaration':
                fn.parameters.append(_get_name(p))

    # Return parameters
    ret = getattr(func_node, 'returnParameters', None)
    if ret:
        fn.return_count = len(list(ret.children()))

    # Modifiers — modifierName is IdentifierPath with name
    for child in func_node.children():
        if _get_node_type(child) == 'ModifierInvocation':
            mod_name = getattr(child, 'modifierName', None)
            if mod_name:
                fn.modifiers.append(_get_name(mod_name))
            else:
                fn.modifiers.append(_get_name(child))

    # Traverse AST body to detect structures
    body = getattr(func_node, 'body', func_node)
    all_nodes = _traverse(body, lambda n: True) if HAS_SOLCAST else []

    for n in all_nodes:
        nt = _get_node_type(n)
        name = _get_name(n)

        if nt == 'MemberAccess':
            member = getattr(n, 'memberName', '')
            if member == 'delegatecall':
                if 'delegatecall' not in fn.external_calls:
                    fn.uses_delegatecall = True
                    fn.external_calls.append('delegatecall')
            elif member == 'call':
                if 'call' not in fn.external_calls:
                    fn.uses_call_value = True
                    fn.external_calls.append('call')
            elif member == 'origin':
                expr = getattr(n, 'expression', None)
                if expr and _get_name(expr) == 'tx':
                    fn.uses_tx_origin = True
            elif member == 'timestamp':
                expr = getattr(n, 'expression', None)
                if expr and _get_name(expr) == 'block':
                    fn.uses_block_timestamp = True
            elif member in ('transfer', 'send'):
                if member not in fn.external_calls:
                    fn.external_calls.append(member)

        elif nt == 'Identifier':
            if name == 'tx':
                fn.uses_tx_origin = True
            elif name == 'block':
                fn.uses_block_timestamp = True
            elif name in ('require', 'assert'):
                if name == 'require':
                    fn.has_require = True
                else:
                    fn.has_assert = True
            elif name == 'selfdestruct':
                fn.uses_selfdestruct = True
            elif name in ('delegatecall', 'callcode'):
                fn.uses_delegatecall = True
                fn.external_calls.append(name)

        elif nt == 'InlineAssembly':
            fn.uses_assembly = True

        elif nt in ('ForStatement', 'WhileStatement', 'DoWhileStatement'):
            fn.has_loop = True

        elif nt == 'UncheckedBlock':
            fn.has_unchecked_block = True

        elif nt == 'VariableDeclarationStatement':
            for decl in getattr(n, 'declarations', []):
                fn.variables.append(_get_name(decl))

    return fn


def has_reentrancy_pattern(func: ASTFunction, contract_modifiers: list = None) -> bool:
    """Detect reentrancy: call/transfer without nonReentrant"""
    if not func.external_calls:
        return False
    # If nonReentrant modifier exists, it's protected
    if contract_modifiers and 'nonReentrant' in contract_modifiers:
        return False
    if 'nonReentrant' in func.modifiers:
        return False
    return True


def has_unchecked_loop(func: ASTFunction) -> bool:
    """Detect loop without maximum bound"""
    names = ' '.join([func.name] + func.modifiers + func.variables + func.external_calls + func.parameters)
    return func.has_loop and 'MAX' not in names and 'max' not in names
