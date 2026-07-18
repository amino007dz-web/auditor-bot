"""
Move language AST parser — proper brace/paren matching instead of raw regex.
"""
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set


@dataclass
class MoveField:
    name: str
    type_name: str

@dataclass
class MoveStruct:
    name: str
    abilities: Set[str]
    fields: List[MoveField]
    line_start: int
    line_end: int

@dataclass
class MoveFunction:
    name: str
    visibility: str  # public, public(friend), public(entry), entry, or ""
    params: List[tuple]  # (name, type)
    return_type: Optional[str]
    line_start: int
    line_end: int
    body: str

@dataclass
class MoveSpec:
    name: str
    body_lines: List[str]

@dataclass
class MoveModule:
    address: str
    name: str
    structs: List[MoveStruct]
    functions: List[MoveFunction]
    specs: List[MoveSpec]
    friends: List[str]
    code: str


def _skip_string_comment(line: str, start: int) -> int:
    in_string = False
    in_line_comment = False
    i = start
    while i < len(line):
        ch = line[i]
        next_ch = line[i + 1] if i + 1 < len(line) else ""
        if not in_string and not in_line_comment and ch == '/' and next_ch == '/':
            in_line_comment = True
            i += 1
            continue
        if not in_string and not in_line_comment and ch == '/' and next_ch == '*':
            return i + 2
        if not in_string and not in_line_comment and ch == '*' and next_ch == '/':
            return i + 2
        if ch == '"' and not in_line_comment and (i == 0 or line[i - 1] != '\\'):
            in_string = not in_string
        i += 1
        if in_line_comment:
            break
    return i

def _find_block_end(lines: List[str], start_line: int, open_ch: str = "{", close_ch: str = "}") -> int:
    """Find matching closing brace starting from start_line, ignoring strings/comments."""
    depth = 0
    started = False
    for i in range(start_line, len(lines)):
        line = lines[i]
        j = 0
        while j < len(line):
            ch = line[j]
            next_ch = line[j + 1] if j + 1 < len(line) else ""
            if ch == '/' and next_ch == '/':
                break
            if ch == '/' and next_ch == '*':
                end = line.find('*/', j + 2)
                j = end + 2 if end != -1 else len(line)
                continue
            if ch == '"' and (j == 0 or line[j - 1] != '\\'):
                j = _skip_string_comment(line, j + 1)
                continue
            if ch == open_ch:
                depth += 1
                started = True
            elif ch == close_ch:
                depth -= 1
            j += 1
        if started and depth <= 0:
            return i
    return len(lines) - 1


def _get_line(code: str, pos: int) -> int:
    return code[:pos].count("\n") + 1


def _extract_abilities(struct_decl_line: str) -> Set[str]:
    m = re.search(r'\bhas\s+([a-zA-Z_,\s]+?)\s*\{', struct_decl_line)
    if not m:
        m = re.search(r'\bhas\s+([a-zA-Z_,\s]+?)$', struct_decl_line)
    if m:
        raw = m.group(1)
        return {a.strip() for a in re.split(r'[, ]+', raw) if a.strip()}
    return set()


def parse_move_code(code: str) -> List[MoveModule]:
    """Parse Move source code into AST modules."""
    lines = code.split("\n")
    modules: List[MoveModule] = []

    # Locate module boundaries
    mod_pattern = re.compile(r'(?:\b(?:public\s+)?)\bmodule\s+(?:(\S+?)::)?(\w+)\s*\{')
    for mod_match in mod_pattern.finditer(code):
        addr = mod_match.group(1) or ""
        mod_name = mod_match.group(2)
        mod_start = _get_line(code, mod_match.start())
        mod_end = _find_block_end(lines, mod_start - 1)
        mod_code_block = "\n".join(lines[mod_start - 1:mod_end])

        structs: List[MoveStruct] = []
        functions: List[MoveFunction] = []
        specs: List[MoveSpec] = []
        friends: List[str] = []

        # Parse friend declarations
        for fr_match in re.finditer(r'\bfriend\s+(\S+?)\s*;', mod_code_block):
            friends.append(fr_match.group(1))

        # Parse structs with char-level brace matching
        struct_pattern = re.compile(r'(?:public\s+)?\bstruct\s+(\w+)\s*(?:<[^>]+>)?')
        for st_match in struct_pattern.finditer(mod_code_block):
            st_name = st_match.group(1)
            st_line = _get_line(mod_code_block, st_match.start())
            # Find opening brace
            obrace = mod_code_block.find("{", st_match.end())
            if obrace == -1:
                continue
            depth = 1
            pos = obrace + 1
            in_string = False
            while pos < len(mod_code_block) and depth > 0:
                ch = mod_code_block[pos]
                next_ch = mod_code_block[pos + 1] if pos + 1 < len(mod_code_block) else ""
                if ch == '"' and (pos == 0 or mod_code_block[pos - 1] != '\\'):
                    in_string = not in_string
                if not in_string:
                    if ch == '/' and next_ch == '/':
                        nxt = mod_code_block.find("\n", pos)
                        pos = nxt if nxt != -1 else len(mod_code_block)
                        continue
                    if ch == '{':
                        depth += 1
                    elif ch == '}':
                        depth -= 1
                pos += 1
            st_code = mod_code_block[st_match.start():pos]

            abilities = _extract_abilities(st_code)
            fields: List[MoveField] = []
            for fld_match in re.finditer(r'(\w+)\s*:\s*([^,}\n]+)', st_code):
                fname = fld_match.group(1).strip()
                ftype = fld_match.group(2).strip()
                if fname not in ("has",) and ftype:
                    fields.append(MoveField(fname, ftype))

            structs.append(MoveStruct(
                name=st_name, abilities=abilities, fields=fields,
                line_start=st_line + mod_start - 1,
                line_end=_get_line(mod_code_block, pos) + mod_start - 1,
            ))

        # Parse functions
        fn_pattern = re.compile(
            r'((?:public\s+(?:entry\s+|friend\s+)?|entry\s+)?)fun\s+(\w+)\s*\('
        )
        for fn_match in fn_pattern.finditer(mod_code_block):
            vis_str = fn_match.group(1).strip()
            fn_name = fn_match.group(2)
            fn_line = _get_line(mod_code_block, fn_match.start())

            # Extract parameter types up to the first ) without crossing {
            paren_depth = 0
            pos = fn_match.end()
            params_code = ""
            while pos < len(mod_code_block):
                ch = mod_code_block[pos]
                if ch == '(':
                    paren_depth += 1
                elif ch == ')':
                    if paren_depth == 0:
                        break
                    paren_depth -= 1
                elif ch == '{' and paren_depth == 0:
                    break
                params_code += ch
                pos += 1

            # Parse individual parameters
            params: List[tuple] = []
            for p in params_code.split(","):
                p = p.strip()
                if ':' in p:
                    pname, _, ptype = p.partition(":")
                    params.append((pname.strip(), ptype.strip()))

            # Determine return type (between ) and {)
            rest_after_paren = mod_code_block[pos + 1:] if pos < len(mod_code_block) else ""
            ret_match = re.match(r'\s*:\s*([^{(]+?)\s*\{', rest_after_paren)
            return_type = ret_match.group(1).strip() if ret_match else None

            # Find function body
            fn_body_start_line = _get_line(mod_code_block, pos + 1 if pos < len(mod_code_block) else fn_match.start()) - 1
            # Find the opening { for body
            body_search_start = mod_code_block.find("{", fn_match.end())
            if body_search_start == -1:
                continue
            body_start_line = _get_line(mod_code_block, body_search_start) - 1
            fn_end = _find_block_end(mod_code_block.split("\n"), body_start_line)
            fn_body = "\n".join(mod_code_block.split("\n")[body_start_line:fn_end + 1])

            functions.append(MoveFunction(
                name=fn_name, visibility=vis_str, params=params,
                return_type=return_type, line_start=fn_line + mod_start - 1,
                line_end=fn_end + mod_start - 1, body=fn_body,
            ))

        # Parse spec blocks
        for spec_match in re.finditer(r'\bspec\s+(\w+)', mod_code_block):
            sp_name = spec_match.group(1)
            sp_line = _get_line(mod_code_block, spec_match.start()) - 1
            sp_end = _find_block_end(mod_code_block.split("\n"), sp_line)
            sp_lines = mod_code_block.split("\n")[sp_line + 1:sp_end]
            specs.append(MoveSpec(name=sp_name, body_lines=[l.strip() for l in sp_lines if l.strip()]))

        modules.append(MoveModule(
            address=addr, name=mod_name, structs=structs,
            functions=functions, specs=specs, friends=friends,
            code=mod_code_block,
        ))

    return modules


def find_module_by_name(modules: List[MoveModule], name: str) -> Optional[MoveModule]:
    for m in modules:
        if m.name == name:
            return m
    return None


def find_function(modules: List[MoveModule], fn_name: str) -> List[MoveFunction]:
    result = []
    for m in modules:
        for f in m.functions:
            if f.name == fn_name:
                result.append(f)
    return result


def find_struct(modules: List[MoveModule], struct_name: str) -> List[MoveStruct]:
    result = []
    for m in modules:
        for s in m.structs:
            if s.name == struct_name:
                result.append(s)
    return result


def get_all_function_names(modules: List[MoveModule]) -> Set[str]:
    return {f.name for m in modules for f in m.functions}


def get_all_struct_names(modules: List[MoveModule]) -> Set[str]:
    return {s.name for m in modules for s in m.structs}


def generate_move_tree(modules: List[MoveModule]) -> str:
    """Generate a text representation of the Move AST."""
    lines = []
    for mod in modules:
        addr_prefix = f"{mod.address}::" if mod.address else ""
        lines.append(f"module {addr_prefix}{mod.name} {{")
        for fr in mod.friends:
            lines.append(f"  +-- friend {fr}")
        for st in mod.structs:
            ab_str = f" has {', '.join(sorted(st.abilities))}" if st.abilities else ""
            lines.append(f"  +-- struct {st.name}{ab_str} {{")
            for fd in st.fields:
                lines.append(f"  |   +-- {fd.name}: {fd.type_name}")
            lines.append(f"  |   `-- }}")
        for fn in mod.functions:
            vis = f"{fn.visibility} " if fn.visibility else ""
            ret = f": {fn.return_type}" if fn.return_type else ""
            params_str = ", ".join(f"{p[0]}: {p[1]}" for p in fn.params)
            lines.append(f"  +-- {vis}fun {fn.name}({params_str}){ret}")
        for sp in mod.specs:
            lines.append(f"  +-- spec {sp.name} {{...}}")
        lines.append(f"`-- }}")
    return "\n".join(lines)
