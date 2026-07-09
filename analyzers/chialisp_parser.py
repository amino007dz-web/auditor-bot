"""
Shared Chialisp parser — dataclasses + extraction functions
Used by chialisp_analyzer, fifty_agents, thousand_agents, tenk_agents
"""
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set


@dataclass
class FuncDef:
    name: str
    file: str
    code: str
    line_start: int
    line_end: int
    is_inline: bool = False
    params: List[str] = field(default_factory=list)
    calls: Set[str] = field(default_factory=set)
    vars: Set[str] = field(default_factory=set)


def extract_functions(code: str, filename: str) -> List[FuncDef]:
    funcs = []
    for m in re.finditer(r'\(defun(?:-inline)?\s+(\S+)\s+\(', code):
        name = m.group(1)
        start = code[:m.start()].count('\n') + 1
        depth = 0
        pos = m.start()
        while pos < len(code):
            if code[pos] == '(':
                depth += 1
            elif code[pos] == ')':
                depth -= 1
            if depth == 0 and pos > m.end():
                break
            pos += 1
        end = code[:pos].count('\n') + 1
        func_code = code[m.start():pos + 1]
        is_inline = 'defun-inline' in m.group(0)
        params = _extract_params(func_code)
        calls = set(re.findall(r'\((\w[\w-]*)', func_code))
        vars_set = set(re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_-]*\b', func_code))
        funcs.append(FuncDef(
            name=name, file=filename, code=func_code,
            line_start=start, line_end=end, is_inline=is_inline,
            params=params, calls=calls, vars=vars_set,
        ))
    return funcs


def _extract_params(code: str) -> List[str]:
    m = re.search(r'\(defun(?:-inline)?\s+\S+\s+\(([^)]*)\)', code)
    if m:
        return [p.strip() for p in m.group(1).split() if p.strip()]
    return []


def check_code(pattern: str, code: str) -> bool:
    return bool(re.search(pattern, code))


def find_funcs_by_name(funcs: List[FuncDef], pattern: str) -> List[FuncDef]:
    return [f for f in funcs if re.search(pattern, f.name, re.IGNORECASE)]


def find_funcs_by_file(funcs: List[FuncDef], pattern: str) -> List[FuncDef]:
    return [f for f in funcs if re.search(pattern, f.file, re.IGNORECASE)]
