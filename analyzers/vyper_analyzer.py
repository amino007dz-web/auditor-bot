import re
from typing import List, Dict
from .base import LanguageAnalyzer, Agent, Finding, has_pattern
from .vyper_ast import parse_vyper_code, VyperContract, VyperFunction, HAS_VYPER


class VyperAnalyzer(LanguageAnalyzer):
    name = "Vyper Static Analysis"
    language = "vyper"
    extensions = [".vy"]

    def __init__(self):
        super().__init__()
        self._vyper_ast: List[VyperContract] = []
        self._vyper_funcs: Dict[str, VyperFunction] = {}
        self._register_agents()

    def analyze_file(self, filename: str, code: str) -> list:
        self._vyper_ast = parse_vyper_code(code)
        self._vyper_funcs = {}
        for c in self._vyper_ast:
            for fn in c.functions:
                self._vyper_funcs[fn.name] = fn
        return super().analyze_file(filename, code)

    def _register_agents(self):
        self.add_agent(Agent("Reentrancy (Missing @nonreentrant)", "Critical", "Reentrancy", self._check_reentrancy))
        self.add_agent(Agent("Unchecked External Call", "High", "Input Validation", self._check_unchecked_call))
        self.add_agent(Agent("Integer Overflow/Underflow", "High", "Arithmetic", self._check_integer_overflow))
        self.add_agent(Agent("Block Manipulation", "Medium", "Timing", self._check_block_manipulation))
        self.add_agent(Agent("Insecure __default__ Fallback", "High", "Access Control", self._check_default_fallback))
        self.add_agent(Agent("Dangerous Delegatecall", "Critical", "Access Control", self._check_delegatecall))
        self.add_agent(Agent("Selfdestruct", "Critical", "Access Control", self._check_selfdestruct))
        self.add_agent(Agent("Uninitialized Storage", "High", "Storage", self._check_uninitialized))
        self.add_agent(Agent("Unbounded Loop", "Medium", "DoS", self._check_unbounded_loop))
        self.add_agent(Agent("Weak PRNG", "High", "Cryptographic", self._check_weak_prng))
        self.add_agent(Agent("Timestamp Dependence", "Medium", "Timing", self._check_timestamp))
        self.add_agent(Agent("Unprotected Withdrawal", "High", "Access Control", self._check_unprotected_withdraw))
        self.add_agent(Agent("Missing Event Emission", "Medium", "Best Practice", self._check_missing_event))
        self.add_agent(Agent("Hardcoded Address", "Low", "Readability", self._check_hardcoded_addr))
        self.add_agent(Agent("Unused Function", "Low", "Style", self._check_unused_fn))
        self.add_agent(Agent("Public Function Named _", "Low", "Style", self._check_underscore_fn))
        self.add_agent(Agent("Missing @version Pragma", "Low", "Best Practice", self._check_version_pragma))
        self.add_agent(Agent("Empty Function Body", "Info", "Style", self._check_empty_fn))
        self.add_agent(Agent("Large Function", "Info", "Readability", self._check_large_fn))
        self.add_agent(Agent("Multiple External Calls", "Medium", "Reentrancy", self._check_multi_calls))
        self.add_agent(Agent("Reentrancy (CEI Violation)", "Critical", "Reentrancy", self._check_cei_violation))
        self.add_agent(Agent("Modifier Reentrancy", "High", "Reentrancy", self._check_modifier_reentrancy))
        self.add_agent(Agent("Unchecked Return Value", "High", "Input Validation", self._check_unchecked_return))
        self.add_agent(Agent("Unsafe Delegatecall Loop", "Critical", "Access Control", self._check_delegatecall_loop))
        self.add_agent(Agent("Non-reentrant Before External Call", "High", "Reentrancy", self._check_nonreentrant_order))
        self.add_agent(Agent("Missing Input Validation", "High", "Input Validation", self._check_input_validation))
        self.add_agent(Agent("Deprecated raw_call", "Medium", "Best Practice", self._check_deprecated_raw_call))
        self.add_agent(Agent("Incorrect Visibility", "Medium", "Access Control", self._check_visibility))
        self.add_agent(Agent("Selfdestruct in Fallback", "Critical", "Access Control", self._check_fallback_destruct))
        self.add_agent(Agent("Outdated Compiler Version", "Low", "Best Practice", self._check_outdated_version))

    def _make(self, fname, code, agent, severity, cat, desc, snippet="", func="", fix=""):
        return Finding(agent, severity, cat, fname, func, desc, snippet[:200], 0, fix)

    def _ast_fn_names(self) -> List[str]:
        return list(self._vyper_funcs.keys())

    def _ast_get_fn(self, name: str) -> VyperFunction:
        return self._vyper_funcs.get(name)

    def _has_decorator(self, fn: VyperFunction, dec: str) -> bool:
        return any(dec in d for d in fn.decorators)

    def _check_reentrancy(self, fname, code):
        findings = []
        for fn in self._vyper_funcs.values():
            has_nr = self._has_decorator(fn, "nonreentrant")
            makes_call = fn.has_raw_call or fn.has_send or bool(re.search(r'\w+\.\w+\(', fn.body))
            if makes_call and not has_nr:
                findings.append(self._make(fname, code, "Reentrancy (Missing @nonreentrant)", "Critical",
                              "Reentrancy", f"'{fn.name}' calls externally without @nonreentrant",
                              fn.name, fix="Add @nonreentrant decorator"))
        return findings

    def _check_unchecked_call(self, fname, code):
        findings = []
        for m in re.finditer(r'\b(raw_call|send)\s*\(', code):
            ctx = code[max(0, m.start()-60):m.end()+80]
            if not re.search(r'(success|assert|if\s+raw_call|if\s+send)', ctx):
                findings.append(self._make(fname, code, "Unchecked External Call", "High",
                              "Input Validation", f"Unchecked {m.group(1)}() call", m.group()[:60],
                              fix="Check return value"))
        return findings

    def _check_integer_overflow(self, fname, code):
        findings = []
        version = ""
        for c in self._vyper_ast:
            if c.version:
                version = c.version
        if version:
            try:
                ver = version.lstrip("~^>=<")
                parts = [int(x) for x in ver.split(".")]
                if len(parts) >= 2 and (parts[0] < 0 or (parts[0] == 0 and parts[1] < 3)):
                    findings.append(self._make(fname, code, "Integer Overflow/Underflow", "High",
                                  "Arithmetic", f"Vyper {version} before 0.3.0 — no overflow protection",
                                  version, fix="Upgrade to Vyper >= 0.3.0"))
            except ValueError:
                pass
        for m in re.finditer(r'\b(raw_add|raw_sub|raw_mul|unsafe_add|unsafe_sub|unsafe_mul)\s*\(', code):
            findings.append(self._make(fname, code, "Integer Overflow/Underflow", "High",
                          "Arithmetic", f"Using {m.group(1)}() without protection", m.group()[:50],
                          fix="Use safe arithmetic operations instead of raw_*"))
        if not findings:
            if re.search(r'[+\-*/]\s*=\s*\w+|for\s+\w+\s+in\s+range\([^)]*\)', code):
                findings.append(self._make(fname, code, "Integer Overflow/Underflow", "Medium",
                              "Arithmetic", "Without @version — assuming Vyper < 0.3.0", "",
                              fix="Add @version >= 0.3.0"))
        return findings

    def _check_block_manipulation(self, fname, code):
        findings = []
        for m in re.finditer(r'\bblock\.(number|timestamp|difficulty|prevhash|gaslimit)\b', code):
            ctx = code[max(0, m.start()-100):m.end()+20]
            if re.search(r'(if\s+|require\s*\(|assert\s*\()', ctx):
                findings.append(self._make(fname, code, "Block Manipulation", "Medium", "Timing",
                              f"block.{m.group(1)} in a condition — can be manipulated", m.group()[:50],
                              fix="Use an oracle instead of block.*"))
        return findings

    def _check_default_fallback(self, fname, code):
        findings = []
        for fn in self._vyper_funcs.values():
            if fn.name == "__default__" and (fn.has_raw_call or fn.has_send):
                findings.append(self._make(fname, code, "Insecure __default__ Fallback", "High",
                              "Access Control", "__default__() calls externally — reentrancy risk",
                              fn.name, fix="Minimize logic in __default__"))
        if not self._vyper_funcs:
            for m in re.finditer(r'(?:@external|@public)\s*\n\s*def\s+__default__\s*\(', code):
                for sm in re.finditer(r'\b(send|raw_call)\s*\(', code[m.end():m.end()+300]):
                    findings.append(self._make(fname, code, "Insecure __default__ Fallback", "High",
                                  "Access Control", f"__default__() uses {sm.group(1)}", m.group()[:50]))
                    break
        return findings

    def _check_delegatecall(self, fname, code):
        findings = []
        for m in re.finditer(r'raw_call\s*\(\s*(\w+)\s*,\s*\w+\s*,\s*(?:delegate|is_delegate_call)\s*=\s*True', code):
            findings.append(self._make(fname, code, "Dangerous Delegatecall", "Critical",
                          "Access Control", f"delegatecall to '{m.group(1)}'", m.group()[:60],
                          fix="Ensure the target is immutable"))
        for m in re.finditer(r'raw_call\s*\(\s*(\w+)\s*,', code):
            if m.group(1) not in ("msg.sender", "self"):
                findings.append(self._make(fname, code, "Unchecked raw_call Target", "High",
                              "Input Validation", f"raw_call to '{m.group(1)}' without verification", m.group()[:50]))
        return findings

    def _check_selfdestruct(self, fname, code):
        findings = []
        if has_pattern(code, r'selfdestruct|self_destruct|destroy'):
            return [self._make(fname, code, "Selfdestruct", "Critical", "Access Control",
                                "Contract uses selfdestruct — can be destroyed", "",
                                fix="Avoid selfdestruct or add strict permissions")]
        return []

    def _check_uninitialized(self, fname, code):
        findings = []
        for c in self._vyper_ast:
            for sv in c.state_vars:
                if not sv.get("name", "").strip():
                    continue
                if not re.search(rf'{re.escape(sv["name"])}\s*=\s*\w+', code):
                    findings.append(self._make(fname, code, "Uninitialized Storage Variable", "High",
                                  "Storage", f"Variable '{sv.get('name','?')}' without initializer",
                                  sv.get("name",""), fix="Initialize the variable at declaration"))
        return findings

    def _check_unbounded_loop(self, fname, code):
        findings = []
        for fn in self._vyper_funcs.values():
            if fn.has_loop:
                body = fn.body[:500]
                if not re.search(r'range\s*\(\s*\d+', body) and not re.search(r'len\(', body):
                    findings.append(self._make(fname, code, "Unbounded Loop", "Medium", "DoS",
                                  f"'{fn.name}' loop without a maximum limit", fn.name,
                                  fix="Add a maximum loop limit"))
        if not self._vyper_funcs:
            for m in re.finditer(r'for\s+\w+\s+in\s+range\s*\(([^)]*)\)', code):
                arg = m.group(1).strip()
                if not re.search(r'^\d+$', arg):
                    findings.append(self._make(fname, code, "Unbounded Loop", "Medium", "DoS",
                                  "Loop without maximum limit — may consume high Gas", m.group()[:40]))
        return findings

    def _check_weak_prng(self, fname, code):
        fn_names = self._ast_fn_names()
        if any("random" in n.lower() or "rand" in n.lower() for n in fn_names):
            return [self._make(fname, code, "Weak PRNG", "High", "Cryptographic",
                                "Random function in contract — can be manipulated", "",
                                fix="Use Chainlink VRF or external oracle")]
        return []

    def _check_timestamp(self, fname, code):
        findings = []
        for m in re.finditer(r'block\.timestamp', code):
            ctx = code[max(0, m.start()-80):m.end()+20]
            if re.search(r'(if\s+|require\s*\(|assert\s*\()', ctx):
                findings.append(self._make(fname, code, "Timestamp Dependence", "Medium", "Timing",
                              "block.timestamp in a condition — can be manipulated", m.group()[:40],
                              fix="Do not use block.timestamp in critical logic"))
        return findings

    def _check_unprotected_withdraw(self, fname, code):
        findings = []
        for fn in self._vyper_funcs.values():
            if re.search(r'(send|raw_call)\s*\(', fn.body) and \
               not self._has_decorator(fn, "nonreentrant") and \
               not re.search(r'(owner|admin|onlyOwner|only_admin)', fn.body):
                findings.append(self._make(fname, code, "Unprotected Withdrawal", "High",
                              "Access Control", f"'{fn.name}' withdraws funds without permission", fn.name,
                              fix="Add a modifier to check permissions"))
        return findings

    def _check_missing_event(self, fname, code):
        if not has_pattern(code, r'event\s+\w+|log\s+\w+'):
            return [self._make(fname, code, "Missing Event Emission", "Medium", "Best Practice",
                                "No events (events/logs) exist in the contract", "",
                                fix="Add log for important operations")]
        return []

    def _check_hardcoded_addr(self, fname, code):
        findings = []
        for m in re.finditer(r'0x[a-fA-F0-9]{40}', code):
            findings.append(self._make(fname, code, "Hardcoded Address", "Low", "Readability",
                          f"Hardcoded address: {m.group()[:20]}...", m.group(),
                          fix="Use immutable constant"))
        return findings

    def _check_unused_fn(self, fname, code):
        findings = []
        for fn_name, fn in self._vyper_funcs.items():
            if fn_name.startswith("_"):
                continue
            count = code.count(fn_name)
            if count <= 1:
                findings.append(self._make(fname, code, "Unused Function", "Low", "Style",
                              f"Function '{fn_name}' is unused", fn_name))
        return findings

    def _check_underscore_fn(self, fname, code):
        findings = []
        for fn_name, fn in self._vyper_funcs.items():
            if fn_name.startswith("_") and self._has_decorator(fn, "external"):
                findings.append(self._make(fname, code, "Public Function Named _", "Low", "Style",
                              f"External function starts with _: '{fn_name}'", fn_name))
        return findings

    def _check_version_pragma(self, fname, code):
        if not has_pattern(code, r'@version\s'):
            return [self._make(fname, code, "Missing @version Pragma", "Low", "Best Practice",
                                "No @version pragma — add @version >= 0.3.0", "",
                                fix="Add @version >= 0.3.0 at the beginning of the file")]
        return []

    def _check_empty_fn(self, fname, code):
        findings = []
        for fn_name, fn in self._vyper_funcs.items():
            body_clean = re.sub(r'#.*', '', fn.body).strip()
            if body_clean == f"def {fn_name}({', '.join(fn.params)}):" or len(body_clean) < 20:
                findings.append(self._make(fname, code, "Empty Function Body", "Info", "Style",
                              f"Function '{fn_name}' is empty — verify it is complete", fn_name))
        return findings

    def _check_large_fn(self, fname, code):
        findings = []
        for fn_name, fn in self._vyper_funcs.items():
            if fn.line_end - fn.line_start > 80:
                findings.append(self._make(fname, code, "Large Function", "Info", "Readability",
                              f"Function '{fn_name}' is too large ({fn.line_end - fn.line_start} lines)",
                              fn_name, fix="Split the function into smaller functions"))
        return findings

    def _check_multi_calls(self, fname, code):
        findings = []
        for fn_name, fn in self._vyper_funcs.items():
            calls = re.findall(r'\b(raw_call|send)\s*\(', fn.body)
            if len(calls) >= 2:
                has_nr = self._has_decorator(fn, "nonreentrant")
                findings.append(self._make(fname, code, "Multiple External Calls", "Medium",
                              "Reentrancy",
                              f"'{fn_name}' has {len(calls)} external call{' without @nonreentrant' if not has_nr else ''}",
                              fn_name, fix="Add @nonreentrant or apply CEI"))
        return findings

    def _check_cei_violation(self, fname, code):
        findings = []
        for fn_name, fn in self._vyper_funcs.items():
            if fn.has_raw_call or fn.has_send:
                body = fn.body
                last_modify = body.rfind("= ")
                last_call = max(body.rfind("raw_call"), body.rfind("send"))
                if last_call > 0 and last_modify > 0 and last_call < last_modify:
                    findings.append(self._make(fname, code, "Reentrancy (CEI Violation)", "Critical",
                                  "Reentrancy", f"'{fn_name}': state modification after external call",
                                  fn_name, fix="Apply Checks-Effects-Interactions"))
        return findings

    def _check_modifier_reentrancy(self, fname, code):
        findings = []
        for fn_name, fn in self._vyper_funcs.items():
            if (fn.has_raw_call or fn.has_send) and not self._has_decorator(fn, "nonreentrant"):
                if self._has_decorator(fn, "external") or self._has_decorator(fn, "public"):
                    findings.append(self._make(fname, code, "Modifier Reentrancy", "High", "Reentrancy",
                                  f"'{fn_name}' @external without @nonreentrant", fn_name,
                                  fix="Add @nonreentrant"))
        return findings

    def _check_unchecked_return(self, fname, code):
        findings = []
        for m in re.finditer(r'\braw_call\s*\(', code):
            start = max(0, m.start() - 80)
            end = min(len(code), m.end() + 120)
            ctx = code[start:end]
            if not re.search(r'(success|result|returned)', ctx):
                findings.append(self._make(fname, code, "Unchecked Return Value", "High",
                              "Input Validation", "raw_call without checking the result", m.group()[:40],
                              fix="Check the return value of raw_call"))
        return findings

    def _check_delegatecall_loop(self, fname, code):
        if has_pattern(code, r'for\s+\w+\s+in\s+range') and \
           has_pattern(code, r'raw_call.*delegate.*=.*True'):
            return [self._make(fname, code, "Unsafe Delegatecall Loop", "Critical", "Access Control",
                                "delegatecall inside a loop — can be exploited to take over the contract", "",
                                fix="Avoid delegatecall inside loops")]
        return []

    def _check_nonreentrant_order(self, fname, code):
        findings = []
        for fn_name, fn in self._vyper_funcs.items():
            if self._has_decorator(fn, "nonreentrant") and (fn.has_raw_call or fn.has_send):
                lines = fn.body.split("\n")
                nonre_idx = -1
                ext_idx = -1
                for i, line in enumerate(lines):
                    if "@nonreentrant" in line:
                        nonre_idx = i
                    if "raw_call" in line or "send" in line:
                        ext_idx = i
                if nonre_idx >= 0 and ext_idx >= 0 and nonre_idx > ext_idx:
                    findings.append(self._make(fname, code, "Non-reentrant After External Call", "High",
                                  "Reentrancy",
                                  f"'{fn_name}': @nonreentrant after external call", fn_name,
                                  fix="Place @nonreentrant before the function"))
        return findings

    def _check_input_validation(self, fname, code):
        findings = []
        for fn_name, fn in self._vyper_funcs.items():
            if (fn.has_raw_call or fn.has_send) and not re.search(r'(require|assert)\s*\(', fn.body):
                findings.append(self._make(fname, code, "Missing Input Validation", "High",
                              "Input Validation", f"'{fn_name}' without require/assert before the call",
                              fn_name, fix="Add require to validate inputs"))
        return findings

    def _check_deprecated_raw_call(self, fname, code):
        findings = []
        for m in re.finditer(r'raw_call\s*\(', code):
            ctx = code[max(0, m.start()-40):m.end()+60]
            if not re.search(r'(delegate|is_delegate_call)\s*=\s*True', ctx):
                findings.append(self._make(fname, code, "Deprecated raw_call Usage", "Medium",
                              "Best Practice", "Regular raw_call — use send for transfers", m.group()[:30],
                              fix="Use send() for ETH transfers instead of raw_call"))
        return findings

    def _check_visibility(self, fname, code):
        findings = []
        for fn_name, fn in self._vyper_funcs.items():
            if not any(self._has_decorator(fn, d) for d in ("external", "public", "internal", "private", "view", "pure")):
                findings.append(self._make(fname, code, "Incorrect Visibility", "Medium",
                              "Access Control", f"'{fn_name}' without visibility decorator", fn_name,
                              fix="Add @external or @internal or @view"))
        return findings

    def _check_fallback_destruct(self, fname, code):
        for fn_name, fn in self._vyper_funcs.items():
            if fn_name == "__default__" and has_pattern(fn.body, r'selfdestruct|self_destruct|destroy'):
                return [self._make(fname, code, "Selfdestruct in Fallback", "Critical", "Access Control",
                                    "__default__() can destroy the contract", fn_name,
                                    fix="Do not put selfdestruct in __default__")]
        return []

    def _check_outdated_version(self, fname, code):
        for c in self._vyper_ast:
            if c.version:
                try:
                    parts = [int(x) for x in c.version.lstrip("~^>=<>").split(".")]
                    if len(parts) >= 2 and (parts[0] < 0 or (parts[0] == 0 and parts[1] < 4)):
                        return [self._make(fname, code, "Outdated Compiler Version", "Low",
                                         "Best Practice", f"Vyper {c.version} is old — >= 0.4.0 is better",
                                         c.version, fix="Upgrade Vyper to >= 0.4.0")]
                except ValueError:
                    pass
        return []