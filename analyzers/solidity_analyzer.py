"""
Solidity Static Analyzer — Based on AST instead of Regex (solcast + solcx)
"""
import re
import logging
from typing import List
from .base import LanguageAnalyzer, Agent, Finding, has_pattern
from .solidity_ast import (
    compile_to_ast, analyze_contracts, _extract_function, _traverse, _get_node_type, _get_name, HAS_SOLCAST,
    ASTContract, ASTFunction,
)

logger = logging.getLogger(__name__)


class SolidityAnalyzer(LanguageAnalyzer):
    name = "Solidity AST Static Analysis"
    language = "solidity"
    extensions = [".sol"]

    def __init__(self):
        super().__init__()
        self._contracts: List[ASTContract] = []
        self._ast_ok = False
        self._register_agents()

    def _register_agents(self):
        # ─── Critical ───
        self.add_agent(Agent("Reentrancy (AST)", "Critical", "Reentrancy", self._check_reentrancy_ast))
        self.add_agent(Agent("Flash Loan Attack Vector", "Critical", "Economic", self._check_flash_loan))
        self.add_agent(Agent("Delegatecall to Mutable Address", "Critical", "Access Control", self._check_delegatecall_mutable))
        self.add_agent(Agent("Selfdestruct", "Critical", "Access Control", self._check_selfdestruct))
        self.add_agent(Agent("Uninitialized Proxy", "Critical", "Access Control", self._check_uninitialized_proxy))
        self.add_agent(Agent("Arbitrary External Call", "Critical", "Reentrancy", self._check_arbitrary_call))
        self.add_agent(Agent("MEV: Sandwich Attack Vector", "Critical", "MEV", self._check_mev_sandwich))
        self.add_agent(Agent("MEV: JIT Liquidity Attack", "Critical", "MEV", self._check_jit_liquidity))

        # ─── High ───
        self.add_agent(Agent("DELEGATECALL Usage (AST)", "High", "Access Control", self._check_delegatecall))
        self.add_agent(Agent("tx.origin Auth (AST)", "High", "Access Control", self._check_tx_origin))
        self.add_agent(Agent("Unchecked Transfer", "High", "Economic", self._check_unchecked_transfer))
        self.add_agent(Agent("Unvalidated Address", "High", "Access Control", self._check_unvalidated_address))
        self.add_agent(Agent("Public Mint/Burn", "High", "Access Control", self._check_public_mint))
        self.add_agent(Agent("Unbounded Loop (AST)", "High", "DoS", self._check_unbounded_loop))
        self.add_agent(Agent("Storage Collision (Delegatecall)", "High", "Storage", self._check_storage_collision))

        # ─── Medium ───
        self.add_agent(Agent("block.timestamp Usage (AST)", "Medium", "Timing", self._check_block_timestamp))
        self.add_agent(Agent("Assembly Block (AST)", "Medium", "Security", self._check_assembly))
        self.add_agent(Agent("Centralization Risk", "Medium", "Access Control", self._check_only_owner))

        # ─── Low ───
        self.add_agent(Agent("No Zero Address Check", "Low", "Security", self._check_zero_address))
        self.add_agent(Agent("Magic Number", "Low", "Readability", self._check_magic_number))

        # ─── Info ───
        self.add_agent(Agent("safeTransfer (Good)", "Info", "Best Practice", self._check_safe_transfer))
        self.add_agent(Agent("Event Emission", "Info", "Best Practice", self._check_events))
        self.add_agent(Agent("Pragma Fixed", "Info", "Best Practice", self._check_pragma))

    def load_directory(self, path: str):
        files = super().load_directory(path)
        self._parse_ast()
        return files

    def analyze_file(self, filename: str, code: str) -> List[Finding]:
        """Analyze a single file with AST"""
        self._parse_single_file(filename, code)
        return super().analyze_file(filename, code)

    def _parse_single_file(self, fname: str, code: str):
        """Compile a single file to AST"""
        try:
            units = compile_to_ast(code)
            if units:
                self._contracts.extend(analyze_contracts(units))
                self._ast_ok = True
        except Exception as e:
            logger.debug(f"AST parse failed for {fname}: {e}")

    def _parse_ast(self):
        """Try to compile every Solidity file to AST"""
        for fname, code in self._files.items():
            try:
                units = compile_to_ast(code)
                if units:
                    self._contracts.extend(analyze_contracts(units))
                    self._ast_ok = True
            except Exception as e:
                logger.debug(f"AST parse failed for {fname}: {e}")

    def _get_fn(self, contract_name: str, fn_name: str) -> ASTFunction:
        """Look for a function in the analyzed contracts"""
        for c in self._contracts:
            if c.name == contract_name:
                for fn in c.functions:
                    if fn.name == fn_name:
                        return fn
        return ASTFunction(name=fn_name)

    def _make(self, fname, code, agent_name, severity, category, desc, fix="", snippet="", line=0):
        if snippet:
            return [Finding(agent_name, severity, category, fname, "", desc, snippet[:200], line, fix)]
        return []

    # ════════════════════════════════════════
    # AST-based checks (high precision)
    # ════════════════════════════════════════

    def _check_reentrancy_ast(self, fname, code):
        """AST: detect reentrancy — external call without nonReentrant"""
        findings = []
        for c in self._contracts:
            for fn in c.functions:
                if fn.external_calls and 'nonReentrant' not in fn.modifiers:
                    findings.append(Finding("Reentrancy (AST)", "Critical", "Reentrancy",
                                   fname, fn.name,
                                   f"Function '{fn.name}' calls {fn.external_calls[0]} without nonReentrant",
                                   f"def {fn.name}(): calls={fn.external_calls}", 0,
                                   "Follow the checks-effects-interactions pattern or add nonReentrant"))
        return findings

    def _check_delegatecall(self, fname, code):
        """AST: detect DELEGATECALL"""
        findings = []
        for c in self._contracts:
            for fn in c.functions:
                if fn.uses_delegatecall:
                    findings.append(Finding("DELEGATECALL Usage (AST)", "High", "Access Control",
                                   fname, fn.name, f"DELEGATECALL in '{fn.name}' changes storage context",
                                   f"def {fn.name}(): delegatecall", 0,
                                   "Make sure the target address is trusted"))
        return findings

    def _check_delegatecall_mutable(self, fname, code):
        """AST: DELEGATECALL on a mutable address"""
        findings = []
        for c in self._contracts:
            for fn in c.functions:
                if fn.uses_delegatecall and fn.parameters:
                    findings.append(Finding("Delegatecall to Mutable Address", "Critical", "Access Control",
                                   fname, fn.name,
                                   f"DELEGATECALL on a parameter address — can be spoofed",
                                   f"def {fn.name}({','.join(fn.parameters)})", 0,
                                   "Use a fixed immutable address"))
        return findings

    def _check_tx_origin(self, fname, code):
        """AST: detect tx.origin precisely"""
        findings = []
        for c in self._contracts:
            for fn in c.functions:
                if fn.uses_tx_origin:
                    severity = "High" if fn.has_require else "Medium"
                    findings.append(Finding("tx.origin Auth (AST)", severity, "Access Control",
                                   fname, fn.name,
                                   f"tx.origin in function '{fn.name}' — vulnerable to phishing",
                                   f"def {fn.name}(): uses tx.origin", 0, "Use msg.sender"))
        return findings

    def _check_block_timestamp(self, fname, code):
        """AST: detect block.timestamp"""
        findings = []
        for c in self._contracts:
            for fn in c.functions:
                if fn.uses_block_timestamp:
                    findings.append(Finding("block.timestamp Usage (AST)", "Medium", "Timing",
                                   fname, fn.name,
                                   f"block.timestamp in '{fn.name}' — can be manipulated",
                                   f"def {fn.name}(): uses block.timestamp", 0,
                                   "Do not use it to decide on funds"))
        return findings

    def _check_assembly(self, fname, code):
        findings = []
        for c in self._contracts:
            for fn in c.functions:
                if fn.uses_assembly:
                    findings.append(Finding("Assembly Block (AST)", "Medium", "Security",
                                   fname, fn.name,
                                   f"Assembly block in '{fn.name}' — not checked by compiler",
                                   f"def {fn.name}(): assembly", 0, "Minimize assembly usage"))
        return findings

    def _check_unbounded_loop(self, fname, code):
        findings = []
        for c in self._contracts:
            for fn in c.functions:
                if fn.has_loop:
                    findings.append(Finding("Unbounded Loop (AST)", "High", "DoS",
                                   fname, fn.name,
                                   f"Loop in '{fn.name}' with no max limit — may consume high Gas",
                                   f"def {fn.name}(): loop", 0, "Add a maximum iteration limit"))
        return findings

    # ════════════════════════════════════════
    # Shared checks (Regex + hybrid)
    # ════════════════════════════════════════

    def _check_selfdestruct(self, fname, code):
        findings = []
        for c in self._contracts:
            for fn in c.functions:
                if fn.uses_selfdestruct:
                    findings.append(Finding("Selfdestruct", "Critical", "Access Control",
                                   fname, fn.name,
                                   f"SELFDESTRUCT in '{fn.name}' — can destroy the contract", "", 0,
                                   "Remove selfdestruct or add protection"))
        if not findings and "selfdestruct" in code:
            findings.append(Finding("Selfdestruct", "Critical", "Access Control",
                           fname, "", "SELFDESTRUCT present in the code", code[:80], 0,
                           "Remove selfdestruct or add protection"))
        return findings

    def _check_uninitialized_proxy(self, fname, code):
        if "delegatecall" in code and "initialize" in code:
            has_init = False
            for c in self._contracts:
                if c.has_initializer or c.has_initialized_var:
                    has_init = True
                    break
            if not has_init and not has_pattern(code, r"initialized|_initialized"):
                return [Finding("Uninitialized Proxy", "Critical", "Access Control",
                        fname, "", "Proxy without initialized — anyone can call initialize", "", 0,
                        "Add initializer modifier")]
        return []

    def _check_arbitrary_call(self, fname, code):
        findings = []
        for m in re.finditer(r"\.call\s*\{[^}]{0,200}?value\s*:\s*(\w+)\}\s*\(", code, re.IGNORECASE):
            val = m.group(1)
            if val.isalpha() and val not in ("0", "msg.value"):
                findings.append(Finding("Arbitrary External Call", "Critical", "Reentrancy",
                               fname, "", f".call{{value: {val}}} — unverified value", m.group()[:80], 0))
        return findings

    def _check_only_owner(self, fname, code):
        if has_pattern(code, r"onlyOwner") and not has_pattern(code, r"renounceOwnership"):
            return [Finding("Centralization Risk", "Medium", "Access Control",
                    fname, "", "onlyOwner without renounceOwnership — centralization risk", "", 0,
                    "Add multi-sig or timelock")]
        return []

    def _check_zero_address(self, fname, code):
        findings = []
        for m in re.finditer(r"(transfer|send)\s*\((.+?)\)", code):
            to = m.group(2).strip()
            if to != "address(0)" and not has_pattern(code, r"require\s*\(.*\b" + re.escape(to) + r"\b\s*!=\s*address\(0\)"):
                findings.append(Finding("No Zero Address Check", "Low", "Security",
                               fname, "", f"Transfer to {to[:30]} without require(address(0) check)", m.group()[:60], 0,
                               "require(to != address(0))"))
        return findings

    def _check_magic_number(self, fname, code):
        findings = []
        for m in re.finditer(r"[^a-zA-Z]([5-9]\d{3,}|[1-9]\d{5,})[^a-zA-Z]", code):
            findings.append(Finding("Magic Number", "Low", "Readability",
                           fname, "", f"Magic number {m.group(1)} — prefer using constant", m.group()[:30]))
        return findings

    def _check_flash_loan(self, fname, code):
        if has_pattern(code, r"flashLoan|flash_loan|flashloan") and has_pattern(code, r"nonReentrant"):
            return [Finding("Flash Loan Attack Vector", "Critical", "Economic",
                    fname, "", "flashLoan with nonReentrant — check for callback attacks", "", 0)]
        if has_pattern(code, r"flashLoan|flash_loan"):
            return [Finding("Flash Loan Attack Vector", "Critical", "Economic",
                    fname, "", "flashLoan without nonReentrant — very dangerous", "", 0,
                    "Add nonReentrant modifier")]
        return []

    def _check_unvalidated_address(self, fname, code):
        findings = []
        for m in re.finditer(r"\.call\s*\{[^}]*\}\s*\((.+?)\)", code, re.IGNORECASE):
            args = m.group(1)
            if not has_pattern(args, r"address\(|msg\.sender|owner|this"):
                findings.append(Finding("Unvalidated Address", "High", "Access Control",
                               fname, "", f"Call to an unverified address: {args[:40]}", m.group()[:80], 0,
                               "Verify that the address is trustworthy"))
        return findings

    def _check_unchecked_transfer(self, fname, code):
        findings = []
        for m in re.finditer(r"\.transfer\(|\.send\(", code, re.IGNORECASE):
            findings.append(Finding("Unchecked Transfer", "High", "Economic",
                           fname, "", f"Using {m.group()} — may fail (Gas limit 2300)", m.group()[:40], 0,
                           "Use safeTransfer / call{value} instead"))
        return findings

    def _check_public_mint(self, fname, code):
        if has_pattern(code, r"function\s+mint\s*\(") and has_pattern(code, r"public\s+"):
            return [Finding("Public Mint/Burn", "High", "Access Control",
                    fname, "", "mint() function is public — anyone can create tokens", "", 0,
                    "Add onlyOwner or specific permission")]
        return []

    def _check_storage_collision(self, fname, code):
        if has_pattern(code, r"delegatecall") and has_pattern(code, r"struct|mapping\s*\("):
            return [Finding("Storage Collision (Delegatecall)", "High", "Storage",
                    fname, "", "delegatecall with struct/mapping — slot collision risk", "", 0,
                    "Ensure layout matches the called contract")]
        return []

    def _check_safe_transfer(self, fname, code):
        findings = []
        for m in re.finditer(r"safeTransfer\s*\(", code):
            findings.append(Finding("safeTransfer (Good)", "Info", "Best Practice",
                           fname, "", "Uses safeTransfer — good", m.group()[:40]))
        return findings

    def _check_events(self, fname, code):
        if not has_pattern(code, r"emit\s"):
            return [Finding("Event Emission", "Info", "Best Practice",
                    fname, "", "Contract does not emit events (emit)", "", 0, "Add events to track changes")]
        return []

    def _check_pragma(self, fname, code):
        if has_pattern(code, r"pragma solidity\s*\^"):
            return [Finding("Pragma Fixed", "Info", "Best Practice",
                    fname, "", "pragma with ^ — may cause compatibility issues", "", 0,
                    "Use a fixed pragma solidity 0.8.xx")]
        return []

    def _check_mev_sandwich(self, fname, code):
        findings = []
        has_swap = has_pattern(code, r"\bswap\b")
        has_reserve = has_pattern(code, r"reserve|getReserves")
        has_skim = has_pattern(code, r"\bskim\b")
        has_sync = has_pattern(code, r"\bsync\b")
        has_update_pool = has_pattern(code, r"update\w*Pool|_update|mint\s*\(|burn\s*\(")
        if has_swap and (has_reserve or has_skim or has_sync or has_update_pool):
            if has_skim or has_sync:
                risk = "High — skim/sync pool manipulation possible"
            else:
                risk = "detected — check front-running protection"
            findings.append(Finding("MEV: Sandwich Attack Vector", "Critical", "MEV",
                            fname, "", f"DEX swap function with pool state updates — {risk}", "", 0,
                            "Add slippage protection (minOut) and deadline"))
        return findings

    def _check_jit_liquidity(self, fname, code):
        if has_pattern(code, r"\bswap\b") and has_pattern(code, r"\baddLiquidity\b|\bmint\b.*\blp\b"):
            return [Finding("MEV: JIT Liquidity Attack", "Critical", "MEV",
                    fname, "", "swap + addLiquidity in same contract — JIT liquidity sandwich vector", "", 0,
                    "Use a commit-reveal scheme or TWAP oracle")]