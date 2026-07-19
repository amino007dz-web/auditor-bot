import re
from collections import defaultdict
from typing import List
from .base import LanguageAnalyzer, Agent, Finding, has_pattern
from .chialisp_parser import extract_functions as _extract_functions, check_code as _check_code


class ChialispAnalyzer(LanguageAnalyzer):
    name = "Chialisp Static Analysis"
    language = "chialisp"
    extensions = [".clsp", ".clib"]

    def __init__(self):
        super().__init__()
        self._funcs = []
        self._register_agents()

    def _register_agents(self):
        self.add_agent(Agent("List-Atom Type Confusion", "Critical", "Type Safety", self._agent_01))
        self.add_agent(Agent("Missing Hash Size Validation", "High", "Type Safety", self._agent_02))
        self.add_agent(Agent("Missing UInt64 Validation", "Medium", "Type Safety", self._agent_03))
        self.add_agent(Agent("Unvalidated Solution→Curried State", "Critical", "State Machine", self._agent_04))
        self.add_agent(Agent("Division By Zero", "Critical", "DoS", self._agent_05))
        self.add_agent(Agent("Negative Coin Amount", "Critical", "Economic", self._agent_06))
        self.add_agent(Agent("Timestamp Asymmetry", "High", "Timing", self._agent_07))
        self.add_agent(Agent("Missing Lineage Proof", "High", "State Machine", self._agent_08))
        self.add_agent(Agent("Missing Puzzle Hash Verification", "Medium", "State Machine", self._agent_09))
        self.add_agent(Agent("Unbounded List Recursion", "Medium", "DoS", self._agent_10))
        self.add_agent(Agent("Missing Statute Assertion", "High", "Access Control", self._agent_11))
        self.add_agent(Agent("Missing Coin ID Assertion", "Medium", "Access Control", self._agent_12))
        self.add_agent(Agent("Weak Announcement Binding", "Low", "Access Control", self._agent_13))
        self.add_agent(Agent("Message Mode Analysis", "Medium", "Access Control", self._agent_14))
        self.add_agent(Agent("Conditional Branch Type Bypass", "High", "Type Safety", self._agent_15))
        self.add_agent(Agent("Fee Rounding Direction", "Low", "Economic", self._agent_16))
        self.add_agent(Agent("Auction Price Logic", "Medium", "Economic", self._agent_17))
        self.add_agent(Agent("Discount Factor Manipulation", "Medium", "Economic", self._agent_18))
        self.add_agent(Agent("Collateral Ratio", "High", "Economic", self._agent_19))
        self.add_agent(Agent("Ceiling Division Analysis", "Medium", "Economic", self._agent_20))
        self.add_agent(Agent("Timestamp Consistency Across Protocol", "Info", "Timing", self._agent_21))
        self.add_agent(Agent("Time Window Bounds", "High", "Timing", self._agent_22))
        self.add_agent(Agent("Cost Exhaustion (Gas DoS)", "Medium", "DoS", self._agent_23))
        self.add_agent(Agent("Cross-Coin Reentrancy", "Low", "External Interaction", self._agent_24))
        self.add_agent(Agent("Missing Protocol Prefix", "Medium", "Spoofing", self._agent_25))
        self.add_agent(Agent("Min Bid Enforcement", "High", "Economic", self._agent_26))
        self.add_agent(Agent("Missing Uniqueness Check", "Medium", "DoS", self._agent_27))
        self.add_agent(Agent("Ephemeral Spend Locking", "Low", "Access Control", self._agent_28))
        self.add_agent(Agent("Unvalidated Coin Amount", "High", "State Machine", self._agent_29))
        self.add_agent(Agent("Oracle Price Staleness", "Medium", "Economic", self._agent_30))
        self.add_agent(Agent("Hash Collision Surface", "Low", "Cryptographic", self._agent_31))
        self.add_agent(Agent("Coin ID Forgery Risk", "Medium", "Cryptographic", self._agent_32))
        self.add_agent(Agent("Nil vs Zero Confusion", "Medium", "Type Safety", self._agent_33))
        self.add_agent(Agent("Infinite State Loop", "Info", "State Machine", self._agent_34))
        self.add_agent(Agent("Auction Fee Freeze", "Medium", "State Machine", self._agent_35))
        self.add_agent(Agent("Exponential Overflow", "Low", "Economic", self._agent_36))
        self.add_agent(Agent("Unbounded Governance Parameter", "Low", "Economic", self._agent_37))
        self.add_agent(Agent("Duplicate Detection", "Info", "DoS", self._agent_38))
        self.add_agent(Agent("Reorg Attack Surface", "Low", "Timing", self._agent_39))
        self.add_agent(Agent("Mempool Manipulation", "Low", "Timing", self._agent_40))
        self.add_agent(Agent("Protocol Prefix Spoofing", "Info", "Spoofing", self._agent_42))
        self.add_agent(Agent("Vault State Machine Completeness", "Medium", "State Machine", self._agent_43))
        self.add_agent(Agent("Savings Vault Interest Math", "Critical", "Economic", self._agent_44))
        self.add_agent(Agent("Treasury Ring Rebalance", "Medium", "Economic", self._agent_45))
        self.add_agent(Agent("CRT Tail Approval Logic", "Critical", "Access Control", self._agent_46))
        self.add_agent(Agent("BYC Tail Mint Authorization", "Critical", "Access Control", self._agent_47))
        self.add_agent(Agent("Payout Hijacking", "High", "Access Control", self._agent_48))
        self.add_agent(Agent("Vault Launch Uniqueness", "Low", "State Machine", self._agent_49))
        self.add_agent(Agent("Attack Chain Synthesis", "High", "Creative", self._agent_50))

    def load_directory(self, path: str):
        files = super().load_directory(path)
        self._funcs = []
        for fname, code in self._files.items():
            for f in _extract_functions(code, fname):
                self._funcs.append(f)
        return files

    def _find_funcs(self, pattern: str):
        from .chialisp_parser import find_funcs_by_name
        return find_funcs_by_name(self._funcs, pattern)

    def _make(self, fname, code, agent, severity, cat, desc, snippet="", func_name=""):
        return Finding(agent, severity, cat, fname, func_name, desc, snippet[:200])

    # Agent 1
    def _agent_01(self, fname, code):
        findings = []
        for f in [x for x in self._funcs if x.file == fname]:
            for m in re.finditer(r'\([+\-*/]\s+(\S+)', f.code):
                var = m.group(1).strip(')')
                if var.islower() and var not in ('x', 'one', 'false', 'true'):
                    has_check = _check_code(rf'\(not\s+\(l\s+{re.escape(var)}', f.code)
                    if not has_check:
                        sev = "Medium" if f.is_inline else "High"
                        findings.append(self._make(fname, code, "List-Atom Type Confusion", sev, "Type Safety",
                                                     f"'{var}' arithmetic without (not l) check", f.code[:150], f.name))
        return findings

    # Agent 2
    def _agent_02(self, fname, code):
        findings = []
        hash_kw = ['puzzle_hash', 'coin_id', 'mod_hash', 'tail_hash', 'launcher_id', 'parent_id']
        for kw in hash_kw:
            for m in re.finditer(rf'(\w*{kw}\w*)', code, re.IGNORECASE):
                p = m.group(1)
                if p and p[0].islower() and len(p) > 3:
                    if not _check_code(rf'\(is-size-b32\s+{re.escape(p)}', code) and \
                       not _check_code(rf'\(is-size-b32-or-nil\s+{re.escape(p)}', code):
                        findings.append(self._make(fname, code, "Missing Hash Size Validation", "High", "Type Safety",
                                                     f"'{p}' hash without is-size-b32", code[:150]))
        return findings

    # Agent 3
    def _agent_03(self, fname, code):
        findings = []
        for m in re.finditer(r'\([+\-*/]\s+(\w+)', code):
            n = m.group(1)
            if n and n[0].islower() and n not in ('x', 'one'):
                if not _check_code(rf'\(is-uint64\s+{re.escape(n)}', code):
                    findings.append(self._make(fname, code, "Missing UInt64 Validation", "Medium", "Type Safety",
                                                 f"'{n}' numeric without is-uint64", code[:150]))
        return findings

    # Agent 4
    def _agent_04(self, fname, code):
        findings = []
        if 'curry_hashes' in code:
            for m in re.finditer(r'\(sha256\s+ONE\s+(\w+)\)', code):
                v = m.group(1)
                if v and v[0].islower():
                    has_assert = _check_code(rf'\(assert.*\b{re.escape(v)}\b', code) or \
                                 _check_code(rf'\(is-uint64\s+{re.escape(v)}', code) or \
                                 _check_code(rf'>\s+{re.escape(v)}', code)
                    if not has_assert:
                        findings.append(self._make(fname, code, "Unvalidated Solution→Curried State", "Critical", "State Machine",
                                                     f"'{v}' into curry_hashes without validation", code[:200]))
        return findings

    # Agent 5
    def _agent_05(self, fname, code):
        findings = []
        for m in re.finditer(r'/\s+(\w+)', code):
            divisor = m.group(1).strip(')')
            if divisor and divisor[0].isalpha():
                has_zero = _check_code(rf'>\s+{re.escape(divisor)}\s+0', code) or \
                           _check_code(rf'>\s+{re.escape(divisor)}\s+MINUS_ONE', code)
                if not has_zero:
                    fn = next((x.name for x in self._funcs if x.file == fname and divisor in x.code), "")
                    sev = "Critical" if 'calculate-interest' in fn else "High"
                    findings.append(self._make(fname, code, "Division By Zero", sev, "DoS",
                                                 f"Division by '{divisor}' without zero-check", code[:150]))
        return findings

    # Agent 6
    def _agent_06(self, fname, code):
        findings = []
        for m in re.finditer(r'CREATE_COIN.*?(\w+)', code):
            amt = m.group(1)
            if amt and amt.islower() and amt not in ('x', 'one'):
                has_check = _check_code(rf'>\s+{re.escape(amt)}\s+MINUS_ONE', code) or \
                            _check_code(rf'\(is-uint64\s+{re.escape(amt)}', code) or \
                            _check_code(rf'>\s+{re.escape(amt)}\s+0', code)
                if not has_check:
                    findings.append(self._make(fname, code, "Negative Coin Amount", "Critical", "Economic",
                                                 f"CREATE_COIN amount '{amt}' without validation", code[:150]))
        return findings

    # Agent 7
    def _agent_07(self, fname, code):
        findings = []
        buffered = _check_code(r'current_timestamp\s*\+\s*\*\s*3\s*MAX_TX_BLOCK_TIME', code)
        has_calc = 'calculate-cumulative-discount-factor' in code
        if has_calc and 'current_timestamp' in code and not buffered:
            findings.append(self._make(fname, code, "Timestamp Asymmetry", "High", "Timing",
                                          "Uses current_timestamp without buffer 3*MAX_TX_BLOCK_TIME", code[:150]))
        return findings

    # Agent 8
    def _agent_08(self, fname, code):
        if 'lineage_proof' in code and 'ASSERT_MY_PARENT_ID' not in code:
            if 'launch' not in code.lower() and 'eve' not in code.lower():
                return [self._make(fname, code, "Missing Lineage Proof", "High", "State Machine",
                                     "Uses lineage_proof without ASSERT_MY_PARENT_ID", code[:150])]
        return []

    # Agent 9
    def _agent_09(self, fname, code):
        if 'CREATE_COIN' in code and 'ASSERT_MY_PUZZLEHASH' not in code:
            if fname not in ('run_tail.clsp', 'byc_tail.clsp', 'crt_tail.clsp'):
                return [self._make(fname, code, "Missing Puzzle Hash Verification", "Medium", "State Machine",
                                     "Creates coin without ASSERT_MY_PUZZLEHASH", code[:100])]
        return []

    # Agent 10
    def _agent_10(self, fname, code):
        findings = []
        for f in [x for x in self._funcs if x.file == fname]:
            if f.code.count(f.name) > 2:
                if not _check_code(r'list-length.*MAX', f.code) and \
                   not _check_code(r'>.*list-length', f.code):
                    findings.append(self._make(fname, code, "Unbounded List Recursion", "Medium", "DoS",
                                                 f"Recursive function '{f.name}' without cap", f.code[:150], f.name))
        return findings

    # Agent 11
    def _agent_11(self, fname, code):
        findings = []
        statute_vars = ['cumulative_stability_fee_df', 'stability_fee_df', 'cumulative_interest_df',
                        'interest_df', 'liquidation_ratio', 'minimum_debt', 'min_treasury_delta', 'price_info']
        for sv in statute_vars:
            if sv in code and 'assert-statute' not in code:
                findings.append(self._make(fname, code, "Missing Statute Assertion", "High", "Access Control",
                                             f"Uses statute '{sv}' without assert-statute", code[:100]))
        return findings

    # Agent 12
    def _agent_12(self, fname, code):
        if 'my_coin_id' in code and 'ASSERT_MY_COIN_ID' not in code:
            return [self._make(fname, code, "Missing Coin ID Assertion", "Medium", "Access Control",
                                 "my_coin_id without ASSERT_MY_COIN_ID", code[:100])]
        return []

    # Agent 13
    def _agent_13(self, fname, code):
        findings = []
        for m in re.finditer(r'CREATE_COIN_ANNOUNCEMENT\s+(\S+)', code):
            msg = m.group(1)
            if 'PROTOCOL_PREFIX' in msg and 'inner_puzzle_hash' not in msg and 'my_coin_id' not in msg:
                findings.append(self._make(fname, code, "Weak Announcement Binding", "Low", "Access Control",
                                             "Announcement without binding to coin/puzzle identity", msg))
        return findings

    # Agent 14
    def _agent_14(self, fname, code):
        findings = []
        for m in re.finditer(r'SEND_MESSAGE\s+(0x\w+)', code):
            mode = m.group(1)
            if mode not in ('0x3f', '0x12', '0x3e'):
                findings.append(self._make(fname, code, "Message Mode Analysis", "Medium", "Access Control",
                                             f"SEND_MESSAGE with non-standard mode {mode}", mode))
        return findings

    # Agent 15
    def _agent_15(self, fname, code):
        findings = []
        for f in [x for x in self._funcs if x.file == fname]:
            if 'if' in f.code:
                for m2 in re.finditer(r'if\s+\((\w+)', f.code):
                    v = m2.group(1)
                    if v and v[0].islower():
                        has_type = _check_code(rf'\(is-uint64\s+{re.escape(v)}', f.code) or \
                                   _check_code(rf'\(is-size-b32\s+{re.escape(v)}', f.code) or \
                                   _check_code(rf'\(not\s+\(l\s+{re.escape(v)}', f.code)
                        if not has_type:
                            findings.append(self._make(fname, code, "Conditional Branch Type Bypass", "High", "Type Safety",
                                                         f"'{v}' in if without type check", f.code[:200], f.name))
        return findings

    # Agent 16
    def _agent_16(self, fname, code):
        findings = []
        for m in re.finditer(r'\(/\s+\(\*\s+(\w+)\s+(\w+)\)\s+(\w+)', code):
            a, b, c = m.group(1), m.group(2), m.group(3)
            if 'PRECISION' in (a, b, c):
                findings.append(self._make(fname, code, "Fee Rounding Direction", "Low", "Economic",
                                             f"Rounding in interest calculation (/ (* {a} {b}) {c})", m.group(0)))
        return findings

    # Agent 17
    def _agent_17(self, fname, code):
        if 'auction' in fname.lower() or 'bid' in fname.lower():
            if 'min_price' in code and not _check_code(r'> min_price 0', code):
                return [self._make(fname, code, "Auction Price Logic", "Medium", "Economic",
                                     "min_price can be 0", code[:200])]
        return []

    # Agent 18
    def _agent_18(self, fname, code):
        if 'cumulative_stability_fee_df' in code or 'cumulative_interest_df' in code:
            if not _check_code(r'MAX_TX_BLOCK_TIME', code) and \
               not _check_code(r'>.*cumulative.*0', code):
                return [self._make(fname, code, "Discount Factor Manipulation", "Medium", "Economic",
                                     "Discount factor without future guard", code[:150])]
        return []

    # Agent 19
    def _agent_19(self, fname, code):
        if ('get-min-collateral-amount' in code or 'liquidation_ratio' in code) and \
           not _check_code(r'> COLLATERAL.*min_collateral', code):
            return [self._make(fname, code, "Collateral Ratio", "High", "Economic",
                                     "Collateral calculation without sufficient assert", code[:150])]
        return []

    # Agent 20
    def _agent_20(self, fname, code):
        findings = []
        for f in self._find_funcs(r'undiscount'):
            if f.file != fname:
                continue
            if '* -1' in f.code or 'MINUS_ONE' in f.code:
                findings.append(self._make(fname, code, "Ceiling Division Analysis", "Info", "Economic",
                                             "Uses ceiling division", f.code[:200], f.name))
            else:
                findings.append(self._make(fname, code, "Ceiling Division Analysis", "Medium", "Economic",
                                             "undiscount without ceiling may cause loss", f.code[:200], f.name))
        return findings

    # Agent 21
    def _agent_21(self, fname, code):
        findings = []
        for m in re.finditer(r'current_timestamp', code):
            max_tx = 'MAX_TX_BLOCK_TIME' in code
            three_buf = '(* 3 MAX_TX_BLOCK_TIME)' in code or '(+ current_timestamp (* 3' in code
            five_buf = '(* 5 MAX_TX_BLOCK_TIME)' in code
            sev = "Info" if max_tx else "Low"
            findings.append(self._make(fname, code, "Timestamp Consistency Across Protocol", sev, "Timing",
                           f"current_timestamp (MAX_TX={max_tx}, +3={three_buf}, +5={five_buf})",
                           code[m.start():m.start()+80]))
        return findings

    # Agent 22
    def _agent_22(self, fname, code):
        has_abs = 'ASSERT_SECONDS_ABSOLUTE' in code
        has_before = 'ASSERT_BEFORE_SECONDS_ABSOLUTE' in code
        if has_abs and not has_before:
            return [self._make(fname, code, "Time Window Bounds", "Medium", "Timing",
                                 "ASSERT_SECONDS_ABSOLUTE without ASSERT_BEFORE_SECONDS_ABSOLUTE", code[:100])]
        if has_before and not has_abs:
            return [self._make(fname, code, "Time Window Bounds", "High", "Timing",
                                 "ASSERT_BEFORE_SECONDS_ABSOLUTE without ASSERT_SECONDS_ABSOLUTE", code[:100])]
        return []

    # Agent 23
    def _agent_23(self, fname, code):
        findings = []
        for kw in ['mergesort', 'list-length', 'announcer-list-length', 'generate-offer-assert']:
            if kw in code:
                for m in re.finditer(rf'{kw}\s+(\w+)', code):
                    p = m.group(1)
                    if p and (p[0].islower() or 'registry' in p or 'coins' in p):
                        if not _check_code(r'MAX|min_treasury_delta|20|50|100', code) and \
                           'launch' not in fname:
                            findings.append(self._make(fname, code, "Cost Exhaustion (Gas DoS)", "Medium", "DoS",
                                                         f"'{kw}' on '{p}' without cap", code[:150]))
        return findings

    # Agent 24
    def _agent_24(self, fname, code):
        if 'SEND_MESSAGE' in code and 'RECEIVE_MESSAGE' in code:
            return [self._make(fname, code, "Cross-Coin Reentrancy", "Low", "External Interaction",
                                 "SEND and RECEIVE MESSAGE together", code[:100])]
        return []

    # Agent 25
    def _agent_25(self, fname, code):
        findings = []
        for m in re.finditer(r'CREATE_COIN_ANNOUNCEMENT', code):
            start = max(0, m.start()-50)
            end = m.end()+50
            if 'PROTOCOL_PREFIX' not in code[start:end]:
                findings.append(self._make(fname, code, "Missing Protocol Prefix", "Medium", "Spoofing",
                                             "CREATE_COIN_ANNOUNCEMENT without PROTOCOL_PREFIX",
                                             code[m.start():m.end()+80]))
        return findings

    # Agent 26
    def _agent_26(self, fname, code):
        if 'bid' in fname.lower():
            has_min = _check_code(r'min_.*bid|min_price|MIN_PRICE', code)
            if not has_min:
                return [self._make(fname, code, "Min Bid Enforcement", "High", "Economic",
                                     "Auction without a minimum bid", code[:100])]
        return []

    # Agent 27
    def _agent_27(self, fname, code):
        params = re.findall(r'_coins|_list|_registry', fname)
        if params:
            if not _check_code(r'not-contains|unique|count-treasury-coins', code):
                return [self._make(fname, code, "Missing Uniqueness Check", "Medium", "DoS",
                                     f"List {params[0]} without uniqueness check", code[:100])]
        return []

    # Agent 28
    def _agent_28(self, fname, code):
        if 'ASSERT_HEIGHT_RELATIVE 0' in code or 'ASSERT_HEIGHT_RELATIVE\n0' in code:
            return [self._make(fname, code, "Ephemeral Spend Locking", "Low", "Access Control",
                                 "ASSERT_HEIGHT_RELATIVE 0 prevents transient spending", code[:100])]
        return []

    # Agent 29
    def _agent_29(self, fname, code):
        findings = []
        for m in re.finditer(r'CREATE_COIN\s+\S+\s+(\w+)', code):
            amt = m.group(1)
            if amt and amt.islower() and amt not in ('x', 'one'):
                has_uint = _check_code(rf'is-uint64\s+{re.escape(amt)}', code)
                has_pos = _check_code(rf'>\s+{re.escape(amt)}\s+MINUS_ONE', code) or \
                          _check_code(rf'>\s+{re.escape(amt)}\s+0', code)
                if not has_uint and not has_pos:
                    findings.append(self._make(fname, code, "Unvalidated Coin Amount", "High", "State Machine",
                                                 f"CREATE_COIN amount '{amt}' without validation", code[:150]))
        return findings

    # Agent 30
    def _agent_30(self, fname, code):
        if 'price_info' in code and 'launch' not in fname:
            if not _check_code(r'cut-price-infos|cutoff|cut_off', code) and \
               not _check_code(r'ASSERT_SECONDS_ABSOLUTE|ASSERT_BEFORE_SECONDS_ABSOLUTE', code):
                return [self._make(fname, code, "Oracle Price Staleness", "Medium", "Economic",
                                     "price_info without staleness check", code[:100])]
        return []

    # Agent 31
    def _agent_31(self, fname, code):
        findings = []
        for m in re.finditer(r'sha256tree\s*\(c\s+(\w+)\s+(\w+)\)', code):
            a, b = m.group(1), m.group(2)
            if a.islower() and b.islower():
                findings.append(self._make(fname, code, "Hash Collision Surface", "Low", "Cryptographic",
                                             f"sha256tree(c {a} {b}) — both from solution", code[:100]))
        return findings

    # Agent 32
    def _agent_32(self, fname, code):
        findings = []
        for m in re.finditer(r'coinid\s+(\w+)\s+(\w+)\s+(\w+)', code):
            parent, puzzle, amount = m.group(1), m.group(2), m.group(3)
            if parent.islower() or amount.islower():
                findings.append(self._make(fname, code, "Coin ID Forgery Risk", "Medium", "Cryptographic",
                                             f"coinid({parent},{puzzle},{amount}) — forgeable", m.group(0)))
        return findings

    # Agent 33
    def _agent_33(self, fname, code):
        if '= 0' in code and 'nil' in code.lower():
            return [self._make(fname, code, "Nil vs Zero Confusion", "Medium", "Type Safety",
                                 "Confuses nil and 0", code[:100])]
        return []

    # Agent 34
    def _agent_34(self, fname, code):
        if 'ASSERT_MY_PARENT_ID' in code and 'ASSERT_MY_PUZZLEHASH' in code:
            return []
        if 'CREATE_COIN' in code or 'singleton' in fname:
            return [self._make(fname, code, "Infinite State Loop", "Info", "State Machine",
                                 "Singleton without complete self-verification", code[:100])]
        return []

    # Agent 35
    def _agent_35(self, fname, code):
        if 'start_auction' in fname and _check_code(r'auction_state|frozen|freeze', code):
            return [self._make(fname, code, "Auction Fee Freeze", "Medium", "State Machine",
                                 "Fees freeze when auction starts", code[:200])]
        return []

    # Agent 36
    def _agent_36(self, fname, code):
        findings = []
        for f in self._find_funcs(r'pow-discount'):
            if f.file != fname:
                continue
            has_cap = _check_code(r'MAX|>.*exp|>.*base', f.code)
            sev = "Low" if not has_cap else "Info"
            desc = "without max cap" if not has_cap else "has cap"
            findings.append(self._make(fname, code, "Exponential Overflow", sev, "Economic",
                                          f"Exponent {desc}", f.code[:200], f.name))
        return findings

    # Agent 37
    def _agent_37(self, fname, code):
        findings = []
        if 'mutation' in fname.lower() or 'governance' in fname.lower():
            for m in re.finditer(r'>\s+(\w+)\s+0', code):
                var = m.group(1)
                has_max = _check_code(rf'>\s+\d+\s+{re.escape(var)}|>\s+MAX.*{re.escape(var)}|{re.escape(var)}.*MAX', code)
                if not has_max:
                    findings.append(self._make(fname, code, "Unbounded Governance Parameter", "Low", "Economic",
                                                 f"'{var}' > 0 without upper bound", code[:150]))
        return findings

    # Agent 38
    def _agent_38(self, fname, code):
        for f in self._find_funcs(r'contains|not-contains|unique'):
            if f.file == fname:
                return [self._make(fname, code, "Duplicate Detection", "Info", "DoS",
                                     f"Function {f.name} — O(n) without hash", f.code[:150], f.name)]
        return []

    # Agent 39
    def _agent_39(self, fname, code):
        findings = []
        for m in re.finditer(r'ASSERT_BEFORE_SECONDS_ABSOLUTE.*?(\d+)', code):
            delay = int(m.group(1))
            if delay < 600:
                findings.append(self._make(fname, code, "Reorg Attack Surface", "Low", "Timing",
                                             f"Small reorg window ({delay}s)", code[:100]))
        return findings

    # Agent 40
    def _agent_40(self, fname, code):
        if _check_code(r'\*\s*5\s*MAX_TX_BLOCK_TIME', code):
            return [self._make(fname, code, "Mempool Manipulation", "Low", "Timing",
                                 "5-block window — timing can be manipulated", code[:80])]
        return []

    # Agent 42
    def _agent_42(self, fname, code):
        if 'fail-on-protocol-condition' not in code:
            if 'CREATE_COIN_ANNOUNCEMENT' in code or 'SEND_MESSAGE' in code:
                sev = "Low" if 'solution' in fname or 'inner_' in fname else "Info"
                return [self._make(fname, code, "Protocol Prefix Spoofing", sev, "Spoofing",
                                     "May not prevent PROTOCOL_PREFIX spoofing", code[:80])]
        return []

    # Agent 43
    def _agent_43(self, fname, code):
        vault_files = {x.file for x in self._funcs if 'vault' in x.file.lower()}
        if fname not in vault_files or 'collateral_vault' not in fname:
            return []
        operations = set()
        for vf in vault_files:
            op = re.search(r'vault_(\w+)', vf)
            if op:
                operations.add(op.group(1))
        defined_ops = set(re.findall(r"'(borrow|deposit|withdraw|repay|transfer|start_auction|bid|recover_bad_debt|transfer_sf_to_treasury)'", code))
        missing = defined_ops - operations
        if missing:
            return [self._make(fname, code, "Vault State Machine Completeness", "Medium", "State Machine",
                                     f"Missing operations: {missing}", code[:200])]
        return []

    # Agent 44
    def _agent_44(self, fname, code):
        if 'savings_vault' in fname and 'cumulative_interest_df' in code:
            has_zero = _check_code(r'> cumulative_interest_df 0', code)
            sev = "Critical" if not has_zero else "Info"
            return [self._make(fname, code, "Savings Vault Interest Math", sev, "Economic",
                                     f"cumulative_interest_df as divisor {'without' if not has_zero else 'with'} zero-check",
                                     code[500:700])]
        return []

    # Agent 45
    def _agent_45(self, fname, code):
        if 'treasury' in fname and 'rebalance' in code.lower():
            has_concurrent = _check_code(r'ASSERT_CONCURRENT_SPEND', code)
            sev = "Medium" if not has_concurrent else "Info"
            return [self._make(fname, code, "Treasury Ring Rebalance", sev, "Economic",
                                     f"Rebalance {'without' if not has_concurrent else 'with'} ASSERT_CONCURRENT_SPEND",
                                     code[200:400])]
        return []

    # Agent 46
    def _agent_46(self, fname, code):
        if 'crt_tail' in fname:
            has_approval = _check_code(r'approval_mod_hashes|approval_mod', code)
            sev = "Medium" if has_approval else "Critical"
            return [self._make(fname, code, "CRT Tail Approval Logic", sev, "Access Control",
                                     f"CRT tail {'with' if has_approval else 'without'} verification", code[100:300])]
        return []

    # Agent 47
    def _agent_47(self, fname, code):
        if 'byc_tail' in fname:
            has_mod = _check_code(r'approval_mod_hashes|vault_mod_hash', code)
            sev = "High" if has_mod else "Critical"
            return [self._make(fname, code, "BYC Tail Mint Authorization", sev, "Access Control",
                                     f"BYC tail {'uses mod_hash' if has_mod else 'without'} verification", code[100:300])]
        return []

    # Agent 48
    def _agent_48(self, fname, code):
        if 'payout' in fname and 'curried_args_hash' in code:
            return [self._make(fname, code, "Payout Hijacking", "High", "Access Control",
                                 "curried_args_hash from user — can be spoofed", code[100:300])]
        return []

    # Agent 49
    def _agent_49(self, fname, code):
        if 'collateral_vault' in fname:
            has_unique = _check_code(r'unique|not-contains|ASSERT_CONCURRENT_SPEND', code)
            sev = "Info" if has_unique else "Low"
            desc = "Has prevention of multiple vaults" if has_unique else "No prevention of multiple vaults"
            return [self._make(fname, code, "Vault Launch Uniqueness", sev, "State Machine", desc, code[100:300])]
        return []

    def _agent_50(self, fname, code):
        """Attack chain builder — placed as a flag, logic in generate_report"""
        return []

    # ════════════════════════════════════════════
    # Dynamic Agent Generation (1000+ agents style)
    # ════════════════════════════════════════════════

    def _dynamic_angles(self) -> List[Finding]:
        """Generate agents dynamically via 20 analysis angles"""
        results = []
        funcs_by_file = defaultdict(list)
        for f in self._funcs:
            funcs_by_file[f.file].append(f)

        for fname, code in self._files.items():
            funcs = funcs_by_file.get(fname, [])

            # Angle 1: Params without uint64/size-b32
            for f in funcs:
                for p in f.params:
                    if p[0].islower() and p not in ('x', 'one', 'false', 'true', '_noargs'):
                        if not _check_code(rf'is-uint64\s+{re.escape(p)}', f.code) and \
                           not _check_code(rf'is-size-b32\s+{re.escape(p)}', f.code):
                            sev = "Medium" if not f.is_inline else "Low"
                            results.append(Finding(f"Param-UInt:{f.name}", sev, "Type Safety",
                                                    fname, f.name,
                                                    f"'{p}' without uint64/size-b32", f.code[:150]))

            # Angle 2: Hash params without is-size-b32
            hash_kw = ['puzzle_hash', 'coin_id', 'mod_hash', 'tail_hash', 'launcher_id', 'parent_id']
            for f in funcs:
                for kw in hash_kw:
                    for m in re.finditer(rf'(\w*{kw}\w*)', f.code, re.IGNORECASE):
                        p = m.group(1)
                        if p and p[0].islower() and len(p) > 3:
                            if not _check_code(rf'is-size-b32\s+{re.escape(p)}', f.code) and \
                               not _check_code(rf'is-size-b32-or-nil\s+{re.escape(p)}', f.code):
                                results.append(Finding(f"Param-Hash:{f.name}", "High", "Type Safety",
                                                        fname, f.name,
                                                        f"'{p}' hash without is-size-b32", f.code[:150]))

            # Angle 3: Division by zero
            for f in funcs:
                for m in re.finditer(r'/\s+(\w+)', f.code):
                    d = m.group(1).strip(')')
                    if d and d[0].isalpha() and not _check_code(rf'>\s+{re.escape(d)}\s+0', f.code) and \
                       not _check_code(rf'>\s+{re.escape(d)}\s+MINUS_ONE', f.code):
                        results.append(Finding(f"DivZero:{f.name}", "High", "DoS",
                                                fname, f.name,
                                                f"Division by '{d}' without zero-check", f.code[:100]))

            # Angle 4: curry from solution without validation
            for f in funcs:
                for m in re.finditer(r'sha256\s+ONE\s+(\w+)', f.code):
                    v = m.group(1)
                    if v and v[0].islower():
                        has_check = _check_code(rf'\(assert.*\b{re.escape(v)}\b', f.code) or \
                                     _check_code(rf'is-uint64\s+{re.escape(v)}', f.code) or \
                                     _check_code(rf'>\s+{re.escape(v)}', f.code)
                        if not has_check:
                            results.append(Finding(f"Curry-Solution:{f.name}", "Critical", "State Machine",
                                                    fname, f.name,
                                                    f"'{v}' into curry without validation", f.code[:150]))

            # Angle 5: coinid forgery
            for f in funcs:
                for m in re.finditer(r'coinid\s+(\w+)\s+(\w+)\s+(\w+)', f.code):
                    parent, puzzle, amount = m.group(1), m.group(2), m.group(3)
                    if parent.islower() or amount.islower():
                        results.append(Finding(f"CoinID-Forgery:{f.name}", "Medium", "Cryptographic",
                                                fname, f.name,
                                                f"coinid({parent},{puzzle},{amount}) — forgeable",
                                                m.group(0)))

            # Angle 6: unusual SEND_MESSAGE modes
            for m in re.finditer(r'SEND_MESSAGE\s+(0x\w+)', code):
                mode = m.group(1)
                if mode not in ('0x3f', '0x12', '0x3e'):
                    results.append(Finding(f"MsgMode", "Medium", "Access Control",
                                            fname, "",
                                            f"SEND_MESSAGE with non-standard mode {mode}", mode))

            # Angle 7: announcements without PROTOCOL_PREFIX
            for m in re.finditer(r'CREATE_COIN_ANNOUNCEMENT', code):
                start = max(0, m.start()-50)
                end = m.end()+50
                if 'PROTOCOL_PREFIX' not in code[start:end]:
                    results.append(Finding(f"Announce-Prefix", "Medium", "Spoofing",
                                            fname, "",
                                            "Announcement without PROTOCOL_PREFIX", code[m.start():m.end()+50]))

            # Angle 8: ASSERT_HEIGHT_RELATIVE 0
            if 'ASSERT_HEIGHT_RELATIVE 0' in code or 'ASSERT_HEIGHT_RELATIVE\n0' in code:
                results.append(Finding("EphemeralLock", "Low", "Access Control",
                                        fname, "",
                                        "ASSERT_HEIGHT_RELATIVE 0 prevents transient spending", code[:80]))

            # Time window bounds
            has_abs = 'ASSERT_SECONDS_ABSOLUTE' in code
            has_before = 'ASSERT_BEFORE_SECONDS_ABSOLUTE' in code
            if has_abs and not has_before:
                results.append(Finding("TimeWindow", "Medium", "Timing",
                                        fname, "",
                                        "ASSERT_SECONDS_ABSOLUTE without ASSERT_BEFORE_SECONDS_ABSOLUTE", code[:80]))
            if has_before and not has_abs:
                results.append(Finding("TimeWindow", "High", "Timing",
                                        fname, "",
                                        "ASSERT_BEFORE_SECONDS_ABSOLUTE without ASSERT_SECONDS_ABSOLUTE", code[:80]))

            # CREATE_COIN amount without validation
            for m in re.finditer(r'CREATE_COIN\s+\S+\s+(\w+)', code):
                amt = m.group(1)
                if amt and amt.islower() and amt not in ('x', 'one'):
                    if not _check_code(rf'is-uint64\s+{re.escape(amt)}', code) and \
                       not _check_code(rf'>\s+{re.escape(amt)}\s+MINUS_ONE', code) and \
                       not _check_code(rf'>\s+{re.escape(amt)}\s+0', code):
                        results.append(Finding(f"CoinAmount", "High", "State Machine",
                                                fname, "",
                                                f"CREATE_COIN amount '{amt}' without validation", code[:100]))

            # Unbounded recursion
            for f in funcs:
                if f.code.count(f.name) > 2:
                    if not _check_code(r'MAX|list-length', f.code):
                        results.append(Finding(f"Recursion-Unbounded:{f.name}", "Medium", "DoS",
                                                fname, f.name,
                                                f"Recursive function without cap", f.code[:150]))

        # Cross-file state variable analysis
        state_kw = ['cumulative_interest_df', 'cumulative_stability_fee_df', 'price_info',
                    'min_treasury_delta', 'stability_fee_df', 'liquidation_ratio', 'minimum_debt']
        file_state = {}
        for fname in self._files:
            code = self._files[fname]
            file_state[fname] = {kw: kw in code for kw in state_kw}

        shared_files = [fname for fname, states in file_state.items() if any(states.values())]
        if len(shared_files) >= 2:
            for i in range(len(shared_files)):
                for j in range(i+1, len(shared_files)):
                    f1, f2 = shared_files[i], shared_files[j]
                    shared = [kw for kw in state_kw if file_state[f1][kw] and file_state[f2][kw]]
                    if len(shared) >= 2:
                        results.append(Finding(f"SharedState:{len(shared)}var", "Medium", "State Machine",
                                                f1, "",
                                                f"Shared state ({', '.join(shared[:4])}) between {f1} and {f2}", ""))
        return results

    def _combinatorial_agents(self) -> List[Finding]:
        """Generate combinatorial agents (10,000+ agents style)"""
        results = []
        funcs_by_file = defaultdict(list)
        for f in self._funcs:
            funcs_by_file[f.file].append(f)

        max_pairs = 500
        total_pairs_checked = 0

        for fname, code in self._files.items():
            funcs = funcs_by_file.get(fname, [])

            for f in funcs:
                for op in ['+', '-', '*', '/', '>', '<', '=']:
                    for m in re.finditer(rf'\{op}\s+(\w+)', f.code):
                        var = m.group(1)
                        if var and var[0].islower() and var not in ('x', 'one'):
                            has_type = _check_code(rf'is-uint64\s+{re.escape(var)}', f.code) or \
                                       _check_code(rf'is-size-b32\s+{re.escape(var)}', f.code) or \
                                       _check_code(rf'not\s+\(l\s+{re.escape(var)}', f.code)
                            sev = "Medium" if not has_type else "Info"
                            results.append(Finding(f"Arith-{op}:{f.name}", sev, "Type Safety",
                                                          fname, f.name,
                                                          f"'{var}' in {op} operation without type check", f.code[:100]))

            if len(funcs) > 50:
                funcs = funcs[:50]
            for f1 in funcs:
                for f2 in funcs:
                    if total_pairs_checked >= max_pairs:
                        break
                    if f1.name >= f2.name:
                        continue
                    total_pairs_checked += 1
                    shared_vars = [p for p in f1.params if p in f2.params and p[0].islower()]
                    for var in shared_vars:
                        has_type1 = _check_code(f'is-uint64 {re.escape(var)}', f1.code)
                        has_type2 = _check_code(f'is-uint64 {re.escape(var)}', f2.code)
                        if has_type1 != has_type2:
                            results.append(Finding(f"VarTypeMismatch:{var}", "Medium", "Type Safety",
                                                    fname, f1.name,
                                                    f"'{var}' in '{f1.name}' {'with' if has_type1 else 'without'} uint64 but '{f2.name}' {'with' if has_type2 else 'without'}",
                                                    f1.code[:100]))
                if total_pairs_checked >= max_pairs:
                    break

            for f1 in funcs:
                for f2 in funcs:
                    if total_pairs_checked >= max_pairs:
                        break
                    if f1.name >= f2.name:
                        continue
                    total_pairs_checked += 1
                    if f1.params and f2.params and set(f1.params) == set(f2.params):
                        if f1.code != f2.code:
                            results.append(Finding(f"CopyPaste:{f1.name}~{f2.name}", "Low", "Best Practice",
                                                    fname, f1.name,
                                                    f"'{f1.name}' and '{f2.name}' have the same parameters but different code",
                                                    ""))
                if total_pairs_checked >= max_pairs:
                    break
        return results

    def run_complete_audit(self, path: str = "") -> str:
        """Run all agents: the 50 static + dynamic + combinatorial"""
        self._findings = []
        self._agent_results = defaultdict(int)
        self._agent_errors = []

        if path:
            self.load_directory(path)
        elif not self._files:
            return "No files to analyze"

        results = {}
        for fname, code in self._files.items():
            findings = self.analyze_file(fname, code)
            results[fname] = findings

        # Add dynamic agents
        dyn = self._dynamic_angles()
        self._findings.extend(dyn)
        for f in dyn:
            self._agent_results["Dynamic-Angles"] += 1

        comb = self._combinatorial_agents()
        self._findings.extend(comb)
        for f in comb:
            self._agent_results["Combinatorial"] += 1

        return self.generate_report(results)

    def _build_attack_chains(self) -> list:
        """Build dynamic attack chains from all analysis findings"""
        findings = self._findings
        crit = [f for f in findings if f.severity == "Critical" and f.agent_name != "Attack Chain Synthesis"]
        high = [f for f in findings if f.severity == "High" and f.agent_name != "Attack Chain Synthesis"]
        chains = []

        # --- Algorithm: find findings that share a file/function ---
        by_file = defaultdict(list)
        for f in findings:
            by_file[f.file].append(f)

        # Chain builder: look for files with three or more findings
        for fname, fnds in by_file.items():
            sev_counts = defaultdict(int)
            cats = set()
            funcs = set()
            for f in fnds:
                sev_counts[f.severity] += 1
                cats.add(f.category)
                if f.function_name:
                    funcs.add(f.function_name)
            if sev_counts.get("Critical", 0) >= 2:
                chains.append(f"Chain-{len(chains)+1}: {fname} ({sev_counts['Critical']} Critical + {sev_counts.get('High',0)} High) — {' → '.join(sorted(cats)[:4])}")
            elif sev_counts.get("Critical", 0) >= 1 and sev_counts.get("High", 0) >= 2:
                chains.append(f"Chain-{len(chains)+1}: {fname} (1 Critical + {sev_counts['High']} High) — Multi-stage attack via {', '.join(sorted(funcs)[:4])}")

        # Functions with Critical findings that interact across files
        crit_files = {f.file for f in crit}
        if len(crit_files) >= 2:
            files_str = ", ".join(sorted(crit_files)[:5])
            chains.append(f"Chain-{len(chains)+1}: Distribution ({len(crit_files)} files) — Cross-file attack: {files_str}")

        # Reentrancy + external interaction
        has_reent = any("Reentrancy" in f.agent_name or "cross-coin" in f.agent_name.lower() for f in findings)
        has_external = any("SEND_MESSAGE" in f.agent_name or "announce" in f.agent_name.lower() for f in findings)
        if has_reent and has_external:
            chains.append(f"Chain-{len(chains)+1}: Reentrancy + External Interaction — Potential drain via cross-messages")

        # Economic + timing
        eco_crit = [f for f in crit if f.category == "Economic"]
        timing_find = [f for f in findings if f.category == "Timing" and f.severity != "Info"]
        if eco_crit and timing_find:
            chains.append(f"Chain-{len(chains)+1}: Economic ({len(eco_crit)} Critical) + Timing ({len(timing_find)}) — Timing-based economic attack")

        # Access control bypass
        high_access = [f for f in high if f.category == "Access Control"]
        if len(high_access) >= 2:
            names = [f.agent_name for f in high_access[:4]]
            chains.append(f"Chain-{len(chains)+1}: Permission vulnerability chain ({len(high_access)}) — {' + '.join(names)}")

        return chains

    def generate_report(self, results=None):
        base_report = super().generate_report(results)
        chains = self._build_attack_chains()

        chain_report = f"\n{'─' * 50}\nATTACK CHAIN SYNTHESIS:\n{'─' * 50}\n"
        if chains:
            chain_report += "\n".join(f"  [High] {c}" for c in chains)
        else:
            chain_report += "  No attack chains found"

        self._findings.append(Finding("Attack Chain Synthesis", "High" if chains else "Info",
                                       "Creative", "multi", "attack_chains",
                                       "Possible attack chains: " + "; ".join(chains) if chains else "No chains",
                                       "\n".join(chains[:4])))
        return base_report + chain_report