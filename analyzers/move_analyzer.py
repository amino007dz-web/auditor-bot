import re
from typing import List, Dict
from .base import LanguageAnalyzer, Agent, Finding, has_pattern
from .move_ast import parse_move_code, MoveModule, MoveStruct, MoveFunction


class MoveAnalyzer(LanguageAnalyzer):
    name = "Move/Sui Static Analysis"
    language = "move"
    extensions = [".move"]

    def __init__(self):
        super().__init__()
        self._move_ast: List[MoveModule] = []
        self._move_structs: Dict[str, MoveStruct] = {}
        self._move_funcs: Dict[str, MoveFunction] = {}
        self._register_agents()

    def analyze_file(self, filename: str, code: str) -> list:
        self._move_ast = parse_move_code(code)
        self._move_structs = {}
        self._move_funcs = {}
        for mod in self._move_ast:
            for st in mod.structs:
                self._move_structs[st.name] = st
            for fn in mod.functions:
                self._move_funcs[fn.name] = fn
        return super().analyze_file(filename, code)

    def _register_agents(self):
        self.add_agent(Agent("Object ID Leakage", "Critical", "Type Safety", self._check_id_leak))
        self.add_agent(Agent("Missing Store Ability", "Critical", "Type Safety", self._check_missing_store))
        self.add_agent(Agent("Unsafe signer Extraction", "Critical", "Access Control", self._check_signer_extract))
        self.add_agent(Agent("Unchecked Unwrap", "Critical", "Reentrancy", self._check_unchecked_unwrap))
        self.add_agent(Agent("Coin Theft via Phantom Object", "Critical", "Access Control", self._check_phantom_object))
        self.add_agent(Agent("Infinite Mint via Witness", "Critical", "Economic", self._check_witness_mint))
        self.add_agent(Agent("Missing One-Time Witness", "Critical", "Access Control", self._check_otw))

        self.add_agent(Agent("Unsafe vector::pop_back", "High", "DoS", self._check_pop_back))
        self.add_agent(Agent("Unsafe destroy/remove", "High", "DoS", self._check_unsafe_destroy))
        self.add_agent(Agent("Missing freeze_object", "High", "Access Control", self._check_missing_freeze))
        self.add_agent(Agent("Shared Object Mutation", "High", "Access Control", self._check_shared_mutation))
        self.add_agent(Agent("Missing withdraw Capability", "High", "Access Control", self._check_withdraw_cap))
        self.add_agent(Agent("Unsafe Public Entry", "High", "Access Control", self._check_public_entry))
        self.add_agent(Agent("Missing key Ability", "High", "Type Safety", self._check_missing_key))
        self.add_agent(Agent("Flash Loan Without Repay", "High", "Economic", self._check_flash_loan))
        self.add_agent(Agent("ID Duplication", "High", "Cryptographic", self._check_id_dup))
        self.add_agent(Agent("Unsafe init (non OTW)", "High", "Access Control", self._check_unsafe_init))
        self.add_agent(Agent("Unexpired Object Access", "High", "Timing", self._check_expired_object))

        self.add_agent(Agent("Missing abort code", "Medium", "Security", self._check_missing_abort))
        self.add_agent(Agent("assert! with Always True", "Medium", "Security", self._check_always_true_assert))
        self.add_agent(Agent("Unbounded vec Iteration", "Medium", "DoS", self._check_unbounded_vec))
        self.add_agent(Agent("Unsafe transfer to self", "Medium", "Access Control", self._check_transfer_self))
        self.add_agent(Agent("Missing Event Emission", "Medium", "Best Practice", self._check_move_events))
        self.add_agent(Agent("Public freeze Function", "Medium", "Access Control", self._check_public_freeze))
        self.add_agent(Agent("Unchecked Coin::zero", "Medium", "Economic", self._check_coin_zero))
        self.add_agent(Agent("Missing drop Ability", "Medium", "Type Safety", self._check_missing_drop))
        self.add_agent(Agent("Copyable Object", "Medium", "Type Safety", self._check_copyable_object))
        self.add_agent(Agent("Unsafe vec::remove", "Medium", "DoS", self._check_vec_remove))

        self.add_agent(Agent("Hardcoded Address", "Low", "Readability", self._check_hardcoded_addr))
        self.add_agent(Agent("assert_eq / assert_ne", "Low", "Style", self._check_assert_eq))
        self.add_agent(Agent("Large vector Literal", "Low", "Readability", self._check_large_vec))
        self.add_agent(Agent("Unused Function", "Low", "Style", self._check_unused_fn))
        self.add_agent(Agent("Public Function Named _", "Low", "Style", self._check_underscore_fn))

        self.add_agent(Agent("sui::transfer Usage", "Info", "Best Practice", self._check_transfer_good))
        self.add_agent(Agent("Event Convention", "Info", "Best Practice", self._check_event_convention))
        self.add_agent(Agent("Module Version", "Info", "Best Practice", self._check_module_version))
        self.add_agent(Agent("Spec Block", "Info", "Best Practice", self._check_spec_block))
        self.add_agent(Agent("Friend Declaration", "Info", "Best Practice", self._check_friend))

    def _make(self, fname, code, agent, severity, category, desc, snippet="", func="", fix=""):
        return Finding(agent, severity, category, fname, func, desc, snippet[:200], 0, fix)

    # ─── AST-based helpers ───

    def _ast_struct_names(self) -> List[str]:
        return list(self._move_structs.keys())

    def _ast_func_names(self) -> List[str]:
        return list(self._move_funcs.keys())

    def _ast_struct_has_ability(self, sname: str, ability: str) -> bool:
        st = self._move_structs.get(sname)
        return st is not None and ability in st.abilities

    def _ast_module_name(self) -> str:
        if self._move_ast:
            return self._move_ast[0].name
        return ""

    def _ast_find_functions(self, name: str) -> List[MoveFunction]:
        return [fn for fn in self._move_funcs.values() if fn.name == name]

    def _ast_has_pattern_in_func(self, fn: MoveFunction, pattern: str) -> bool:
        return bool(re.search(pattern, fn.body))

    # ─── Critical ───

    def _check_id_leak(self, fname, code):
        findings = []
        for m in re.finditer(r'(?:id|ID|object_id)\.to_bytes|(?:id|ID)\s*=\s*(?:object|tx_context)\s*.*\bid\b', code):
            findings.append(self._make(fname, code, "Object ID Leakage", "Critical", "Type Safety",
                          "ID object is converted to bytes or exposed — can be spoofed", m.group()[:100],
                          fix="Never expose UID to the outside"))
        for m in re.finditer(r'object::id\s*\(', code):
            findings.append(self._make(fname, code, "Object ID Leakage", "Critical", "Type Safety",
                          f"object::id() exposes ID — use only for verification", m.group()[:80]))
        return findings

    def _check_missing_store(self, fname, code):
        findings = []
        for sname in self._ast_struct_names():
            has_store = self._ast_struct_has_ability(sname, "store")
            has_key = self._ast_struct_has_ability(sname, "key")
            if has_key and not has_store:
                findings.append(self._make(fname, code, "Missing store Ability", "Critical", "Type Safety",
                               f"struct {sname} with key but no store — cannot be transferred out of contract",
                               fix="Add has store to the struct"))
        return findings

    def _check_signer_extract(self, fname, code):
        findings = []
        for m in re.finditer(r'(?:borrow|mut)_.*signer', code):
            ctx = code[max(0, m.start()-50):m.end()+50]
            findings.append(self._make(fname, code, "Unsafe signer Extraction", "Critical", "Access Control",
                          f"Extracting signer from reference: {m.group()[:60]}", ctx[:120],
                          fix="Never store signer!"))
        return findings

    def _check_unchecked_unwrap(self, fname, code):
        findings = []
        for m in re.finditer(r'option::unwrap\s*\(|Option::unwrap\s*\(|\.unwrap\(\)', code):
            ctx = code[max(0, m.start()-30):m.end()+30]
            findings.append(self._make(fname, code, "Unchecked Unwrap", "Critical", "Reentrancy",
                          f"unwrap without check: {m.group()}", ctx[:100],
                          fix="Use option::borrow + assert! or match"))
        return findings

    def _check_phantom_object(self, fname, code):
        for mod in self._move_ast:
            for st in mod.structs:
                if "phantom" in st.abilities and "drop" not in st.abilities:
                    return [self._make(fname, code, "Coin Theft via Phantom Object", "Critical", "Access Control",
                                       "Phantom type parameter without drop — may be locked", "", fix="Add has drop")]
        if has_pattern(code, r'phantom') and has_pattern(code, r'struct\s+\w+') and \
           not has_pattern(code, r'has\s+(\w+\s+)*drop'):
            return [self._make(fname, code, "Coin Theft via Phantom Object", "Critical", "Access Control",
                                "Phantom type parameter without drop — may be locked", "", fix="Add has drop")]
        return []

    def _check_witness_mint(self, fname, code):
        findings = []
        if has_pattern(code, r'(witness|Witness|OTW|otw)'):
            for m in re.finditer(r'(mint|create|issue)\s*\(.*witness', code, re.IGNORECASE):
                check_drop = has_pattern(code, r'drop\b')
                check_destroy = has_pattern(code, r'destroy\b')
                if not check_drop and not check_destroy:
                    findings.append(self._make(fname, code, "Infinite Mint via Witness", "Critical", "Economic",
                                  f"Function {m.group(1)} receives witness without drop/destroy", m.group()[:100]))
        return findings

    def _check_otw(self, fname, code):
        mod_name = self._ast_module_name()
        if not mod_name:
            mod_match = re.search(r'module\s+(\w+)::', code)
            if mod_match:
                mod_name = mod_match.group(1)
            else:
                return []
        has_witness = mod_name in self._move_structs
        if has_witness:
            has_drop = self._ast_struct_has_ability(mod_name, "drop")
            if not has_drop:
                return [self._make(fname, code, "Missing One-Time Witness", "Critical", "Access Control",
                              f"struct {mod_name} must be OTW with has drop", "", fix="Add has drop to struct")]
        return []

    # ─── High ───

    def _check_pop_back(self, fname, code):
        findings = []
        for m in re.finditer(r'vector::pop_back|vec::pop_back', code):
            ctx = code[max(0, m.start()-50):m.end()+50]
            if not has_pattern(ctx, r'is_empty|length\s*>\s*0|assert!\('):
                findings.append(self._make(fname, code, "Unsafe vector::pop_back", "High", "DoS",
                              f"pop_back without is_empty — may panic", ctx[:100]))
        return findings

    def _check_unsafe_destroy(self, fname, code):
        findings = []
        for m in re.finditer(r'(destroy|remove|delete)\s+(\w+)', code):
            var = m.group(2)
            if var[0].islower() and not has_pattern(code, rf'assert.*{re.escape(var)}'):
                findings.append(self._make(fname, code, "Unsafe destroy/remove", "High", "DoS",
                              f"Destroy '{var}' without check", m.group()[:80]))
        return findings

    def _check_missing_freeze(self, fname, code):
        if has_pattern(code, r'share_object') and not has_pattern(code, r'freeze_object'):
            return [self._make(fname, code, "Missing freeze_object", "High", "Access Control",
                                "share_object without freeze_object — anyone can modify", "",
                                fix="Add freeze after creation")]
        return []

    def _check_shared_mutation(self, fname, code):
        if has_pattern(code, r'&mut\s+\w+') and has_pattern(code, r'TREASURY|Treasury|treasury|VAULT|Vault|vault'):
            return [self._make(fname, code, "Shared Object Mutation", "High", "Access Control",
                                "Vault/Treasury receives &mut — may be modified without permission", "")]
        return []

    def _check_withdraw_cap(self, fname, code):
        if has_pattern(code, r'withdraw') and not has_pattern(code, r'Cap|cap|caps|Capability|capability'):
            return [self._make(fname, code, "Missing withdraw Capability", "High", "Access Control",
                                "withdraw without Capability — balance can be drained", "",
                                fix="Add TreasuryCap or similar standard")]
        return []

    def _check_public_entry(self, fname, code):
        findings = []
        for fn_name, fn in self._move_funcs.items():
            if fn.visibility and "entry" in fn.visibility:
                body = fn.body
                if has_pattern(body, r'Coin<') and not has_pattern(body, r'Cap|cap|caps'):
                    findings.append(self._make(fname, code, "Unsafe Public Entry", "High", "Access Control",
                                  f"public entry '{fn_name}' handles Coin without Cap", fn_name[:80]))
        return findings

    def _check_missing_key(self, fname, code):
        findings = []
        for sname, st in self._move_structs.items():
            has_uid = any(f.type_name == "UID" or "uid" in f.type_name for f in st.fields)
            has_key = "key" in st.abilities
            if has_uid and not has_key:
                findings.append(self._make(fname, code, "Missing key Ability", "High", "Type Safety",
                              f"struct {sname} contains UID without has key", ""))
        return findings

    def _check_flash_loan(self, fname, code):
        if has_pattern(code, r'flash_loan|flashloan|flash.loan'):
            return [self._make(fname, code, "Flash Loan Without Repay", "High", "Economic",
                                "Flash loan function — verify mandatory repay", "")]
        return []

    def _check_id_dup(self, fname, code):
        if has_pattern(code, r'uid_as_inner|inner\.id|id\s*='):
            return [self._make(fname, code, "ID Duplication", "High", "Cryptographic",
                                "ID used in multiple places — risk of ID re-use", "",
                                fix="Uid must be created only once")]
        return []

    def _check_unsafe_init(self, fname, code):
        init_funcs = [fn for fn in self._move_funcs.values() if fn.name == "init"]
        if init_funcs:
            has_otw_drop = any(
                self._ast_struct_has_ability(sname, "drop")
                for sname in self._ast_struct_names()
            )
            has_cap = has_pattern(code, r'TreasuryCap|Publisher')
            if not has_otw_drop and not has_cap:
                return [self._make(fname, code, "Unsafe init (non OTW)", "High", "Access Control",
                                    "init function without OTW or TreasuryCap — may not be secure", "")]
        return []

    def _check_expired_object(self, fname, code):
        if has_pattern(code, r'delete\s*\(.*\bid\b') or has_pattern(code, r'object::delete'):
            return [self._make(fname, code, "Unexpired Object Access", "High", "Timing",
                                "Object is deleted — ensure it is no longer in use", "")]
        return []

    # ─── Medium ───

    def _check_missing_abort(self, fname, code):
        if has_pattern(code, r'assert!') and not has_pattern(code, r'abort\s+|EBad|EError|E\w+'):
            return [self._make(fname, code, "Missing abort code", "Medium", "Security",
                                "assert! without a specific abort code — use assert!(cond, ECODE)", "",
                                fix="assert!(cond, ECODE)")]
        return []

    def _check_always_true_assert(self, fname, code):
        findings = []
        for m in re.finditer(r'assert!\(true', code):
            findings.append(self._make(fname, code, "assert! with Always True", "Medium", "Security",
                          f"assert!(true...) — does not check anything", m.group()[:60]))
        return findings

    def _check_unbounded_vec(self, fname, code):
        if has_pattern(code, r'while\s*\(') and has_pattern(code, r'vector::length|vec::length|\.length\('):
            return [self._make(fname, code, "Unbounded vec Iteration", "Medium", "DoS",
                                "Loop on vector without maximum limit", "")]
        return []

    def _check_transfer_self(self, fname, code):
        if has_pattern(code, r'transfer\(.*\bself\b|transfer_to_self') and \
           not has_pattern(code, r'withdraw_cap|Cap'):
            return [self._make(fname, code, "Unsafe transfer to self", "Medium", "Access Control",
                                "Transfer to self without Capability", "")]
        return []

    def _check_move_events(self, fname, code):
        if not has_pattern(code, r'event::emit|Event::emit|emit\s*<'):
            return [self._make(fname, code, "Missing Event Emission", "Medium", "Best Practice",
                                "No events in this module", "",
                                fix="Add event::emit for important operations")]
        return []

    def _check_public_freeze(self, fname, code):
        if has_pattern(code, r'public.*freeze') and not has_pattern(code, r'only|admin|cap|Cap'):
            return [self._make(fname, code, "Public freeze Function", "Medium", "Access Control",
                                "Public freeze without permission — anyone can freeze", "")]
        return []

    def _check_coin_zero(self, fname, code):
        if has_pattern(code, r'Coin::zero') or has_pattern(code, r'coin::zero'):
            return [self._make(fname, code, "Unchecked Coin::zero", "Medium", "Economic",
                                "Coin::zero is used — ensure it is not used in calculations", "")]
        return []

    def _check_missing_drop(self, fname, code):
        for sname, st in self._move_structs.items():
            has_copy = "copy" in st.abilities
            has_drop = "drop" in st.abilities
            if has_copy and not has_drop:
                return [self._make(fname, code, "Missing drop Ability", "Medium", "Type Safety",
                                    f"struct {sname} with copy but no drop — may accumulate in memory", "")]
        return []

    def _check_copyable_object(self, fname, code):
        findings = []
        for sname, st in self._move_structs.items():
            has_copy = "copy" in st.abilities
            has_key = "key" in st.abilities
            if has_copy and has_key:
                findings.append(self._make(fname, code, "Copyable Object", "Medium", "Type Safety",
                              f"struct {sname} with copy + key — can be duplicated", sname))
        return findings

    def _check_vec_remove(self, fname, code):
        findings = []
        for m in re.finditer(r'vector::remove|vec::remove', code):
            ctx = code[max(0, m.start()-50):m.end()+50]
            if not has_pattern(ctx, r'swap'):
                findings.append(self._make(fname, code, "Unsafe vec::remove", "Medium", "DoS",
                              f"remove without swap — O(n) + shift", ctx[:100]))
        return findings

    # ─── Low ───

    def _check_hardcoded_addr(self, fname, code):
        findings = []
        for m in re.finditer(r'@0x[0-9a-fA-F]{10,}', code):
            findings.append(self._make(fname, code, "Hardcoded Address", "Low", "Readability",
                          f"Hardcoded address: {m.group()[:30]}", m.group(), fix="Use constant from config"))
        return findings

    def _check_assert_eq(self, fname, code):
        if has_pattern(code, r'assert_eq!|assert_ne!'):
            return [self._make(fname, code, "assert_eq / assert_ne", "Low", "Style",
                                "Prefer assert! with == or !=", "")]
        return []

    def _check_large_vec(self, fname, code):
        for m in re.finditer(r'vector\[(.+?)\]', code):
            items = m.group(1).split(',')
            if len(items) > 20:
                return [self._make(fname, code, "Large vector Literal", "Low", "Readability",
                                    f"Inline vector of length {len(items)} — use loop filling", m.group()[:100])]
        return []

    def _check_unused_fn(self, fname, code):
        findings = []
        all_names = self._ast_func_names()
        for fn_name, fn in self._move_funcs.items():
            if fn_name.startswith('_') or fn_name == 'init':
                continue
            count = len(re.findall(rf'\b{re.escape(fn_name)}\b', code))
            if count <= 1:
                findings.append(self._make(fname, code, "Unused Function", "Low", "Style",
                               f"function '{fn_name}' is defined but unused", f"fun {fn_name}"))
        return findings

    def _check_underscore_fn(self, fname, code):
        findings = []
        for fn_name in self._ast_func_names():
            if fn_name.startswith('_'):
                fn = self._move_funcs.get(fn_name)
                if fn and fn.visibility and "entry" in fn.visibility:
                    findings.append(self._make(fname, code, "Public Function Named _", "Low", "Style",
                                  f"Public entry function starts with _", f"fun {fn_name}"))
        return findings

    # ─── Info ───

    def _check_transfer_good(self, fname, code):
        if has_pattern(code, r'sui::transfer') or has_pattern(code, r'object::transfer'):
            return [self._make(fname, code, "sui::transfer Usage", "Info", "Best Practice",
                                "Uses transfer from Sui framework", "")]
        return []

    def _check_event_convention(self, fname, code):
        if has_pattern(code, r'struct\s+\w+\s+has\s+copy') and \
           has_pattern(code, r'event::emit|emit'):
            return [self._make(fname, code, "Event Convention", "Info", "Best Practice",
                                "Event struct has has copy, drop, store", "")]
        return []

    def _check_module_version(self, fname, code):
        if has_pattern(code, r'module\s+\w+::') and not has_pattern(code, r'version|VERSION'):
            return [self._make(fname, code, "Module Version", "Info", "Best Practice",
                                "Module does not have a version", "")]
        return []

    def _check_spec_block(self, fname, code):
        all_specs = [sp for mod in self._move_ast for sp in mod.specs]
        if not all_specs:
            return [self._make(fname, code, "Spec Block", "Info", "Best Practice",
                                "No specifications (spec) for formal verification", "",
                                fix="Add spec blocks for main functions")]
        return []

    def _check_friend(self, fname, code):
        all_friends = [fr for mod in self._move_ast for fr in mod.friends]
        if not all_friends and len(self._ast_func_names()) > 5:
            return [self._make(fname, code, "Friend Declaration", "Info", "Best Practice",
                                "Large module without friends", "")]
        return []