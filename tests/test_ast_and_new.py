"""Comprehensive tests for new features: AST Solidity, Chialisp Parser, CLIApp"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from analyzers import get_analyzer
from analyzers.base import Finding, HAS_TQDM
from analyzers.solidity_analyzer import SolidityAnalyzer
from analyzers.chialisp_analyzer import ChialispAnalyzer
from analyzers.move_analyzer import MoveAnalyzer
from analyzers.solidity_ast import (
    compile_to_ast, analyze_contracts, _extract_function, HAS_SOLCAST,
    has_reentrancy_pattern, has_unchecked_loop
)
from analyzers.chialisp_parser import (
    FuncDef, extract_functions, check_code, find_funcs_by_name
)


# ── Solidity Samples ──────────────────────────────

REENTRANCY_CODE = """
pragma solidity ^0.8.0;
contract Vulnerable {
    mapping(address => uint) balances;
    function withdraw(uint amt) public {
        require(balances[msg.sender] >= amt);
        (bool ok,) = msg.sender.call{value: amt}("");
        balances[msg.sender] -= amt;
    }
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
}
"""

TX_ORIGIN_CODE = """
pragma solidity ^0.8.0;
contract Auth {
    address owner;
    function setOwner(address _o) public {
        require(tx.origin == msg.sender);
        owner = _o;
    }
}
"""

TIMESTAMP_CODE = """
pragma solidity ^0.8.0;
contract Time {
    uint deadline;
    function check() public {
        require(block.timestamp > deadline);
    }
}
"""

SELFDESTRUCT_CODE = """
pragma solidity ^0.8.0;
contract Killable {
    address owner;
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function kill() public onlyOwner {
        selfdestruct(payable(owner));
    }
}
"""

LOOP_CODE = """
pragma solidity ^0.8.0;
contract Looper {
    uint[] items;
    function process() public {
        for(uint i = 0; i < items.length; i++) {
            items[i] = items[i] + 1;
        }
    }
    function safeProcess() public {
        uint[] memory mem = items;
        uint len = mem.length > 10 ? 10 : mem.length;
        for(uint i = 0; i < len; i++) { }
    }
}
"""

DELEGATECALL_CODE = """
pragma solidity ^0.8.0;
contract Proxy {
    address impl;
    function forward(bytes calldata data) public {
        (bool ok,) = impl.delegatecall(data);
        require(ok);
    }
}
"""

SAFE_WITH_REENTRANCY_GUARD = """
pragma solidity ^0.8.0;
contract Safe {
    bool locked;
    modifier nonReentrant() { require(!locked); locked = true; _; locked = false; }
    function withdraw() public nonReentrant {
        (bool ok,) = msg.sender.call{value: 1}("");
        require(ok);
    }
}
"""

ASSEMBLY_CODE = """
pragma solidity ^0.8.0;
contract Asm {
    function readStorageSlot(uint slot) public view returns (uint v) {
        assembly { v := sload(slot) }
    }
}
"""

# ── Chialisp Samples ─────────────────────────────

CHIA_CODE = """
(defun calculate_interest (principal rate time)
    (if (> principal 0)
        (/ (* principal rate) PRECISION)
        ()
    )
)

(defun-inline double (x)
    (* x 2)
)

(defun transfer (amount to)
    (CREATE_COIN to amount)
)
"""


# ════════════════════════════════════════════
# 1. AST Solidity Tests
# ════════════════════════════════════════════

@pytest.mark.skipif(not HAS_SOLCAST, reason="solcast not installed")
class TestASTCompilation:
    def test_compile_simple(self):
        units = compile_to_ast("pragma solidity ^0.8.0; contract C { uint x; }")
        assert units is not None
        contracts = analyze_contracts(units)
        assert len(contracts) == 1
        assert contracts[0].name == "C"

    def test_compile_reentrancy(self):
        units = compile_to_ast(REENTRANCY_CODE)
        assert units is not None
        contracts = analyze_contracts(units)
        assert len(contracts) == 1
        c = contracts[0]
        fns = {f.name: f for f in c.functions}
        assert "withdraw" in fns
        assert fns["withdraw"].external_calls

    def test_detect_tx_origin(self):
        units = compile_to_ast(TX_ORIGIN_CODE)
        contracts = analyze_contracts(units)
        fn = contracts[0].functions[0]
        assert fn.uses_tx_origin
        assert fn.has_require

    def test_detect_selfdestruct(self):
        units = compile_to_ast(SELFDESTRUCT_CODE)
        contracts = analyze_contracts(units)
        fn = contracts[0].functions[0]
        assert fn.uses_selfdestruct

    def test_detect_timestamp(self):
        units = compile_to_ast(TIMESTAMP_CODE)
        contracts = analyze_contracts(units)
        fn = contracts[0].functions[0]
        assert fn.uses_block_timestamp

    def test_detect_delegatecall(self):
        units = compile_to_ast(DELEGATECALL_CODE)
        contracts = analyze_contracts(units)
        fn = contracts[0].functions[0]
        assert fn.uses_delegatecall
        assert 'delegatecall' in fn.external_calls

    def test_detect_loop(self):
        units = compile_to_ast(LOOP_CODE)
        contracts = analyze_contracts(units)
        fns = {f.name: f for f in contracts[0].functions}
        assert fns["process"].has_loop
        assert fns["safeProcess"].has_loop

    def test_detect_assembly(self):
        units = compile_to_ast(ASSEMBLY_CODE)
        contracts = analyze_contracts(units)
        fn = contracts[0].functions[0]
        assert fn.uses_assembly

    def test_modifier_detection(self):
        units = compile_to_ast(SELFDESTRUCT_CODE)
        contracts = analyze_contracts(units)
        fn = contracts[0].functions[0]
        assert "onlyOwner" in fn.modifiers

    def test_non_reentrant_detected(self):
        units = compile_to_ast(SAFE_WITH_REENTRANCY_GUARD)
        contracts = analyze_contracts(units)
        fn = contracts[0].functions[0]
        assert "nonReentrant" in fn.modifiers
        assert fn.external_calls


@pytest.mark.skipif(not HAS_SOLCAST, reason="solcast not installed")
class TestSolidityAnalyzerAST:
    def test_reentrancy_detected(self):
        a = SolidityAnalyzer()
        results = a.analyze_file("test.sol", REENTRANCY_CODE)
        assert any("Reentrancy (AST)" in r.agent_name for r in results)
        assert any(r.function_name == "withdraw" for r in results)

    def test_reentrancy_skipped_safe(self):
        a = SolidityAnalyzer()
        results = a.analyze_file("test.sol", SAFE_WITH_REENTRANCY_GUARD)
        reentrancy = [r for r in results if "Reentrancy" in r.agent_name]
        assert len(reentrancy) == 0

    def test_tx_origin_detected(self):
        a = SolidityAnalyzer()
        results = a.analyze_file("test.sol", TX_ORIGIN_CODE)
        assert any("tx.origin" in r.agent_name for r in results)

    def test_selfdestruct_detected(self):
        a = SolidityAnalyzer()
        results = a.analyze_file("test.sol", SELFDESTRUCT_CODE)
        assert any("Selfdestruct" in r.agent_name for r in results)
        ast_result = [r for r in results if "Selfdestruct" in r.agent_name and r.function_name]
        assert len(ast_result) > 0

    def test_timestamp_detected(self):
        a = SolidityAnalyzer()
        results = a.analyze_file("test.sol", TIMESTAMP_CODE)
        assert any("block.timestamp" in r.agent_name for r in results)

    def test_delegatecall_detected(self):
        a = SolidityAnalyzer()
        results = a.analyze_file("test.sol", DELEGATECALL_CODE)
        assert any("DELEGATECALL" in r.agent_name for r in results)

    def test_loop_detected(self):
        a = SolidityAnalyzer()
        results = a.analyze_file("test.sol", LOOP_CODE)
        assert any("Unbounded Loop" in r.agent_name for r in results)

    def test_assembly_detected(self):
        a = SolidityAnalyzer()
        results = a.analyze_file("test.sol", ASSEMBLY_CODE)
        assert any("Assembly Block" in r.agent_name for r in results)

    def test_set_owner_not_txorigin(self):
        code = "contract C { address o; function set(address _o) public { o = _o; } }"
        a = SolidityAnalyzer()
        results = a.analyze_file("test.sol", code)
        assert not any("tx.origin" in r.agent_name for r in results)


# ════════════════════════════════════════════
# 2. Chialisp Parser Tests
# ════════════════════════════════════════════

class TestChialispParser:
    def test_funcdef_creation(self):
        f = FuncDef(name="test", file="f.clsp", code="(defun test ())",
                     line_start=1, line_end=1)
        assert f.name == "test"
        assert not f.is_inline

    def test_extract_functions(self):
        funcs = extract_functions(CHIA_CODE, "test.clsp")
        names = {f.name for f in funcs}
        assert "calculate_interest" in names
        assert "double" in names
        assert "transfer" in names

    def test_is_inline_detected(self):
        funcs = extract_functions(CHIA_CODE, "test.clsp")
        double = [f for f in funcs if f.name == "double"][0]
        assert double.is_inline

    def test_params_extracted(self):
        funcs = extract_functions(CHIA_CODE, "test.clsp")
        calc = [f for f in funcs if f.name == "calculate_interest"][0]
        assert calc.params == ["principal", "rate", "time"]

    def test_calls_extracted(self):
        funcs = extract_functions(CHIA_CODE, "test.clsp")
        f = funcs[0]
        assert f.calls  # has at least some calls

    def test_check_code(self):
        assert check_code(r"defun", CHIA_CODE)
        assert not check_code(r"nonexistent", CHIA_CODE)

    def test_find_funcs_by_name(self):
        funcs = extract_functions(CHIA_CODE, "test.clsp")
        found = find_funcs_by_name(funcs, r"interest|double")
        assert len(found) >= 2

    def test_empty_code(self):
        funcs = extract_functions("", "empty.clsp")
        assert len(funcs) == 0

    def test_edge_bracket_matching(self):
        code = "(defun deep (x) (if (> x 0) (begin (foo x) (bar x)) ()))"
        funcs = extract_functions(code, "e.clsp")
        assert len(funcs) == 1
        assert funcs[0].name == "deep"

    def test_multiple_funcs(self):
        code = "(defun a ()) (defun b ()) (defun c ())"
        funcs = extract_functions(code, "m.clsp")
        assert len(funcs) == 3
        assert [f.name for f in funcs] == ["a", "b", "c"]

    def test_large_bracket_nesting(self):
        code = "(defun nested (x) (f (g (h (j x)))))"
        funcs = extract_functions(code, "n.clsp")
        assert len(funcs) == 1
        assert funcs[0].code.endswith(')))')


# ════════════════════════════════════════════
# 3. Comprehensive analyzer tests
# ════════════════════════════════════════════

class TestAnalyzersIntegration:
    def test_analyze_all_languages(self):
        for lang in ["solidity", "chialisp", "move"]:
            a = get_analyzer(lang)
            assert a is not None
            assert len(a.agents) > 5

    def test_no_crash_on_empty_code(self):
        for lang, cls in [("solidity", SolidityAnalyzer),
                          ("chialisp", ChialispAnalyzer),
                          ("move", MoveAnalyzer)]:
            a = cls()
            results = a.analyze_file("empty", "")
            assert isinstance(results, list)

    def test_tqdm_flag(self):
        assert HAS_TQDM is True or HAS_TQDM is False

    def test_finding_dataclass_defaults(self):
        f = Finding("Agent", "High", "Cat", "f.sol", "fn", "desc")
        assert f.code_snippet == ""
        assert f.line == 0
        assert f.fix == ""


# ════════════════════════════════════════════
# 4. CLIApp Tests
# ════════════════════════════════════════════

class TestCLIApp:
    def test_cli_app_imports(self):
        from main import CLIApp, interactive_mode, cli_mode
        assert CLIApp is not None

    def test_report_dir_creation(self):
        from main import ensure_report_dir, REPORT_DIR
        ensure_report_dir()
        assert os.path.isdir(REPORT_DIR)

    def test_save_report(self):
        from main import save_report_txt, REPORT_DIR
        save_report_txt("test_report.txt", "Hello World")
        path = os.path.join(REPORT_DIR, "test_report.txt")
        assert os.path.isfile(path)
        with open(path, encoding="utf-8") as f:
            assert f.read() == "Hello World"
        os.remove(path)

    def test_interactive_dispatch_keys(self):
        from main import INTERACTIVE_DISPATCH
        for k in ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
                  "11", "12", "13", "14", "15", "16"]:
            assert k in INTERACTIVE_DISPATCH, f"Missing dispatch key {k}"

    def test_menu_has_exit(self):
        from main import MENU_ITEMS
        assert any(k == "0" and "Exit" in desc for k, desc in MENU_ITEMS)


# ════════════════════════════════════════════
# 5. HTML Report Tests
# ════════════════════════════════════════════

class TestHTMLReport:
    def test_findings_to_html_basic(self):
        from analyzers.base import findings_to_html, Finding
        f = [Finding("Reentrancy", "Critical", "Security", "f.sol", "withdraw",
                     "Reentrancy vulnerability", "call.value", 10, "Use nonReentrant")]
        html = findings_to_html(f, "Test Analyzer", 1)
        assert "Test Analyzer" in html
        assert "Critical" in html
        assert "Reentrancy" in html
        assert "nonReentrant" in html
        assert "withdraw" in html

    def test_findings_to_html_empty(self):
        from analyzers.base import findings_to_html
        html = findings_to_html([], "Empty Report")
        assert "Empty Report" in html
        assert "0" in html
        assert "No findings found" in html

    def test_findings_to_html_multiple_severities(self):
        from analyzers.base import findings_to_html, Finding
        findings = [
            Finding("Agent1", "Critical", "Cat1", "f.sol", "fn1", "desc1", "snippet1", 0, "fix1"),
            Finding("Agent2", "Medium", "Cat2", "f.sol", "fn2", "desc2", "", 0, ""),
            Finding("Agent3", "High", "Cat3", "f.sol", "fn3", "desc3", "snippet3", 42, "fix3"),
        ]
        html = findings_to_html(findings, "Multi", 2)
        assert "Critical" in html
        assert "Medium" in html
        assert "High" in html
        assert "snippet1" in html
        assert "snippet3" in html

    def test_findings_to_html_with_errors(self):
        from analyzers.base import findings_to_html, Finding
        f = [Finding("A", "Info", "Cat", "f.sol", "fn", "desc")]
        html = findings_to_html(f, "Test", 1, agent_errors=["Agent X failed", "Agent Y failed"])
        assert "Agent X failed" in html
        assert "Agent Y failed" in html

    def test_findings_to_html_escape(self):
        from analyzers.base import findings_to_html, Finding
        f = [Finding("A&B", "Low", "Cat", "f.sol", "fn", "desc<test>", "<script>alert('xss')</script>")]
        html = findings_to_html(f, "Esc& Test")
        assert "A&amp;B" in html
        assert "desc&lt;test&gt;" in html
        assert "&lt;script&gt;" in html
        assert '<script>' not in html  # raw script should be escaped

    def test_generate_text_report(self):
        from analyzers.base import findings_to_html
        from analyzers import SolidityAnalyzer
        a = SolidityAnalyzer()
        code = "contract C { function f(uint x) public pure returns (uint) { return x; } }"
        results_list = a.analyze_file("test.sol", code)
        html = findings_to_html(results_list, "Sol Test", 1)
        assert html.startswith("<!DOCTYPE html>")
        assert len(html) > 200


# ════════════════════════════════════════════
# 6. Enhanced Chialisp Analyzer Tests
# ════════════════════════════════════════════

class TestChialispEnhanced:
    CHIA_CODE = """(defun calculate_interest (principal rate time)
    (if (> principal 0)
        (/ (* principal rate) PRECISION)
        ()
    )
)
(defun-inline double (x) (* x 2))
"""

    def test_dynamic_angles(self):
        from analyzers.chialisp_analyzer import ChialispAnalyzer
        a = ChialispAnalyzer()
        a._files = {"test.clsp": self.CHIA_CODE}
        a._funcs = []
        from analyzers.chialisp_parser import extract_functions
        a._funcs.extend(extract_functions(self.CHIA_CODE, "test.clsp"))
        results = a._dynamic_angles()
        assert isinstance(results, list)

    def test_combinatorial_agents(self):
        from analyzers.chialisp_analyzer import ChialispAnalyzer
        a = ChialispAnalyzer()
        a._files = {"test.clsp": self.CHIA_CODE}
        from analyzers.chialisp_parser import extract_functions
        a._funcs = extract_functions(self.CHIA_CODE, "test.clsp")
        results = a._combinatorial_agents()
        assert isinstance(results, list)
        if results:
            assert hasattr(results[0], 'severity')

    def test_run_complete_audit_no_files(self):
        from analyzers.chialisp_analyzer import ChialispAnalyzer
        a = ChialispAnalyzer()
        report = a.run_complete_audit()
        assert "No files to analyze" in report

    def test_attack_chains_empty(self):
        from analyzers.chialisp_analyzer import ChialispAnalyzer
        a = ChialispAnalyzer()
        a._findings = []
        chains = a._build_attack_chains()
        assert isinstance(chains, list)
        assert len(chains) == 0

    def test_attack_chains_with_findings(self):
        from analyzers.chialisp_analyzer import ChialispAnalyzer
        from analyzers.base import Finding
        a = ChialispAnalyzer()
        a._findings = [
            Finding("Agent1", "Critical", "Type Safety", "vault.clsp", "fn1", "desc1"),
            Finding("Agent2", "Critical", "Economic", "vault.clsp", "fn2", "desc2"),
            Finding("Agent3", "High", "Access Control", "vault.clsp", "fn3", "desc3"),
        ]
        chains = a._build_attack_chains()
        assert len(chains) >= 1
        assert any("vault.clsp" in c for c in chains)

    def test_cross_file_attack_chain(self):
        from analyzers.chialisp_analyzer import ChialispAnalyzer
        from analyzers.base import Finding
        a = ChialispAnalyzer()
        a._findings = [
            Finding("Critical1", "Critical", "Type Safety", "vault1.clsp", "fn1", "desc1"),
            Finding("Critical2", "Critical", "Economic", "vault2.clsp", "fn2", "desc2"),
            Finding("Critical3", "Critical", "Access Control", "vault3.clsp", "fn3", "desc3"),
        ]
        chains = a._build_attack_chains()
        cross_file = [c for c in chains if "files" in c]
        assert len(cross_file) >= 1

    def test_reentrancy_chain(self):
        from analyzers.chialisp_analyzer import ChialispAnalyzer
        from analyzers.base import Finding
        a = ChialispAnalyzer()
        a._findings = [
            Finding("Cross-Coin Reentrancy", "Low", "External Interaction", "f.clsp", "", ""),
            Finding("CREATE_COIN_ANNOUNCEMENT", "Medium", "Spoofing", "f.clsp", "", ""),
        ]
        chains = a._build_attack_chains()
        assert any("Reentrancy" in c for c in chains) or any("External" in c for c in chains)

    def test_agent_50_stub(self):
        from analyzers.chialisp_analyzer import ChialispAnalyzer
        a = ChialispAnalyzer()
        results = a._agent_50("test.clsp", "")
        assert results == []
