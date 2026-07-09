import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from analyzers import get_analyzer, detect_language, list_languages, SolidityAnalyzer, ChialispAnalyzer, MoveAnalyzer, VyperAnalyzer
from analyzers.base import Finding, Agent, LanguageAnalyzer


SIMPLE_SOL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vulnerable {
    mapping(address => uint) public balances;
    function withdraw(uint _amount) public {
        require(balances[msg.sender] >= _amount);
        (bool success,) = msg.sender.call{value: _amount}("");
        balances[msg.sender] -= _amount;
    }
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
}"""

SIMPLE_CHIA = """(defun simple (amount)
    (if (> amount 0)
        (CREATE_COIN puzzle_hash amount)
        ()
    )
)"""

SIMPLE_MOVE = """module example::vault {
    struct Vault has key, store {
        id: UID,
        balance: u64,
    }
    public fun deposit(vault: &mut Vault, amount: u64) {
        vault.balance = vault.balance + amount;
    }
}"""

SIMPLE_VY = """@version >=0.3.0
@external
def safe_deposit():
    self.balance += 1

@internal
def _helper():
    pass
"""

VY_REENTRANCY = """@version >=0.3.0
@external
def withdraw(amount: uint256):
    send(msg.sender, amount)
    self.balance -= amount
"""


class TestBase:
    def test_finding_dataclass(self):
        f = Finding("Agent1", "Critical", "Reentrancy", "file.sol", "fn1", "desc")
        assert f.severity == "Critical"
        assert f.agent_name == "Agent1"

    def test_agent_dataclass(self):
        a = Agent("Test", "High", "Security", lambda f, c: [])
        assert a.name == "Test"
        assert a.severity == "High"


class TestDetectLanguage:
    def test_detect_solidity_single_file(self, tmp_path):
        f = tmp_path / "contract.sol"
        f.write_text("pragma solidity ^0.8.0;")
        assert detect_language(str(f)) == "solidity"

    def test_detect_solidity_dir(self, tmp_path):
        d = tmp_path / "proj"
        d.mkdir()
        (d / "test.sol").write_text("pragma solidity ^0.8.0;")
        assert detect_language(str(d)) == "solidity"

    def test_detect_chialisp_dir(self, tmp_path):
        d = tmp_path / "puzzles"
        d.mkdir()
        (d / "puzzle.clsp").write_text("(defun test ())")
        assert detect_language(str(d)) == "chialisp"

    def test_detect_move_dir(self, tmp_path):
        d = tmp_path / "move_proj"
        d.mkdir()
        (d / "source.move").write_text("module test;")
        assert detect_language(str(d)) == "move"

    def test_list_languages(self):
        langs = list_languages()
        assert "solidity" in langs
        assert "chialisp" in langs
        assert "move" in langs


class TestSolidityAnalyzer:
    def test_get_analyzer(self):
        a = get_analyzer("solidity")
        assert isinstance(a, SolidityAnalyzer)

    def test_solidity_agents_loaded(self):
        a = SolidityAnalyzer()
        assert len(a.agents) > 10
        assert a.extensions == [".sol"]

    def test_detect_call_value(self):
        a = SolidityAnalyzer()
        results = a.analyze_file("test.sol", SIMPLE_SOL)
        agents = {r.agent_name for r in results}
        assert "Reentrancy (AST)" in agents

    def test_detect_pragma(self):
        a = SolidityAnalyzer()
        results = a.analyze_file("test.sol", SIMPLE_SOL)
        assert any("Pragma Fixed" in r.agent_name for r in results)

    def test_clean_contract_no_severe(self):
        a = SolidityAnalyzer()
        clean = "contract Safe { function f() public pure returns (uint) { return 1; } }"
        results = a.analyze_file("safe.sol", clean)
        critical_high = [r for r in results if r.severity in ("Critical", "High")]
        assert len(critical_high) == 0

    def test_count_agents(self):
        a = SolidityAnalyzer()
        agent_names = [ag.name for ag in a.agents]
        assert len(set(agent_names)) == len(agent_names), "Duplicate agent names!"


class TestChialispAnalyzer:
    def test_get_analyzer(self):
        a = get_analyzer("chialisp")
        assert isinstance(a, ChialispAnalyzer)

    def test_chialisp_agents_loaded(self):
        a = ChialispAnalyzer()
        assert len(a.agents) > 30
        assert ".clsp" in a.extensions

    def test_analyze_simple(self):
        a = ChialispAnalyzer()
        a.load_directory = lambda p: a._files.__setitem__("test.clsp", SIMPLE_CHIA) or {"test.clsp": SIMPLE_CHIA}
        a._files = {"test.clsp": SIMPLE_CHIA}
        a._funcs = [{"name": "simple", "code": SIMPLE_CHIA, "file": "test.clsp",
                     "line_start": 1, "line_end": 5, "is_inline": False}]
        results = a.analyze_file("test.clsp", SIMPLE_CHIA)
        assert isinstance(results, list)


class TestMoveAnalyzer:
    def test_get_analyzer(self):
        a = get_analyzer("move")
        assert isinstance(a, MoveAnalyzer)

    def test_move_agents_loaded(self):
        a = MoveAnalyzer()
        assert len(a.agents) > 10
        assert ".move" in a.extensions

    def test_analyze_simple(self):
        a = MoveAnalyzer()
        results = a.analyze_file("test.move", SIMPLE_MOVE)
        assert isinstance(results, list)


class TestGenerateReport:
    def test_report_empty(self):
        a = SolidityAnalyzer()
        report = a.generate_report()
        assert "FINDINGS BY SEVERITY" in report

    def test_report_with_findings(self):
        a = SolidityAnalyzer()
        a._files = {"test.sol": SIMPLE_SOL}
        results = a.analyze_file("test.sol", SIMPLE_SOL)
        a._findings = results
        report = a.generate_report({"test.sol": results})
        assert "Reentrancy" in report or "Pragma Fixed" in report


class TestVyperAnalyzer:
    def test_get_analyzer(self):
        a = get_analyzer("vyper")
        assert a is not None
        assert a.language == "vyper"

    def test_vyper_agents_loaded(self):
        a = VyperAnalyzer()
        assert len(a.agents) > 20
        assert ".vy" in a.extensions

    def test_analyze_simple(self):
        a = VyperAnalyzer()
        results = a.analyze_file("test.vy", SIMPLE_VY)
        assert isinstance(results, list)

    def test_analyze_reentrancy_detected(self):
        a = VyperAnalyzer()
        results = a.analyze_file("test.vy", VY_REENTRANCY)
        severities = [f.severity for f in results]
        assert any(s in ("Critical", "High") for s in severities)

    def test_vyper_detect_language(self, tmp_path):
        d = tmp_path / "vyper_proj"
        d.mkdir()
        (d / "contract.vy").write_text("@version >=0.3.0")
        assert detect_language(str(d)) == "vyper"
