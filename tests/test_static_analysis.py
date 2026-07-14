import sys
import os
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from static_analysis.opcode_tracer import analyze_opcodes
from static_analysis.storage_analyzer import analyze_storage_single, _extract_contracts_from_code, _compute_storage_layout
from static_analysis.inheritance_analyzer import analyze_inheritance
from static_analysis.combined_report import generate_combined_report


SIMPLE_CONTRACT = """
// SPDX-License-Identifier: MIT
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
}
"""

INHERITANCE_CONTRACT = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Base {
    uint public x;
}

contract Middle is Base {
    uint public y;
}

contract Child is Middle {
    uint public z;
}
"""

STORAGE_CONTRACT = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract StorageTest {
    uint256 public a;
    address public b;
    bool public c;
    mapping(address => uint) public d;
}
"""


class TestOpcodeAnalysis:
    def test_detect_call_value(self):
        report = analyze_opcodes(SIMPLE_CONTRACT)
        assert "call_value" in report or ".call{value}" in report or "CRITICAL" in report
        assert len(report) > 50

    def test_clean_contract_no_findings(self):
        clean = "contract Safe { function f() public pure returns (uint) { return 1; } }"
        report = analyze_opcodes(clean)
        assert "No dangerous" in report

    def test_detect_assembly(self):
        code = "contract C { function f() { assembly { let x := 1 } } }"
        report = analyze_opcodes(code)
        assert "assembly" in report.lower() and "MEDIUM" in report


class TestStorageAnalysis:
    def test_extract_contracts(self):
        contracts = _extract_contracts_from_code(SIMPLE_CONTRACT)
        assert "Vulnerable" in contracts
        assert len(contracts["Vulnerable"]["state_vars"]) > 0

    def test_storage_layout(self):
        contracts = _extract_contracts_from_code(STORAGE_CONTRACT)
        layout = _compute_storage_layout(contracts, "StorageTest")
        assert len(layout) >= 3
        assert layout[0]["name"] == "a"
        assert layout[0]["slot"] == 0

    def test_storage_report(self):
        report = analyze_storage_single(STORAGE_CONTRACT)
        assert "Storage Analysis" in report
        assert "StorageTest" in report


class TestInheritanceAnalysis:
    def test_inheritance_chain(self):
        report = analyze_inheritance(INHERITANCE_CONTRACT)
        assert "Child" in report and "Middle" in report and "Base" in report
        assert "depth" in report

    def test_no_contracts(self):
        report = analyze_inheritance("// just a comment")
        assert "No contracts found" in report


class TestCombinedReport:
    def test_combined_generation(self):
        report = generate_combined_report(SIMPLE_CONTRACT, "TestContract")
        assert "TestContract" in report
        assert "Opcode Analysis" in report
        assert "Storage Analysis" in report
        assert "Inheritance Analysis" in report


class TestASTAnalysis:
    def test_ast_storage_simple(self):
        from static_analysis.ast_analyzer import analyze_storage_with_ast
        code = "contract C { uint256 public a; address public b; bool public c; }"
        report = analyze_storage_with_ast(code)
        assert "C" in report
        assert "a" in report
        assert "b" in report
        assert "c" in report

    def test_ast_storage_no_contracts(self):
        from static_analysis.ast_analyzer import analyze_storage_with_ast
        report = analyze_storage_with_ast("// just comment")
        assert report is not None

    def test_ast_inheritance_simple(self):
        from static_analysis.ast_analyzer import analyze_inheritance_with_ast
        code = INHERITANCE_CONTRACT
        report = analyze_inheritance_with_ast(code)
        assert "Child" in report
        assert "Middle" in report
        assert "Base" in report

    def test_ast_inheritance_empty(self):
        from static_analysis.ast_analyzer import analyze_inheritance_with_ast
        report = analyze_inheritance_with_ast("// nothing")
        assert report is not None

    def test_ast_storage_layout(self):
        from static_analysis.ast_analyzer import analyze_storage_with_ast
        code = STORAGE_CONTRACT
        report = analyze_storage_with_ast(code)
        assert "StorageTest" in report
        assert "slot" in report.lower() or "Slot" in report

    def test_ast_combined_report(self):
        from static_analysis.ast_analyzer import generate_combined_ast_report
        code = SIMPLE_CONTRACT
        report = generate_combined_ast_report(code, "TestVuln")
        assert "TestVuln" in report

    def test_ast_inheritance_detects_storage_collision(self):
        from static_analysis.ast_analyzer import analyze_inheritance_with_ast
        code = """
        pragma solidity ^0.8.0;
        contract Base { uint256 x; }
        contract Child is Base {
            function callBase(address addr) public {
                (bool ok,) = addr.delegatecall(abi.encodeWithSignature("setX(uint256)", 1));
                require(ok);
            }
        }"""
        report = analyze_inheritance_with_ast(code)
        assert "DELEGATECALL" in report or "Delegatecall" in report or "delegatecall" in report
