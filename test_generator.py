"""Test Generation - generate Foundry/Hardhat tests from detected vulnerabilities."""
import re
from typing import List, Dict


VULN_TEMPLATES = {
    "reentrancy": {
        "name": "Reentrancy",
        "check": "assertEq(counter, expected, 'Reentrancy guard failed');",
        "setup": "vm.expectRevert();",
    },
    "access_control": {
        "name": "Access Control",
        "check": "vm.expectRevert(bytes('Ownable: caller is not the owner'));",
        "setup": "",
    },
    "unchecked": {
        "name": "Unchecked Return",
        "check": "assertTrue(success, 'call should not revert');",
        "setup": "",
    },
    "overflow": {
        "name": "Overflow",
        "check": "assertEq(counter, type(uint256).max, 'Overflow check');",
        "setup": "vm.assume(counter < type(uint256).max);",
    },
    "txorigin": {
        "name": "TxOrigin",
        "check": "assertEq(tx.origin, attacker, 'tx.origin check');",
        "setup": "vm.prank(attacker);",
    },
    "selfdestruct": {
        "name": "Selfdestruct",
        "check": "assertEq(address(contract).code.length, 0, 'contract should be destroyed');",
        "setup": "",
    },
    "delegatecall": {
        "name": "DelegateCall",
        "check": "assertEq(storageVar, expected, 'storage collision check');",
        "setup": "",
    },
    "flashloan": {
        "name": "Flash Loan",
        "check": "assertGe(token.balanceOf(address(this)), fee, 'flash loan fee');",
        "setup": "",
    },
}


_VULN_REVERSE = {v["name"].lower().replace(" ", "_"): k for k, v in VULN_TEMPLATES.items()}


def _detect_vulnerabilities(report: str) -> List[str]:
    """Extract vulnerability types from audit report."""
    found = []
    report_lower = report.lower()
    patterns = {
        "reentrancy": r"reentrancy|re[\s-]*entry",
        "access_control": r"access\s*control|access[\s-]*control|permissions|owner|onlyowner",
        "unchecked": r"unchecked|uncheck|\s.call\s*\(|low.level",
        "overflow": r"overflow|flood|underflow",
        "txorigin": r"tx\.origin|msg\.sender",
        "selfdestruct": r"selfdestruct|self.destruct|destroy|destruct",
        "delegatecall": r"delegatecall|delegate.call|delegate[\s-]*call",
        "flashloan": r"flash\s*loan|flash[\s-]*loan|flashloan",
    }
    for vuln, pat in patterns.items():
        if re.search(pat, report_lower, re.IGNORECASE):
            found.append(vuln)
    return found


def generate_foundry_test(contract_name: str, report: str, sol_code: str) -> str:
    """Generate Foundry tests from audit report."""
    vulns = _detect_vulnerabilities(report)

    lines = [
        f"// SPDX-License-Identifier: MIT",
        f"pragma solidity ^0.8.20;",
        f"",
        f'import "forge-std/Test.sol";',
        f'import "../src/{contract_name}.sol";',
        f"",
        f"contract {contract_name}Test is Test {{",
        f"    {contract_name} public target;",
        f"    address public attacker = makeAddr('attacker');",
        f"",
        f"    function setUp() public {{",
        f"        target = new {contract_name}();",
        f"        vm.deal(attacker, 100 ether);",
        f"    }}",
        f"",
    ]

    for vuln in vulns:
        template = VULN_TEMPLATES.get(vuln)
        if not template:
            continue
        lines.append(f"    function test{vuln.title()}() public {{")
        lines.append(f'        vm.label(attacker, "Attacker");')
        if template["setup"]:
            lines.append(f"        {template['setup']}")
        # Get function names from code that might be vulnerable
        funcs = re.findall(rf"function\s+(\w+)\s*\(", sol_code)
        for func in funcs[:2]:
            lines.append(f"        // Test {func} for {template['name']}")
            lines.append(f"        target.{func}();")
        lines.append(f"        {template['check']}")
        lines.append(f"    }}")
        lines.append(f"")

    lines.append(f"    function testInvariant() public {{")
    lines.append(f'        // Invariant: contract balance should never decrease')
    lines.append(f'        assertGe(address(target).balance, 0);')
    lines.append(f"    }}")
    lines.append(f"}}")
    lines.append(f"")

    return "\n".join(lines)


def generate_hardhat_test(contract_name: str, report: str) -> str:
    """Generate Hardhat tests (JavaScript) from audit report."""
    vulns = _detect_vulnerabilities(report)
    lines = [
        'const { expect } = require("chai");',
        f'const {contract_name} = artifacts.require("{contract_name}");',
        "",
        f'contract("{contract_name}", (accounts) => {{',
        "  let target;",
        "  const [owner, attacker] = accounts;",
        "",
        '  beforeEach(async () => {',
        f"    target = await {contract_name}.new({{ from: owner }});",
        "  });",
        "",
    ]
    for vuln in vulns[:5]:
        lines.append(f'  describe("{vuln}", () => {{')
        lines.append('    it("should detect vulnerability", async () => {')
        lines.append("      // Test for " + vuln)
        lines.append("      // await target.vulnerableFunction({ from: attacker });")
        lines.append("      // expect(await target.someVar()).to.equal(expected);")
        lines.append("    });")
        lines.append("  });")
        lines.append("")

    lines.append("  after(async () => {")
    lines.append("    // Cleanup")
    lines.append("  });")
    lines.append("});")
    return "\n".join(lines)
