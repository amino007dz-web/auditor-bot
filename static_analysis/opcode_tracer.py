import re
from typing import List, Dict

OPCODE_PATTERNS = {
    "call_value": {
        "pattern": r"\.call\s*\{\s*value\s*:\s*(.+?)\}\s*\((.*?)\)",
        "severity": "CRITICAL",
        "description": "ETH transfer via .call{value} — susceptible to reentrancy and FIFO DoS",
        "fix": "Use safeTransfer instead of .call{value} or add try/catch"
    },
    "delegatecall": {
        "pattern": r"delegatecall",
        "severity": "HIGH",
        "description": "DELEGATECALL — changes storage context, proxy/upgrade risk",
        "fix": "Ensure target address is trusted and not mutable"
    },
    "selfdestruct": {
        "pattern": r"selfdestruct",
        "severity": "HIGH",
        "description": "SELFDESTRUCT — can destroy the contract and send ETH to any address",
        "fix": "Remove selfdestruct or add onlyOwner protection"
    },
    "tx_origin": {
        "pattern": r"tx\.origin",
        "severity": "MEDIUM",
        "description": "tx.origin for authentication — vulnerable to phishing attacks",
        "fix": "Use msg.sender instead of tx.origin"
    },
    "unchecked_loop": {
        "pattern": r"unchecked\s*\{[\s\S]*?\+\+[\s\S]*?\}",
        "severity": "LOW",
        "description": "unchecked increment in loop — may hide overflow",
        "fix": "Ensure counter does not reach max uint256"
    },
    "block_timestamp": {
        "pattern": r"block\.timestamp",
        "severity": "MEDIUM",
        "description": "block.timestamp — can be manipulated by 15-30 seconds by miner",
        "fix": "Do not use block.timestamp for deciding user funds"
    },
    "weth_withdraw": {
        "pattern": r"\.withdraw\s*\(\s*\d+\s*\)",
        "severity": "MEDIUM",
        "description": "WETH.withdraw() — converts WETH to ETH, may fail if balance is insufficient",
        "fix": "Ensure balance exists before calling"
    },
    "low_level_call": {
        "pattern": r"\.call\s*\{[^}]*\}\s*\(",
        "severity": "HIGH",
        "description": "Low-level CALL — reentrancy and DoS risk if receiver fails",
        "fix": "Use try/catch or use ERC-20 interface instead of low-level call"
    },
    "assembly": {
        "pattern": r"assembly\s*\{",
        "severity": "MEDIUM",
        "description": "Assembly — low-level code not subject to Solidity compiler checks",
        "fix": "Minimize assembly usage to absolute necessity"
    },
    "safe_transfer": {
        "pattern": r"safeTransfer\s*\(",
        "severity": "INFO",
        "description": "safeTransfer — good because it uses try/catch internally",
        "fix": "—"
    },
    "safe_transfer_from": {
        "pattern": r"safeTransferFrom\s*\(",
        "severity": "INFO",
        "description": "safeTransferFrom — good because it uses try/catch internally",
        "fix": "—"
    },
}

def analyze_opcodes(code: str) -> str:
    findings = []
    for name, info in OPCODE_PATTERNS.items():
        matches = re.findall(info["pattern"], code, re.IGNORECASE)
        if matches:
            for match in matches:
                findings.append({
                    "name": name, "severity": info["severity"],
                    "description": info["description"],
                    "match": str(match)[:100], "fix": info["fix"]
                })
    if not findings:
        return "## Opcode Analysis\n\n✅ No dangerous opcode patterns found.\n"
    report = "## Opcode Analysis (EVM)\n\n"
    report += "| # | Pattern | Severity | Description | Fix |\n"
    report += "|-------|-------|---------|-------|--------|\n"
    for i, f in enumerate(findings, 1):
        report += f"| {i} | `{f['name']}` | **{f['severity']}** | {f['description'][:60]} | {f['fix'][:60]} |\n"
    report += "\n### Details\n\n"
    for f in findings:
        report += f"- **{f['name']}** ({f['severity']}): {f['description']}\n"
        report += f"  - Matched text: `{f['match']}`\n"
        report += f"  - Fix: {f['fix']}\n\n"
    return report
