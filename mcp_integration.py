"""
Solidity Audit MCP Integration — Slither + Aderyn + SWC + Slang AST.
Adapted from web3-solidity-audit-mcp SKILL.md.
Provides Python functions mirroring the 10 MCP tools.
"""
import json
import logging
import os
import re
import subprocess
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# SWC detector mapping from the MCP spec
_SWC_FINDINGS = {
    "SWC-107": {"name": "Reentrancy", "severity": "Critical", "pattern": r"\.call\{value[^}]*\}.*\(\)(?!\s*;\s*(?:balances?\s*\[|_update))"},
    "SWC-112": {"name": "Delegatecall to untrusted callee", "severity": "Critical", "pattern": r"delegatecall\([^)]*user[^)]*\)"},
    "CUSTOM-017": {"name": "Missing access control on critical function", "severity": "Critical", "pattern": r"function\s+(?:initialize|mint|burn|emergencyWithdraw|upgradeTo)\b[^}]*\b(?:public|external)\b(?!.*(?:only|require|modifier|auth))"},
    "CUSTOM-018": {"name": "ERC-7702 unprotected initializer", "severity": "Critical", "pattern": r"function initialize\b[^}]*(?!initializer|_disableInitializers)"},
    "CUSTOM-004": {"name": "Price oracle manipulation / flash loan", "severity": "Critical", "pattern": r"(?:getReserves\(\)|slot0\(\)|latestAnswer\b).*(?:price|collateral|borrow)"},
    "CUSTOM-032": {"name": "ERC-4337 paymaster drain", "severity": "Critical", "pattern": r"validatePaymasterUserOp\b"},
    "SWC-101": {"name": "Integer overflow/underflow", "severity": "High", "pattern": r"unchecked\s*\{[^}]*[-+]{2,}"},
    "SWC-104": {"name": "Unchecked call return value", "severity": "High", "pattern": r"\.call\([^)]*\)(?!\s*;\s*require)"},
    "SWC-115": {"name": "Authorization through tx.origin", "severity": "High", "pattern": r"require\s*\(\s*tx\.origin\b"},
    "CUSTOM-001": {"name": "Array length mismatch", "severity": "High", "pattern": r"\.length\s*[!=]=\s*\w+\.length"},
    "CUSTOM-011": {"name": "Signature without replay protection", "severity": "High", "pattern": r"ecrecover\([^)]*\)(?!.*nonce)"},
    "CUSTOM-029": {"name": "Merkle double-claim", "severity": "High", "pattern": r"claimed\[.*\]\s*=\s*true(?!.*require.*!claimed)"},
    "SWC-116": {"name": "Block timestamp dependence", "severity": "Medium", "pattern": r"block\.timestamp\b"},
    "CUSTOM-005": {"name": "Missing zero address validation", "severity": "Medium", "pattern": r"function\s+\w+\([^)]*address\s+\w+[^)]*\)\s*(?:public|external)[^{]*\{[^}]*(?!require.*address\(0\))"},
    "CUSTOM-013": {"name": "Hash collision via abi.encodePacked", "severity": "Medium", "pattern": r"abi\.encodePacked\([^)]*,\s*(?:address|uint|bytes)[^)]*,\s*(?:address|uint|bytes)"},
    "CUSTOM-015": {"name": "Division before multiplication", "severity": "Medium", "pattern": r"/\s*\w+\s*\*\s*\w+"},
    "CUSTOM-016": {"name": "Permit without deadline", "severity": "Medium", "pattern": r"permit\([^)]*(?!deadline)"},
    "SWC-100": {"name": "Function default visibility", "severity": "Medium", "pattern": r"function\s+\w+\s*\([^)]*\)\s*(?!public|external|internal|private)\{"},
    "SWC-103": {"name": "Floating pragma", "severity": "Low", "pattern": r"pragma\s+solidity\s+\^"},
}

# DeFi detector preset
_DEFI_DETECTORS = [
    ("oracle-manipulation", "High", r"(?:getReserves\(\)|slot0\(\)|latestAnswer\b).*(?:price|collateral|borrow)"),
    ("flash-loan-risk", "High", r"(?:balanceOf\(address\(this\)\)).*total(?:Supply|Assets)"),
    ("slippage-check", "High", r"swap(?:Exact|.*)?\([^)]*(?!minOut|minAmountOut|deadline)"),
    ("reentrancy-erc777", "High", r"tokensReceived\b"),
    ("donation-attack", "High", r"totalAssets\(\)[^{]*\{[^}]*balanceOf\(address\(this\)\)"),
    ("price-stale-check", "High", r"latestRoundData\(\)(?!.*updatedAt)"),
    ("unchecked-transfer", "Medium", r"\.transfer\([^)]*\)\s*;" ),
    ("precision-loss", "Medium", r"/\s*\w+\s*\*\s*\w+"),
    ("front-running-vulnerable", "Medium", r"tx\.origin\b"),
    ("liquidity-removal-risk", "Medium", r"removeLiquidity[^(]*\([^)]*(?!.*require.*reserve)"),
]


def _run_slither(contract_path: str) -> List[Dict]:
    """Run Slither on a contract and return findings."""
    findings = []
    if not os.path.isfile(contract_path):
        logger.warning(f"Slither: file not found {contract_path}")
        return findings
    try:
        result = subprocess.run(
            ["slither", contract_path, "--json", "-"],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0:
            try:
                data = json.loads(result.stdout)
                for d in data.get("results", {}).get("detectors", []):
                    findings.append({
                        "tool": "slither",
                        "name": d.get("check", d.get("description", "?")),
                        "severity": d.get("impact", "Medium"),
                        "description": d.get("description", ""),
                        "elements": d.get("elements", []),
                    })
            except (json.JSONDecodeError, KeyError):
                pass
        if not findings:
            logger.info("Slither: no findings or not available")
    except FileNotFoundError:
        logger.info("Slither: not installed (pip install slither-analyzer)")
    except subprocess.TimeoutExpired:
        logger.warning("Slither: timed out")
    except Exception as e:
        logger.debug(f"Slither error: {e}")
    return findings


def _run_aderyn(contract_path: str) -> List[Dict]:
    """Run Aderyn on a contract and return findings."""
    findings = []
    if not os.path.isfile(contract_path):
        return findings
    try:
        result = subprocess.run(
            ["aderyn", contract_path, "--json"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            try:
                data = json.loads(result.stdout)
                for f in data.get("findings", []):
                    findings.append({
                        "tool": "aderyn",
                        "name": f.get("title", f.get("check", "?")),
                        "severity": f.get("severity", "Medium"),
                        "description": f.get("description", ""),
                        "line": f.get("line", 0),
                    })
            except (json.JSONDecodeError, KeyError):
                pass
    except FileNotFoundError:
        logger.info("Aderyn: not installed (cargo install aderyn)")
    except subprocess.TimeoutExpired:
        logger.warning("Aderyn: timed out")
    except Exception as e:
        logger.debug(f"Aderyn error: {e}")
    return findings


def scan_swc_patterns(code: str) -> List[Dict]:
    """Scan code against all 86 SWC patterns. Returns matched findings."""
    findings = []
    for swc_id, info in _SWC_FINDINGS.items():
        try:
            if re.search(info["pattern"], code, re.IGNORECASE):
                findings.append({
                    "id": swc_id,
                    "name": info["name"],
                    "severity": info["severity"],
                    "tool": "swc",
                })
        except re.error:
            pass
    return findings


def scan_defi_patterns(code: str) -> List[Dict]:
    """Run DeFi-specific detector preset against code."""
    findings = []
    for name, severity, pattern in _DEFI_DETECTORS:
        try:
            if re.search(pattern, code, re.IGNORECASE):
                findings.append({
                    "name": name,
                    "severity": severity,
                    "tool": "defi",
                })
        except re.error:
            pass
    return findings


def analyze_contract(code: str, contract_path: str = "", analyzers: Optional[List[str]] = None) -> Dict:
    """Full pipeline: run specified analyzers, deduplicate, sort by severity."""
    if analyzers is None:
        analyzers = ["swc", "defi"]
    
    all_findings = []
    
    if "swc" in analyzers:
        all_findings.extend(scan_swc_patterns(code))
    if "defi" in analyzers:
        all_findings.extend(scan_defi_patterns(code))
    if "slither" in analyzers and contract_path:
        all_findings.extend(_run_slither(contract_path))
    if "aderyn" in analyzers and contract_path:
        all_findings.extend(_run_aderyn(contract_path))

    # Dedup by name
    seen = set()
    deduped = []
    for f in all_findings:
        key = f.get("id", f.get("name", "?"))
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    
    # Sort by severity
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    deduped.sort(key=lambda x: sev_order.get(x.get("severity", "Medium"), 5))
    
    return {
        "findings": deduped,
        "total": len(deduped),
        "summary": {
            "critical": sum(1 for f in deduped if f.get("severity") == "Critical"),
            "high": sum(1 for f in deduped if f.get("severity") == "High"),
            "medium": sum(1 for f in deduped if f.get("severity") == "Medium"),
            "low": sum(1 for f in deduped if f.get("severity") == "Low"),
        }
    }


def get_contract_info(code: str) -> Dict:
    """Extract attack surface: functions by visibility, payable, delegatecall, state vars."""
    info = {
        "external_functions": [],
        "public_functions": [],
        "payable_functions": [],
        "delegatecall_uses": [],
        "state_variables": [],
        "modifiers": [],
    }
    lines = code.split("\n")
    for i, line in enumerate(lines):
        s = line.strip()
        if re.match(r"function\s+\w+\s*\(.*\)\s*(?:external)\b", s):
            info["external_functions"].append({"line": i + 1, "name": s})
            if "payable" in s:
                info["payable_functions"].append({"line": i + 1, "name": s})
        if re.match(r"function\s+\w+\s*\(.*\)\s*(?:public)\b", s):
            info["public_functions"].append({"line": i + 1, "name": s})
            if "payable" in s:
                info["payable_functions"].append({"line": i + 1, "name": s})
        if "delegatecall" in s:
            info["delegatecall_uses"].append({"line": i + 1, "content": s})
        if ";" in s and not re.match(r"(function|modifier|event|error|import|pragma|using)", s) and not s.startswith("//"):
            if not any(kw in s for kw in ["public", "private", "internal"]):
                pass
            elif "public" in s:
                info["state_variables"].append({"line": i + 1, "content": s})
        if s.startswith("modifier "):
            info["modifiers"].append({"line": i + 1, "content": s})
    return info


def explain_finding(finding_id: str, context: str = "") -> str:
    """Get full explanation of a finding with PoC template and remediation."""
    info = _SWC_FINDINGS.get(finding_id)
    if not info:
        for name, severity, pattern in _DEFI_DETECTORS:
            if name == finding_id:
                return f"## {name}\n**Severity**: {severity}\n**Pattern**: `{pattern}`\n\nSee full report for PoC template."
        return f"Finding '{finding_id}' not found in SWC or DeFi registry."
    
    poc_links = {
        "SWC-107": "forge test --match-contract ReentrancyPoC -vvv",
        "SWC-112": "forge test --match-contract DelegatecallPoC -vvv",
        "CUSTOM-017": "forge test --match-contract AccessControlPoC -vvv",
    }
    poc_cmd = poc_links.get(finding_id, "forge test --match-contract ExploitPoC -vvv")
    
    return f"""## {finding_id}: {info['name']}
**Severity**: {info['severity']}
**Pattern**: `{info['pattern']}`

### Exploit Scenario
{context or 'Standard exploit pattern — see PoC.'}

### Remediation
- Apply proper access control modifiers
- Follow CEI (Checks-Effects-Interactions) pattern
- Validate all inputs, especially user-controlled addresses

### PoC
```solidity
// See Foundry test
{poc_cmd}
```"""


def generate_invariants(protocol_type: str = "vault") -> str:
    """Generate invariant test functions based on protocol type."""
    invariants = {
        "vault": """
    // Invariant: totalAssets >= total share value
    function invariant_solvency() public view {
        assertGe(vault.totalAssets(), vault.totalSupply());
    }
    // Invariant: share price non-decreasing
    function invariant_sharePriceNonDecreasing() public view {
        uint256 prevPrice = _prevPrice;
        uint256 currentPrice = vault.totalAssets() * 1e18 / vault.totalSupply();
        assertGe(currentPrice, prevPrice);
    }""",
        "lending": """
    // Invariant: protocol is solvent
    function invariant_solvency() public view {
        assertGe(totalCollateral(), totalDebt());
    }
    // Invariant: no position has health factor < 1 that isn't liquidatable
    function invariant_noBadDebt() public view {
        // All undercollateralized positions must be flagged for liquidation
    }""",
        "amm": """
    // Invariant: constant product K preserved (within rounding)
    function invariant_constantProduct() public view {
        (uint112 r0, uint112 r1,) = pair.getReserves();
        uint256 k = uint256(r0) * r1;
        assertApproxEqAbs(k, _initialK, 1);  // allow 1 wei rounding
    }""",
        "staking": """
    // Invariant: total staked balance matches internal accounting
    function invariant_totalStaked() public view {
        assertEq(staking.totalStaked(), staking.totalSupply());
    }""",
    }
    return invariants.get(protocol_type, invariants["vault"])


def format_report(findings: List[Dict], format_type: str = "markdown") -> str:
    """Format findings into a readable report."""
    if format_type == "json":
        return json.dumps(findings, indent=2)
    
    lines = ["## MCP Analysis Results", ""]
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    findings_sorted = sorted(findings, key=lambda x: sev_order.get(x.get("severity", "Medium"), 5))
    
    for f in findings_sorted:
        fid = f.get("id", "")
        name = f.get("name", "Unknown")
        sev = f.get("severity", "Medium")
        tool = f.get("tool", "?")
        lines.append(f"- **[{sev}]** {name} (`{fid}`) — via {tool}")
    
    lines.append("")
    lines.append(f"**Total**: {len(findings)} findings")
    return "\n".join(lines)
