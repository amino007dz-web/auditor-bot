"""
ZKsync Era Attack Vector Detector.
Adapted from web3-hunt-zksync-era SKILL.md — 25 attack vectors tested, 0 findings.
Used as a DEFENSE STUDY to recognize hardened vs vulnerable patterns.
"""
import logging
import re
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# The 25 attack vectors tested against ZKsync Era (0 found)
_ATTACK_VECTORS = [
    {"id": 1, "name": "UnsafeBytes offset miscalculation", "class": "incomplete_path",
     "defense": "All callers pre-validate message length before UnsafeBytes calls",
     "check": r"_parse\w+Message\b|UnsafeBytes\b"},
    {"id": 2, "name": "Legacy/new boundary double-withdrawal", "class": "off_by_one",
     "defense": "try/catch returns false on decode failure; encoding prefix discriminator prevents collision",
     "check": r"_isLegacy\b|try\s*\{[^}]*decode"},
    {"id": 3, "name": "secondBridgeAddress return value manipulation", "class": "access_control",
     "defense": ">0xFFFF check blocks system contracts; L2-side msg.sender auth",
     "check": r"requestL2Transaction\b|secondBridgeAddress\b"},
    {"id": 4, "name": "Failed deposit claim wrong amount (legacy encoding)", "class": "accounting_desync",
     "defense": "Legacy hash uses try/catch; depositHappened tracks per-encoding-version",
     "check": r"claimFailedDeposit\b|depositHappened\b"},
    {"id": 5, "name": "V29 interop root forgery", "class": "access_control",
     "defense": "addChainBatchRoot requires onlyChain + onlyL2; historical roots verified via Merkle",
     "check": r"addChainBatchRoot\b|onlyChain\b"},
    {"id": 6, "name": "Missing access control on sibling function", "class": "access_control",
     "defense": "Every external function has appropriate modifier",
     "check": r"function\s+\w+\s*\([^)]*\)\s*(public|external)"},
    {"id": 7, "name": "Fee-on-transfer token accounting desync", "class": "accounting_desync",
     "defense": "if (amount != _amount) revert TokensWithFeesNotSupported()",
     "check": r"TokensWithFeesNotSupported\b|amount\s*!=\s*_amount\b"},
    {"id": 8, "name": "Governance timelock bypass", "class": "access_control",
     "defense": "5-role RBAC via AccessControlEnumerable; block.timestamp >= commitTimestamp + delay",
     "check": r"commitTimestamp\b|ValidatorTimelock\b|timelock\b",},
    {"id": 9, "name": "GatewayTransactionFilterer bypass", "class": "access_control",
     "defense": "transactionFilterer == address(0), not used", "check": r"transactionFilterer\b"},
    {"id": 10, "name": "Precommitment sentinel collision", "class": "off_by_one",
     "defense": "_revertBatches properly resets precommitment", "check": r"_revertBatches\b|precommitment\b"},
    {"id": 11, "name": "L2→L1 message forgery", "class": "access_control",
     "defense": "Anyone can call sendToL1, but L1 verifies sender=0x8008 in log",
     "check": r"sendToL1\b|0x8008\b"},
    {"id": 12, "name": "Compressor state diff manipulation", "class": "access_control",
     "defense": "publishCompressedBytecode called only from bootloader context",
     "check": r"publishCompressedBytecode\b|bootloaderContext\b"},
    {"id": 13, "name": "Admin privilege escalation", "class": "proxy_upgrade",
     "defense": "Diamond proxy admin is governance; no facet can self-modify",
     "check": r"DiamondProxy\b|diamondCut\b"},
    {"id": 14, "name": "Fee calculation overflow", "class": "accounting_desync",
     "defense": "All fee math uses SafeMath or checked arithmetic", "check": r"unchecked[^}]*fee|fee\s*[-+*]"},
    {"id": 15, "name": "Free L2 transaction abuse", "class": "incomplete_path",
     "defense": "reservedDynamic field properly handled; bootloader validates gas",
     "check": r"reservedDynamic\b|bootloader\b"},
    {"id": 16, "name": "DataEncoding L1/L2 mismatch", "class": "off_by_one",
     "defense": "All 10 encode/decode pairs verified consistent", "check": r"encode\w*\(|decode\w*\("},
    {"id": 17, "name": "NTV token registration race", "class": "incomplete_path",
     "defense": "_ensureTokenRegistered is idempotent", "check": r"_ensureTokenRegistered\b|idempotent\b"},
    {"id": 18, "name": "Asset ID collision", "class": "off_by_one",
     "defense": "keccak256(chainId, ntvAddress, tokenAddress)", "check": r"assetId\b|keccak256.*tokenAddress"},
    {"id": 19, "name": "Beacon proxy CREATE2 collision", "class": "proxy_upgrade",
     "defense": "address determined by deployer+salt+bytecodeHash", "check": r"CREATE2\b|create2\b"},
    {"id": 20, "name": "Cross-contract reentrancy", "class": "reentrancy",
     "defense": "Each contract has independent ReentrancyGuard AND follows CEI",
     "check": r"ReentrancyGuard\b|nonReentrant\b"},
    {"id": 21, "name": "Address aliasing collision", "class": "off_by_one",
     "defense": "Bijective mapping (add/subtract offset mod 2^160)", "check": r"addressAliasing\b|L2_ETH_TOKEN\b"},
    {"id": 22, "name": "Diamond proxy selector clash", "class": "proxy_upgrade",
     "defense": "Explicit selector mapping in DiamondCut; duplicates would revert",
     "check": r"selector\b|facet\b"},
    {"id": 23, "name": "Priority tree manipulation", "class": "incomplete_path",
     "defense": "Merkle range proofs; unprocessedIndex only moves forward",
     "check": r"unprocessedIndex\b|priorityTree\b|Merkle\b"},
    {"id": 24, "name": "Chain migration state corruption", "class": "incomplete_path",
     "defense": "forwardedBridgeMint validates consistency; atomic revert on mismatch",
     "check": r"forwardedBridgeMint\b|chainMigration\b"},
    {"id": 25, "name": "Cross-chain message replay", "class": "signature_replay",
     "defense": "isWithdrawalFinalized[chainId][batch][index] prevents replay",
     "check": r"isWithdrawalFinalized\b|finalizedWithdrawals\b"},
]

# Defense patterns that make protocols hardened
_DEFENSE_PATTERNS = [
    {
        "name": "CEI Everywhere",
        "description": "Check-Effect-Interact pattern on ALL withdrawal/claim/deposit paths. State update BEFORE external call.",
        "check": r"(balances?\[.*\]\s*[-+*]?=\s*\w+\s*;)[^;]*\.call",
        "vulnerable_pattern": r"\.call[^;]*;[^}]*balances?\[",
    },
    {
        "name": "Independent Access Control",
        "description": "Each contract independently enforces access — no single RBAC failure cascades.",
        "check": r"onlyRole\b|onlyCallFrom\b|require.*msg\.sender\s*==",
    },
    {
        "name": "Encoding Collision Resistance",
        "description": "Different encoding versions have distinct first bytes — impossible to confuse formats.",
        "check": r"ENCODING_VERSION\b|version\s*=",
    },
    {
        "name": "Mature Legacy Boundary Handling",
        "description": "Multiple bridge generations coexist with version checks, try/catch, and fallback paths.",
        "check": r"legacy\b|version\b|try\s*\{|V\d+\b",
    },
    {
        "name": "Audit Fix Quality",
        "description": "Fixes are thorough — not just patches but architectural improvements.",
        "check": r"_disableInitializers\b|ReentrancyGuard\b|CEI\b",
    },
]


def check_defense_patterns(code: str) -> List[Dict]:
    """Check which defense patterns the code implements."""
    results = []
    for dp in _DEFENSE_PATTERNS:
        implemented = bool(re.search(dp["check"], code, re.IGNORECASE))
        results.append({
            "name": dp["name"],
            "description": dp["description"],
            "implemented": implemented,
        })
    return results


def check_vulnerable_patterns(code: str) -> Dict:
    """Check for vulnerable versions of defense patterns."""
    vulnerable = []
    for dp in _DEFENSE_PATTERNS:
        vp = dp.get("vulnerable_pattern")
        if vp and re.search(vp, code, re.IGNORECASE):
            vulnerable.append({
                "pattern": dp["name"],
                "vulnerable_match": True,
            })
    defense_status = check_defense_patterns(code)
    
    # Estimate how many attack vectors apply
    applicable = []
    for av in _ATTACK_VECTORS:
        if re.search(av["check"], code, re.IGNORECASE):
            applicable.append(av)
    
    return {
        "defenses": defense_status,
        "vulnerable_patterns_found": vulnerable,
        "attack_vectors_applicable": len(applicable),
        "attack_vectors": applicable,
        "estimated_hardenability": "high" if len(applicable) < 5 and not vulnerable else (
            "medium" if len(applicable) < 15 else "low"
        ),
    }


def format_zksync_report(result: Dict) -> str:
    """Format ZKsync analysis results."""
    lines = ["### ZKsync Defense Analysis"]
    
    lines.append("\n**Defense Patterns:**")
    for d in result.get("defenses", []):
        status = "✅" if d["implemented"] else "❌"
        lines.append(f"- {status} {d['name']}: {d['description']}")
    
    if result.get("vulnerable_patterns_found"):
        lines.append("\n**⚠ Vulnerable Pattern Variants Detected:**")
        for v in result["vulnerable_patterns_found"]:
            lines.append(f"- {v['pattern']}")
    
    lines.append(f"\n**Applicable Attack Vectors**: {result['attack_vectors_applicable']}/25")
    for av in result.get("attack_vectors", [])[:10]:
        lines.append(f"- #{av['id']} {av['name']} ({av['class']})")
    if len(result.get("attack_vectors", [])) > 10:
        lines.append(f"  ... and {len(result['attack_vectors']) - 10} more")
    
    hardness = result.get("estimated_hardenability", "unknown")
    if hardness == "high":
        lines.append("\n**Estimate**: Protocol appears HARDENED — expect 0 findings")
    elif hardness == "medium":
        lines.append("\n**Estimate**: Protocol has some defenses — moderate chance of findings")
    else:
        lines.append("\n**Estimate**: Protocol appears VULNERABLE — good hunting prospects")
    
    return "\n".join(lines)
