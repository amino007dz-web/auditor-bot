"""
Bug Detector — 16 DeFi bug classes with detection patterns.
Adapted from web3-bug-classes SKILL.md.
Each class has: grep patterns, kill signals, severity hints, and detection rules.
"""
import logging
import re
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_BUG_CLASSES = {}

_BUG_CLASSES["accounting_desync"] = {
    "name": "Accounting State Desynchronization",
    "rank": 1,
    "frequency": "28% of Criticals",
    "description": "Two state variables should stay in sync. One path updates A but forgets B.",
    "grep_patterns": [
        r"totalSupply\s*[-+*]=[^=]",
        r"totalShares\s*[-+*]=[^=]",
        r"totalAssets\s*[-+*]=[^=]",
        r"totalDebt\s*[-+*]=[^=]",
        r"cumulativeReward\s*[-+*]=[^=]",
        r"rewardPerShare\s*[-+*]=[^=]",
    ],
    "vulnerable_patterns": [
        r"totalSupply\s*-=\s*\w+\s*;.*\n(?:[^}]*\n)*?.*\.transfer",
        r"\.call\{value.*\}\(\).*\n(?:[^}]*\n)*?.*totalSupply\s*-=",
        r"return;?\s*\n(?:[^}]*\n)*?(?:cumulativeReward|totalDebt|_redemptionWeight)",
    ],
    "kill_signals": [
        "Only one variable involved (no pair to desync)",
        "Both paths update all state vars identically",
        "Transfer happens AFTER state update in every path",
        "Single-transaction atomicity prevents intermediate state",
    ],
    "severity_hint": "Critical/High",
    "detect": lambda code: _run_grep(code, "accounting_desync"),
}

_BUG_CLASSES["access_control"] = {
    "name": "Access Control",
    "rank": 2,
    "frequency": "19% of Criticals",
    "description": "Function should be restricted but is callable by anyone. Or wrong check (existence vs ownership).",
    "grep_patterns": [
        r"function\s+\w+\s*\([^)]*\)\s*(?:public|external)(?:\s+(?:view|pure))?\s*(?:returns?[^\{]*)?\s*\{",
        r"function initialize\b[^}]*\{",
        r"_requireOwned\b",
        r"_isApprovedOrOwner\b",
    ],
    "vulnerable_patterns": [
        r"modifier\s+\w+\s*\(\s*\)\s*\{[^}]*if\s*\([^)]*\)\s*\{",
        r"function\s+(?:mint|burn|emergencyWithdraw|upgradeTo)\b[^}]*\bpublic\b(?!.*(?:only|require|modifier|auth))",
        r"function initialize\b[^}]*(?!initializer|_disableInitializers)",
    ],
    "kill_signals": [
        "Function has correct modifier using `require` (not silent `if`)",
        "Upgrade functions have onlyOwner in _authorizeUpgrade",
        "_disableInitializers() is present in implementation constructor",
        "All roles referenced in onlyRole() are actually granted",
    ],
    "severity_hint": "Critical/High",
    "detect": lambda code: _run_grep(code, "access_control"),
}

_BUG_CLASSES["incomplete_path"] = {
    "name": "Incomplete Code Path",
    "rank": 3,
    "frequency": "17% of Criticals",
    "description": "Happy path handles tokens correctly. Alternate path skips refunds, state updates, or cleanup.",
    "grep_patterns": [
        r"function\s+(?:place_|create_|add_|open_)\w+",
        r"function\s+(?:update_|modify_|edit_|change_)\w+",
        r"safeApprove\b",
        r"_refundExcess\w+",
        r"delete\b[^}]*\n(?:[^}]*\n)*?\.call\(",
    ],
    "vulnerable_patterns": [
        r"safeApprove\([^,]+,\s*\w+\)(?!\s*;\s*safeApprove\([^,]+,\s*0\))",
        r"delete\s+\w+\[.*\]\s*;.*\n(?:[^}]*\n)*?\.call\{value",
        r"return;?\s*\n(?:[^}]*\n)*(?!.*\b(?:update|increment|decrement|transfer)\b).*(?:mint|burn)\b",
    ],
    "kill_signals": [
        "update/cancel functions explicitly handle token transfers in all cases",
        "Partial fills refund both ETH and ERC20 paths",
        "safeApprove(router, 0) present before every safeApprove(router, amount)",
        "deposit() and mint() both call the same internal _deposit()",
    ],
    "severity_hint": "Critical/High",
    "detect": lambda code: _run_grep(code, "incomplete_path"),
}

_BUG_CLASSES["off_by_one"] = {
    "name": "Off-By-One & Boundary Conditions",
    "rank": 4,
    "frequency": "22% of Highs",
    "description": "Wrong comparison operator at boundary. `>` excludes the equal case where `>=` is needed.",
    "grep_patterns": [
        r"(?:period|epoch|round)\w*.*[<>][^=]",
        r"timestamp.*[<>][^=]",
        r"deadline.*[<>][^=]",
        r"cutoff|threshold.*[<>][^=]",
        r"i\s*<=\s*.*\.length\b",
        r"\bbreak\b.*\n(?:[^}]*\n)*?[<>][^=]",
    ],
    "vulnerable_patterns": [
        r"(?:endPeriod|exitPeriod|endTimestamp|deadline)\s*>\s*\w+",
        r"for\s*\([^)]*;\s*t\s*<=\s*\w+\s*;\s*[^)]*\)\s*\{[^}]*if\s*\(t\s*>\s*\w+\)\s*break",
        r"i\s*<=\s*\w+\.length",
    ],
    "kill_signals": [
        "Both >= and > are present with distinct intent",
        "Unit tests explicitly cover the equal-case boundary",
        "No period/epoch system in the contract",
    ],
    "severity_hint": "High",
    "detect": lambda code: _run_grep(code, "off_by_one"),
}

_BUG_CLASSES["oracle_manipulation"] = {
    "name": "Oracle / Price Manipulation",
    "rank": 5,
    "frequency": "12% of reports, largest payouts",
    "description": "Wrong price read → undercollateralized loans, fake asset minting, bad liquidations.",
    "grep_patterns": [
        r"latestRoundData\(\)",
        r"getReserves\(\)",
        r"slot0\b",
        r"latestAnswer\(\)",
        r"sequencerUptimeFeed",
        r"balanceOf\(address\(this\)\).*total",
    ],
    "vulnerable_patterns": [
        r"latestRoundData\(\)(?!.*updatedAt)",
        r"getReserves\(\).*return\s+\w+\s*[-+*/]\s*\w+",
        r"slot0\(\)",
        r"balanceOf\(address\(this\)\).*totalS",
        r"latestAnswer\(\)",
    ],
    "kill_signals": [
        "Protocol has no lending/borrowing (yield-only vaults safe)",
        "All price reads use TWAP with >= 30 minutes",
        "Price has both staleness AND validity checks",
        "Sequencer uptime check present on L2",
    ],
    "severity_hint": "Critical/High",
    "detect": lambda code: _run_grep(code, "oracle_manipulation"),
}

_BUG_CLASSES["erc4626_vault"] = {
    "name": "ERC4626 Vault Bugs",
    "rank": 6,
    "frequency": "Common in 2024-2025",
    "description": "First depositor inflation, share transfer without stake migration, rounding direction attacks.",
    "grep_patterns": [
        r"convertToShares\b",
        r"totalAssets\(\)",
        r"_update\b.*\n.*override",
        r"\.decimals\(\)",
    ],
    "vulnerable_patterns": [
        r"convertToShares[^}]*totalSupply\(\).*\n.*totalAssets\(\)(?!.*\+ 1)",
        r"totalAssets\(\)[^}]*balanceOf\(address\(this\)\)",
        r"_update\(.*\).*\n(?:[^}]*\n)*(?!.*migrate|.*stake)",
    ],
    "kill_signals": [
        "OpenZeppelin ERC4626 v4.9+ with _decimalsOffset()",
        "Protocol is NOT ERC4626 (simpler 1:1 share model)",
        "Transfers disabled entirely (TransferLocked pattern)",
        "totalAssets() uses internal tracked balance",
    ],
    "severity_hint": "High/Critical",
    "detect": lambda code: _run_grep(code, "erc4626_vault"),
}

_BUG_CLASSES["reentrancy"] = {
    "name": "Reentrancy (All Variants)",
    "rank": 7,
    "frequency": "8% of Criticals, $300M+ losses since Jan 2024",
    "description": "External call before state update. Classic, cross-function, read-only, cross-contract.",
    "grep_patterns": [
        r"\.call\{value",
        r"\.call\(",
        r"safeTransfer\b",
        r"safeTransferFrom\b",
        r"\.transfer\(",
        r"\.send\(",
    ],
    "vulnerable_patterns": [
        r"balances?\[.*\]\s*[-+*]?=\s*\w+\s*;.*\n(?:[^}]*\n)*?\.call\{value",
        r"\.call\{value[^}]*\}\([^)]*\)(?!\s*;\s*balances?\s*\[)",
        r"\.execute\{value[^}]*\}\([^)]*\)(?!\s*;\s*balances?\s*\[)",
    ],
    "kill_signals": [
        "All _processYield / _claim functions follow CEI",
        "Reward token is not ERC777 (no tokensReceived hook)",
        "nonReentrant present on all external-call functions",
        "harvest() requires whitelisted caller",
    ],
    "severity_hint": "Critical",
    "detect": lambda code: _run_grep(code, "reentrancy"),
}

_BUG_CLASSES["flash_loan"] = {
    "name": "Flash Loan Attacks",
    "rank": 8,
    "frequency": "83% of exploits use flash loans",
    "description": "Flash loans give zero-cost capital for 1 block. Any spot-price or governance check is vulnerable.",
    "grep_patterns": [
        r"getReserves\(\)",
        r"slot0\b",
        r"balanceOf\(address\(this\)\)",
        r"flashLoan\b",
        r"receiveFlashLoan\b",
        r"executeOperation\b",
    ],
    "vulnerable_patterns": [
        r"getReserves\(\).*(?:return|price|collateral)",
        r"slot0\(\).*(?:return|price|collateral)",
        r"balanceOf\(address\(this\)\).*total(?:Supply|Assets)",
        r"function\s+flashLoan\b[^}]*\b(receiver|borrower)\b[^}]*(?:\.transfer|\.safeTransfer)\s*\([^)]*(?:receiver|borrower)",
    ],
    "kill_signals": [
        "Protocol has no lending/borrowing, oracle pricing, or governance",
        "Early withdrawal fee > flash loan profit",
        "Harvest requires whitelisted caller",
        "All price reads use TWAP",
    ],
    "severity_hint": "Critical/High",
    "detect": lambda code: _run_grep(code, "flash_loan"),
}

_BUG_CLASSES["signature_replay"] = {
    "name": "Signature Replay",
    "rank": 9,
    "frequency": "3% of reports, high payout $5K-$500K",
    "description": "Missing chainId, nonce, or deadline in signed messages. Cross-chain or same-chain replay.",
    "grep_patterns": [
        r"ecrecover\b",
        r"ECDSA\.recover\b",
        r"DOMAIN_SEPARATOR",
        r"nonces?\b",
        r"permit\b",
        r"chainId",
    ],
    "vulnerable_patterns": [
        r"ecrecover\([^)]*\)(?!.*nonce)",
        r"ECDSA\.recover\([^)]*\)(?!.*nonce)",
        r"(?:chainId|block\.chainid)(?!.*DOMAIN_SEPARATOR)",
    ],
    "kill_signals": [
        "DOMAIN_SEPARATOR includes both block.chainid and address(this)",
        "All signature uses have nonces with nonces[user]++",
        "OpenZeppelin ECDSA library used throughout",
        "No off-chain signature mechanism",
    ],
    "severity_hint": "High/Critical",
    "detect": lambda code: _run_grep(code, "signature_replay"),
}

_BUG_CLASSES["proxy_upgrade"] = {
    "name": "Proxy / Upgrade Bugs",
    "rank": 10,
    "frequency": "2% of reports, biggest payouts ($10M Wormhole)",
    "description": "Uninitialized implementation, storage collision, UUPS without _authorizeUpgrade.",
    "grep_patterns": [
        r"function initialize\b",
        r"_disableInitializers\b",
        r"_authorizeUpgrade\b",
        r"upgradeTo\b",
        r"delegatecall\b",
        r"__gap\b",
    ],
    "vulnerable_patterns": [
        r"function initialize\b[^}]*(?!initializer)",
        r"function _authorizeUpgrade\b[^}]*\{\s*\}",
        r"constructor\(\)\s*\{[^}]*(?!_disableInitializers)",
    ],
    "kill_signals": [
        "Contract is NOT upgradeable",
        "Constructor calls _disableInitializers()",
        "_authorizeUpgrade has onlyOwner",
        "Storage layout shows __gap arrays",
    ],
    "severity_hint": "Critical",
    "detect": lambda code: _run_grep(code, "proxy_upgrade"),
}

_BUG_CLASSES["unchecked_return_value"] = {
    "name": "Unchecked Return Value",
    "rank": 11,
    "frequency": "5-10% of reports",
    "description": "Low-level .call()/.delegatecall()/.send() return value ignored. Failed calls don't revert, leading to silent failures.",
    "grep_patterns": [
        r"\.call\([^)]*\)",
        r"\.delegatecall\([^)]*\)",
        r"\.send\([^)]*\)",
        r"success\s*=\s*\w+\.call",
        r"\(bool\s+success",
    ],
    "vulnerable_patterns": [
        r"\.call\{value[^}]*\}\([^)]*\)\s*(?:;|\n(?!.*require.*success))",
        r"\.delegatecall\([^)]*\)\s*;\s*(?!.*require\b)",
        r"\.send\([^)]*\)\s*;\s*(?!.*require\b)",
        r"\(bool\s+\w+,\s*\)\s*=\s*\w+\.call[^;]*;(?!.*\b\w+\b)",
    ],
    "kill_signals": [
        "require(success) present after every .call()",
        "Uses OpenZeppelin Address.sendValue() which reverts on failure",
        "Return value is explicitly checked in all code paths",
        "Uses ReentrancyGuard with CEI pattern",
    ],
    "severity_hint": "High",
    "detect": lambda code: _run_grep(code, "unchecked_return_value"),
}

_BUG_CLASSES["msg_value_reuse"] = {
    "name": "msg.value Reuse in Loops",
    "rank": 12,
    "frequency": "Rare but critical ($10M+ MISO/Opyn)",
    "description": "msg.value does not change during execution. Using it inside a loop allows same ETH to be counted multiple times.",
    "grep_patterns": [
        r"msg\.value",
        r"for\s*\(",
        r"while\s*\(",
    ],
    "vulnerable_patterns": [
    ],
    "multiline_patterns": [
        r"for\s*\([^)]*\)[^{]*\{[^}]*msg\.value",
        r"while\s*\([^)]*\)[^{]*\{[^}]*msg\.value",
        r"do\s*\{[^}]*msg\.value[^}]*\}\s*while",
    ],
    "kill_signals": [
        "Loop tracks total ETH sent separately (sum of individual payments)",
        "msg.value is validated before entering loop (must equal expected total)",
        "Only one iteration possible (loop condition prevents multiple)",
        "Payment amount is computed per-iteration, not from msg.value directly",
    ],
    "severity_hint": "Critical",
    "detect": lambda code: _run_grep(code, "msg_value_reuse"),
}

_BUG_CLASSES["tx_origin_auth"] = {
    "name": "tx.origin Authentication",
    "rank": 13,
    "frequency": "2-3% of reports",
    "description": "Using tx.origin instead of msg.sender for authorization. A intermediate contract can impersonate the original caller.",
    "grep_patterns": [
        r"tx\.origin",
    ],
    "vulnerable_patterns": [
        r"require\(tx\.origin\s*==",
        r"if\s*\(tx\.origin\s*==",
        r"require\(.*tx\.origin",
        r"tx\.origin\s*==\s*(?:owner|admin|msg\.sender)",
    ],
    "kill_signals": [
        "tx.origin is only used for informational events, not authorization",
        "Function has additional msg.sender check alongside tx.origin",
        "tx.origin is compared against a trusted relayer address with nonce verification",
    ],
    "severity_hint": "High",
    "detect": lambda code: _run_grep(code, "tx_origin_auth"),
}

_BUG_CLASSES["bad_randomness"] = {
    "name": "Bad Randomness Source",
    "rank": 14,
    "frequency": "3% of reports (gambling/lottery/NFT)",
    "description": "Using block.timestamp, blockhash, block.prevrandao, or block.number as randomness. Miners can manipulate these.",
    "grep_patterns": [
        r"block\.timestamp\b",
        r"block\.number\b",
        r"blockhash\b",
        r"block\.difficulty\b",
        r"block\.prevrandao\b",
        r"block\.chainid\b",
    ],
    "vulnerable_patterns": [
        r"block\.timestamp\b[^;]*%[^;]*;",
        r"block\.number\b[^;]*%[^;]*;",
        r"blockhash\b[^;]*%[^;]*;",
        r"uint\(block\.timestamp\)",
        r"keccak256\(.*block\.(?:timestamp|number|difficulty|prevrandao)",
        r"block\.timestamp\b[^;]*\%\s*(?:\d+|participants|winners|players)",
        r"blockhash\(block\.number\s*[-+]",
    ],
    "kill_signals": [
        "Uses Chainlink VRF for randomness",
        "Commit-reveal scheme separates seed generation from reveal",
        "block.timestamp only used for time-based expiry, not randomness",
        "Uses prevrandao from recent beacon chain with additional entropy",
    ],
    "severity_hint": "High",
    "detect": lambda code: _run_grep(code, "bad_randomness"),
}

_BUG_CLASSES["arbitrary_call"] = {
    "name": "Arbitrary External Call",
    "rank": 15,
    "frequency": "4-5% of reports (bridges, proxy patterns)",
    "description": "User-supplied calldata passed to address.call() without validation. Allows arbitrary logic execution.",
    "grep_patterns": [
        r"\.call\([^)]*\)",
        r"\.delegatecall\([^)]*\)",
        r"staticcall\b",
        r"functionCall\b",
    ],
    "vulnerable_patterns": [
        r"address\([^)]*\)\.call\(\s*(?:data|payload|_data|_calldata|calldata)",
        r"\.call\(\s*(?:abi\.encodeWithSignature|abi\.encodeWithSelector)[^)]*\);",
        r"(?:target|_to|addr|contract|implementation)\.call\{?[^}]*\}?\s*\(\s*(?:data|_data|payload|_payload|_calldata|calldata)",
        r"(?:target|_to|addr|contract|implementation)\.(?:functionCall|call)\{?[^}]*\}?\s*\(\s*(?:data|_data|payload|_payload|_calldata)",
        r"(?:target|_to|addr|contract|implementation)\.delegatecall\(\s*(?:data|_data|payload|_payload|_calldata)",
    ],
    "kill_signals": [
        "Call targets are restricted to a whitelist of approved addresses",
        "Calldata is constructed from a fixed function selector, not user-supplied",
        "Only staticcall (read-only) is used with external addresses",
        "Delegatecall is only used with known implementation addresses via UUPS/transparent proxy",
    ],
    "severity_hint": "Critical",
    "detect": lambda code: _run_grep(code, "arbitrary_call"),
}

_BUG_CLASSES["fee_on_transfer_token"] = {
    "name": "Fee-on-Transfer / Non-Standard Token",
    "rank": 16,
    "frequency": "3-5% of reports",
    "description": "Assumes token.transfer() transfers exactly 'amount'. Fee-on-transfer, rebasing, or deflationary tokens break this.",
    "grep_patterns": [
        r"safeTransfer\b",
        r"safeTransferFrom\b",
        r"\.transfer\(",
        r"\.transferFrom\(",
        r"balanceOf\(address\(this\)\)",
    ],
    "vulnerable_patterns": [
        r"\.transfer(?:From)?\([^,]+,\s*(?:amount|_amount|value)\s*\)\s*;(?!.*balanceOf)",
        r"safeTransfer[^)]*,\s*(?:amount|_amount)\s*\)\s*;(?!.*balanceOf)",
        r"\.transfer\([^)]*\)\s*;\s*(?:\n|.)*?(?:emit\s+Transfer|emit\s+Deposit)(?!.*balanceOf)",
    ],
    "kill_signals": [
        "Uses balanceOf(address(this)) before and after transfer to track actual received amount",
        "Token is assumed to be standard (documented in comments)",
        "Uses pull-over-push pattern where user initiates withdrawal",
        "Only trusted/whitelisted tokens are accepted",
        "Transfer amount is validated against actual balance change",
    ],
    "severity_hint": "High",
    "detect": lambda code: _run_grep(code, "fee_on_transfer_token"),
}

_BUG_CLASS_ORDER = [
    "accounting_desync",
    "access_control",
    "incomplete_path",
    "off_by_one",
    "oracle_manipulation",
    "erc4626_vault",
    "reentrancy",
    "flash_loan",
    "signature_replay",
    "proxy_upgrade",
    "unchecked_return_value",
    "msg_value_reuse",
    "tx_origin_auth",
    "bad_randomness",
    "arbitrary_call",
    "fee_on_transfer_token",
]


def _run_grep(code: str, bug_class: str) -> List[Dict]:
    """Run grep patterns for a bug class against code. Returns matching locations."""
    info = _BUG_CLASSES.get(bug_class)
    if not info:
        return []
    matches = []
    patterns = info.get("vulnerable_patterns", [])
    lines = code.split("\n")
    for i, line in enumerate(lines):
        for pat in patterns:
            try:
                m = re.search(pat, line, re.IGNORECASE)
                if m:
                    matches.append({
                        "line": i + 1,
                        "content": line.strip(),
                        "pattern": pat,
                        "class": bug_class,
                    })
            except re.error:
                pass
    # Also check vulnerable patterns against full code for multi-line matches
    for pat in patterns:
        try:
            for m in re.finditer(pat, code, re.IGNORECASE | re.DOTALL):
                match_text = m.group()
                if "\n" not in match_text:
                    continue  # already caught by line-by-line scan
                line_no = code[:m.start()].count("\n") + 1
                # avoid duplicates: check if same line+pattern already reported
                dup = any(
                    x["line"] == line_no and x["pattern"] == pat and x["class"] == bug_class
                    for x in matches
                )
                if not dup:
                    matches.append({
                        "line": line_no,
                        "content": match_text[:80].replace("\n", "\\n"),
                        "pattern": pat,
                        "class": bug_class,
                    })
        except re.error:
            pass
    # Also check dedicated multiline patterns
    ml_patterns = info.get("multiline_patterns", [])
    for pat in ml_patterns:
        try:
            for m in re.finditer(pat, code, re.IGNORECASE | re.DOTALL):
                line_no = code[:m.start()].count("\n") + 1
                matches.append({
                    "line": line_no,
                    "content": m.group()[:80].replace("\n", "\\n"),
                    "pattern": pat,
                    "class": bug_class,
                })
        except re.error:
            pass
    return matches


def detect_all(code: str) -> Dict[str, List[Dict]]:
    """Run all bug class detectors against code. Returns dict of class -> matches."""
    results = {}
    for key in _BUG_CLASS_ORDER:
        matches = _BUG_CLASSES[key]["detect"](code)
        if matches:
            results[key] = matches
    return results


def get_summary(code: str) -> List[Dict]:
    """Get a flat list of all potential issues found across all bug classes."""
    all_matches = detect_all(code)
    summary = []
    for cls, matches in all_matches.items():
        info = _BUG_CLASSES.get(cls, {})
        summary.append({
            "class": cls,
            "name": info.get("name", cls),
            "severity_hint": info.get("severity_hint", "Medium"),
            "frequency": info.get("frequency", ""),
            "match_count": len(matches),
            "matches": matches,
        })
    return summary


def get_bug_class_info(cls: str) -> Optional[Dict]:
    """Get full info for a specific bug class."""
    return _BUG_CLASSES.get(cls)


def get_grep_commands(cls: str) -> List[str]:
    """Get grep commands for a specific bug class."""
    info = _BUG_CLASSES.get(cls)
    if not info:
        return []
    return info.get("grep_patterns", [])


def get_kill_signals(cls: str) -> List[str]:
    """Get kill signals for a specific bug class."""
    info = _BUG_CLASSES.get(cls)
    if not info:
        return []
    return info.get("kill_signals", [])
