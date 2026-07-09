"""Gas Analysis - analyze gas consumption and optimization."""
import re
from typing import List, Dict

GAS_PATTERNS = [
    (r"\bfor\s*\([^;]*;\s*[^;]*;\s*i\+\+\s*\)", "Loop with i++ (use ++i)", "medium"),
    (r"\bfor\s*\([^;]*;\s*[^;]*;\s*i\s*=\s*i\s*\+\s*1\s*\)", "Loop with i = i + 1 (use ++i)", "medium"),
    (r"\brequire\s*\([^)]*\)", "require() without reason string (gas penalty)", "low"),
    (r"\baddress\s*\(this\)\.balance", "address(this).balance (use address(this).balance directly)", "info"),
    (r"\bdelete\b", "delete (use zero-assignment for gas refund)", "low"),
    (r"\bpublic\s+\w+\s+\w+\s*;", "Public state variable (use private + getter)", "low"),
    (r"\bstring\s+\w+\s*;", "String state variable (use bytes32 when possible)", "medium"),
    (r"\bfor\s*\([^;]*;\s*[^;]*;\s*[^)]*\)\s*\{", "Loop (consider caching array length)", "info"),
    (r"\b\.length\b", ".length in loop (cache in memory)", "info"),
    (r"\buint\b(?!\s*256)", "uint (use uint256 explicitly)", "info"),
    (r"\b(msg\.sender|tx\.origin)\b", "msg.sender/tx.origin in loop (gas cost)", "low"),
    (r"\bkeccak256\b", "keccak256 (expensive — use sparingly)", "medium"),
    (r"\bSSTORE\b|\bsstore\b", "SSTORE (22k gas cold, 5k warm)", "high"),
    (r"\bSLOAD\b|\bsload\b", "SLOAD (2.1k gas cold, 100 warm)", "medium"),
    (r"\bcall\s*\{value\b", "call{value} (use transfer pattern)", "medium"),
    (r"\bimport\b", "Import statement (unused imports cost deployment)", "low"),
]


def analyze_gas(code: str) -> str:
    """Analyze gas consumption in the code."""
    findings: List[Dict] = []
    lines = code.split("\n")

    for pattern, desc, severity in GAS_PATTERNS:
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "line": i,
                    "severity": severity,
                    "finding": desc,
                    "code": line.strip()[:120],
                })

    if not findings:
        return "## Gas Analysis\n\n_No gas issues detected._"

    result = ["# Gas Optimization Report\n"]

    # Statistics
    sev_count = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev_count[f["severity"]] = sev_count.get(f["severity"], 0) + 1

    result.append("### Summary")
    result.append(f"- High: {sev_count['high']} | Medium: {sev_count['medium']} | Low: {sev_count['low']} | Info: {sev_count['info']}")
    result.append(f"- **Estimated savings:** ~{sev_count['high'] * 5000 + sev_count['medium'] * 500 + sev_count['low'] * 50} gas")
    result.append("")

    # Recommendations
    result.append("### Recommendations")
    for s in ["high", "medium", "low", "info"]:
        items = [f for f in findings if f["severity"] == s]
        if not items:
            continue
        label = {"high": "🔴 High", "medium": "🟡 Medium", "low": "🟢 Low", "info": "🔵 Info"}[s]
        result.append(f"**{label}**")
        for it in items[:10]:
            result.append(f"- Line {it['line']}: {it['finding']}")
            result.append(f"  `{it['code']}`")
        if len(items) > 10:
            result.append(f"  _...and {len(items) - 10} more_")
        result.append("")

    return "\n".join(result)


def _count_severity(report: str) -> dict:
    """Count findings by severity from text report."""
    counts: dict[str, int] = {"high": 0, "medium": 0, "low": 0, "info": 0}
    sev_map = {"high": 0, "medium": 0, "low": 0, "info": 0}
    current = None
    for line in report.split("\n"):
        lower = line.strip().lower()
        for s in sev_map:
            if lower.startswith(f"**{s}") or lower.startswith(f"*{s}"):
                current = s
                break
            if lower.startswith(f"**🔴") and s == "high": current = s; break
            if lower.startswith(f"**🟡") and s == "medium": current = s; break
            if lower.startswith(f"**🟢") and s == "low": current = s; break
            if lower.startswith(f"**🔵") and s == "info": current = s; break
        if current and line.strip().startswith("- Line "):
            counts[current] = counts.get(current, 0) + 1
    return counts


def estimate_gas_savings(code: str) -> dict:
    """Estimate gas savings in USD."""
    analysis = analyze_gas(code)
    counts = _count_severity(analysis)
    high = counts["high"]
    medium = counts["medium"]
    low = counts["low"]
    gas_saved = high * 5000 + medium * 500 + low * 50
    eth_price = 3000  # Approximate ETH price
    eth_saved = gas_saved * 1e-9 * 0.1  # 0.1 gwei ≈ average price
    return {
        "gas_saved": gas_saved,
        "eth_saved": round(eth_saved, 6),
        "usd_saved": round(eth_saved * eth_price, 2),
    }
