import logging
import re

from agents.llm_client import call_model_with_fallback

logger = logging.getLogger(__name__)

_has_cvss = False
try:
    import cvss_scorer as _cvss
    _has_cvss = True
except ImportError:
    pass


def validate_report(report: str, code: str, language: str = "english") -> str:
    """Second-pass validator: aggressively removes false positives from the report."""
    prompt = f"""You are a strict validator. Your ONLY job is to REMOVE false positives from the audit report below.

## Rules for removal:
1. **Remove any finding** that matches a KNOWN SAFE PATTERN:
   - tstore/tload reentrancy guard
   - nonReentrant modifier
   - CEI pattern (state change before external call)
   - Multicall intentional partial failure
   - Ternary-guarded division (end > start ? ... : 0)
   - safeTransfer/safeTransferFrom
   - WETH.withdraw() + transfer pattern
   - block.timestamp for expiry/deadline
   - unchecked arithmetic with bounded values
   - Constructor immutables
   - OpenZeppelin standard patterns
2. **Downgrade severity** if overstated: Critical->High, High->Medium, Medium->Low, Low->Info
3. **Remove any finding** that has NO concrete exploit path (just theoretical)
4. **Remove any finding** that says "could lead to" without showing HOW

## Original Report to Validate:
{report}

## Original Code:
```solidity
{(code or "")[:3000]}
```

## Output Format:
### Overall Security Rating: [A+ / A / B / C / D / F]

### Vulnerability List (only validated findings — NONE if all removed)
- **Name**: ...
- **Severity**: [Critical / High / Medium / Low]
- **Description**: [with EXPLOIT PATH]
- **Fix**: ...

### Gas Optimizations
- ...

### Fixed Code (if any genuine findings remained)
"""
    try:
        return call_model_with_fallback(prompt)
    except Exception as e:
        logger.warning(f"Validation failed: {e}")
        return report


def self_critique(report: str, code: str) -> str:
    prompt = f"""You are a second reviewer focused on REMOVING false positives.

Do NOT add new findings. Your ONLY job:
1. Remove findings with no realistic exploit path
2. Downgrade inflated severity
3. Flag analysis errors in the original report
4. Return a validated, cleaner report

Original report:
{report}

Original code:
```solidity
{(code or "")[:3000]}
```

Output in English:
## Validated Report
### Removed Findings: [list what was removed and why]
### Downgraded Severity: [list what was changed]
### Remaining Findings (validated):
- **Name**: ...
- **Severity**: ...
- **Exploit Path**: (concrete steps)
"""
    try:
        critique = call_model_with_fallback(prompt)
        return critique
    except Exception as e:
        logger.warning(f"Critique failed: {e}")
        return report


def cvss_score_report(report: str) -> dict:
    if _has_cvss:
        try:
            return _cvss.score_report(report)
        except Exception as e:
            return {"error": str(e)}
    return {"error": "CVSS scorer not available"}


def _self_evaluate(report: str, code: str) -> dict:
    scores = {
        "has_exploit_path": 0.0,
        "fix_preserves_logic": 0.0,
        "severity_appropriate": 0.0,
        "specificity": 0.0,
    }
    report_lower = report.lower()

    if any(kw in report_lower for kw in ("how to exploit", "exploit path", "proof of concept", "poc", "forge test")):
        scores["has_exploit_path"] = 1.0
    elif any(kw in report_lower for kw in ("attack", "malicious", "exploit", "steal", "drain")):
        scores["has_exploit_path"] = 0.7
    elif any(kw in report_lower for kw in ("could lead to", "potential", "possibly")):
        scores["has_exploit_path"] = 0.3

    fix_phrases = ("change", "replace", "add", "remove", "require", "use")
    preserve_phrases = ("without affecting", "preserves", "remains unchanged", "does not change")
    has_fix = any(f in report_lower for f in fix_phrases)
    has_preserve = any(p in report_lower for p in preserve_phrases)
    if has_fix and has_preserve:
        scores["fix_preserves_logic"] = 1.0
    elif has_fix:
        scores["fix_preserves_logic"] = 0.5

    critical_or_high = len(re.findall(r"\b(critical|high)\b", report_lower))
    medium_or_low = len(re.findall(r"\b(medium|low)\b", report_lower))
    total = critical_or_high + medium_or_low
    if total > 0:
        ratio = critical_or_high / total
        if 0.2 <= ratio <= 0.6:
            scores["severity_appropriate"] = 1.0
        elif 0.1 <= ratio <= 0.7:
            scores["severity_appropriate"] = 0.7
        else:
            scores["severity_appropriate"] = 0.3

    code_lines = len(code.splitlines())
    report_lines = len(report.splitlines())
    specificity_ratio = report_lines / max(code_lines, 1)
    if specificity_ratio > 0.5:
        scores["specificity"] = 1.0
    elif specificity_ratio > 0.2:
        scores["specificity"] = 0.7
    else:
        scores["specificity"] = 0.3

    overall = sum(scores.values()) / len(scores) if scores else 0.0
    return {"overall": round(overall, 2), "dimensions": scores}
