"""
CVSS 4.0 Scorer for smart contract vulnerabilities.
Maps severity levels to CVSS 4.0 Base Scores and generates vector strings.
"""
import math
from typing import Dict, Optional, Tuple

# CVSS 4.0 severity bands
SEVERITY_BANDS = {
    "None": (0.0, 0.0),
    "Low": (0.1, 3.9),
    "Medium": (4.0, 6.9),
    "High": (7.0, 8.9),
    "Critical": (9.0, 10.0),
}

# Default CVSS 4.0 vectors by severity
_DEFAULT_VECTORS = {
    "Critical": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "High": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N",
    "Medium": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N",
    "Low": "CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "Info": "CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
}

# CVSS 4.0 metric numerical values (per CVSS 4.0 spec)
_METRIC_VALUES = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.85, "H": 0.44},
    "AT": {"N": 0.85, "P": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
    "UI": {"N": 0.85, "P": 0.62, "A": 0.44},
    "VC": {"H": 0.50, "L": 0.25, "N": 0.00},
    "VI": {"H": 0.50, "L": 0.25, "N": 0.00},
    "VA": {"H": 0.50, "L": 0.25, "N": 0.00},
    "SC": {"H": 0.20, "L": 0.10, "N": 0.00},
    "SI": {"H": 0.20, "L": 0.10, "N": 0.00},
    "SA": {"H": 0.20, "L": 0.10, "N": 0.00},
}

_VULN_CATEGORY_MAP = {
    "reentrancy": ("AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H", "Critical"),
    "oracle manipulation": ("AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L", "High"),
    "flash loan": ("AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L", "High"),
    "access control": ("AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H", "High"),
    "integer overflow": ("AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N", "Medium"),
    "division by zero": ("AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N", "Medium"),
    "signature replay": ("AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L", "Medium"),
    "uninitialized proxy": ("AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H", "Critical"),
    "denial of service": ("AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:H", "Medium"),
    "front running": ("AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N", "Low"),
    "gas griefing": ("AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L", "Low"),
    "logic error": ("AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H", "High"),
    "price manipulation": ("AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L", "High"),
    "sandwich attack": ("AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N", "Low"),
    "permission": ("AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H", "High"),
}


def parse_vector(vector: str) -> Dict[str, str]:
    """Parse a CVSS 4.0 vector string into a dict of metric:value pairs."""
    parts = vector.replace("CVSS:4.0/", "").split("/")
    result = {}
    for part in parts:
        if ":" in part:
            k, v = part.split(":", 1)
            result[k] = v
    return result


def _sub_score(metrics: Dict[str, str], keys) -> float:
    """Compute sub-score = 1 - prod(1 - val) for the given metric keys."""
    prod = 1.0
    for key in keys:
        val = metrics.get(key, "N")
        metric_vals = _METRIC_VALUES.get(key, {})
        prod *= (1.0 - metric_vals.get(val, 0.0))
    return 1.0 - prod


def compute_base_score(metrics: Dict[str, str]) -> float:
    """Compute CVSS 4.0 base score using the standard formula."""
    eq1 = _sub_score(metrics, ["AV", "AC", "AT", "PR", "UI"])
    eq2 = _sub_score(metrics, ["VC", "VI", "VA"])
    eq3 = _sub_score(metrics, ["SC", "SI", "SA"])

    if eq2 <= 0.0 and eq3 <= 0.0:
        return 0.0

    score = 10.0 * eq1 * (1.0 - 0.5 * (1.0 - eq2) * (1.0 - eq3))
    return round(min(10.0, max(0.0, score)), 1)


def severity_from_score(score: float) -> str:
    """Map a CVSS 4.0 score (0-10) back to a severity band."""
    for sev, (lo, hi) in SEVERITY_BANDS.items():
        if lo <= score <= hi:
            return sev
    return "None"


def vector_from_severity(severity: str, category_hint: str = "") -> str:
    """Generate a CVSS 4.0 vector string from severity and optional category."""
    hint = category_hint.lower().strip()
    for key, (vec_part, default_sev) in _VULN_CATEGORY_MAP.items():
        if key in hint:
            full_vec = f"CVSS:4.0/{vec_part}/SC:N/SI:N/SA:N"
            return full_vec

    clean_sev = severity.replace("*", "").replace("`", "").strip()
    for key in _DEFAULT_VECTORS:
        if key.lower() == clean_sev.lower():
            return _DEFAULT_VECTORS[key]
    return _DEFAULT_VECTORS["Medium"]


def score_report(report: str) -> Dict:
    """Extract findings from a report and compute CVSS 4.0 scores for each."""
    import re
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
            raw = s.split(":", 1)[1].strip() if ":" in s else "Medium"
            current["severity"] = raw.replace("*", "").replace("`", "").strip()
        elif s.startswith("- **Description**") and current:
            current["description"] = s.split(":", 1)[1].strip() if ":" in s else ""

    if current and current.get("name"):
        findings.append(current)

    scored = []
    for f in findings:
        name = f.get("name", "?")
        sev = f.get("severity", "Medium")
        desc = f.get("description", "")
        vector = vector_from_severity(sev, desc)
        metrics = parse_vector(vector)
        score = compute_base_score(metrics)
        severity_band = severity_from_score(score)
        scored.append({
            "name": name,
            "severity": sev,
            "cvss_vector": vector,
            "cvss_score": score,
            "cvss_severity": severity_band,
        })

    overall_score = 0.0
    if scored:
        overall_score = max(s["cvss_score"] for s in scored)
    overall_severity = severity_from_score(overall_score)

    return {
        "findings": scored,
        "overall_score": overall_score,
        "overall_severity": overall_severity,
        "total_findings": len(scored),
    }


def compute_cvss(attack_vector: str = "N", complexity: str = "L",
                 privileges: str = "N", user_interaction: str = "N",
                 confidentiality: str = "H", integrity: str = "H",
                 availability: str = "H") -> Tuple[float, str, str]:
    """Compute CVSS 4.0 from individual metric values. Returns (score, severity, vector)."""
    metrics = {
        "AV": attack_vector[0].upper() if attack_vector else "N",
        "AC": complexity[0].upper() if complexity else "L",
        "AT": "N",
        "PR": privileges[0].upper() if privileges else "N",
        "UI": user_interaction[0].upper() if user_interaction else "N",
        "VC": confidentiality[0].upper() if confidentiality else "H",
        "VI": integrity[0].upper() if integrity else "H",
        "VA": availability[0].upper() if availability else "H",
        "SC": "N",
        "SI": "N",
        "SA": "N",
    }
    score = compute_base_score(metrics)
    sev = severity_from_score(score)
    vector = f"CVSS:4.0/AV:{metrics['AV']}/AC:{metrics['AC']}/AT:N/PR:{metrics['PR']}/UI:{metrics['UI']}/VC:{metrics['VC']}/VI:{metrics['VI']}/VA:{metrics['VA']}/SC:N/SI:N/SA:N"
    return score, sev, vector


def cvss_explanation(score: float, severity: str, vector: str) -> str:
    """Generate a human-readable explanation of the CVSS score."""
    metrics = parse_vector(vector)
    parts = [
        f"**CVSS 4.0 Score**: {score}/10 ({severity})",
        f"**Vector**: `{vector}`",
        "",
        "### Metric Breakdown",
        f"- **Attack Vector (AV)**: {_metric_label(metrics.get('AV','N'), 'AV')}",
        f"- **Attack Complexity (AC)**: {_metric_label(metrics.get('AC','L'), 'AC')}",
        f"- **Privileges Required (PR)**: {_metric_label(metrics.get('PR','N'), 'PR')}",
        f"- **User Interaction (UI)**: {_metric_label(metrics.get('UI','N'), 'UI')}",
        f"- **Confidentiality (VC)**: {_metric_label(metrics.get('VC','H'), 'VC')}",
        f"- **Integrity (VI)**: {_metric_label(metrics.get('VI','H'), 'VI')}",
        f"- **Availability (VA)**: {_metric_label(metrics.get('VA','H'), 'VA')}",
    ]
    return "\n".join(parts)


def _metric_label(val: str, metric: str) -> str:
    labels = {
        "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
        "AC": {"L": "Low", "H": "High"},
        "AT": {"N": "None", "P": "Present"},
        "PR": {"N": "None", "L": "Low", "H": "High"},
        "UI": {"N": "None", "P": "Passive", "A": "Active"},
        "VC": {"H": "High", "L": "Low", "N": "None"},
        "VI": {"H": "High", "L": "Low", "N": "None"},
        "VA": {"H": "High", "L": "Low", "N": "None"},
        "SC": {"H": "High", "L": "Low", "N": "None"},
        "SI": {"H": "High", "L": "Low", "N": "None"},
        "SA": {"H": "High", "L": "Low", "N": "None"},
    }
    return labels.get(metric, {}).get(val, val)
