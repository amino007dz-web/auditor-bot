import re

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

_has_detector = False
_detector = None
try:
    import bug_detector as _detector
    _has_detector = True
except ImportError:
    pass

_has_grep = False
_grep = None
try:
    import grep_arsenal as _grep
    _has_grep = True
except ImportError:
    pass

_has_mcp = False
_mcp = None
try:
    import mcp_integration as _mcp
    _has_mcp = True
except ImportError:
    pass

_has_ai_tools = False
_ai_tools = None
try:
    import ai_tools as _ai_tools
    _has_ai_tools = True
except ImportError:
    pass

_has_zksync = False
_zksync = None
try:
    import zksync_detector as _zksync
    _has_zksync = True
except ImportError:
    pass

_has_gate = False
_gate = None
try:
    import gate_validator as _gate
    _has_gate = True
except ImportError:
    pass

_has_external = False
try:
    from external_analyzers import run_external_analyzers, findings_to_text
    _has_external = True
except ImportError:
    pass

_has_sbom = False
try:
    from sbom import analyze_sbom, format_sbom_text
    _has_sbom = True
except ImportError:
    pass

_has_pattern_learner = False
_learned_classes = None
try:
    from agents.pattern_learner import get_learned_bug_classes, patterns_text as _learned_text
    _has_pattern_learner = True
except ImportError:
    pass

_has_ast_detector = False
try:
    from agents.ast_detector import analyze_ast as _run_ast_analysis
    _has_ast_detector = True
except ImportError:
    pass


def _run_detector(code: str) -> str:
    if not _has_detector:
        return ""
    detections = _detector.get_summary(code)
    if not detections:
        return ""
    parts = ["### Pre-Scan: Bug Classes (grep-based)"]
    for d in detections:
        sev = d.get("severity_hint", "?")
        cls_name = d.get("name", d.get("class", "?"))
        count = d.get("match_count", 0)
        parts.append(f"- [{sev}] {cls_name}: {count} pattern(s)")
    logger.info(f"Pre-scan bug detector: {len(detections)} classes")
    return "\n".join(parts)


def _run_grep(code: str) -> str:
    if not _has_grep:
        return ""
    grep_summary = _grep.get_summary(code)
    if not grep_summary:
        return ""
    parts = ["### Pre-Scan: Grep Arsenal"]
    for s in grep_summary:
        tier = s["tier"]
        parts.append(f"- [{tier}] {s['name']}: {s['match_count']} match(es)")
        for rf in s["red_flags"][:2]:
            parts.append(f"  ! {rf}")
    logger.info(f"Pre-scan grep arsenal: {len(grep_summary)} blocks")
    return "\n".join(parts)


def _run_mcp(code: str) -> str:
    if not _has_mcp:
        return ""
    mcp_result = _mcp.analyze_contract(code, analyzers=["swc", "defi"])
    if not mcp_result.get("findings"):
        return ""
    parts = ["### Pre-Scan: MCP (SWC + DeFi)"]
    for f in mcp_result["findings"][:8]:
        fid = f.get("id", f.get("name", "?"))
        sev = f.get("severity", "?")
        parts.append(f"- [{sev}] {fid}")
    logger.info(f"Pre-scan MCP: {mcp_result['total']} findings")
    return "\n".join(parts)


def _run_ai_tools(code: str) -> str:
    if not _has_ai_tools:
        return ""
    parts = []
    ai_check = _ai_tools.detect_ai_generated(code)
    if ai_check.get("ai_likely"):
        parts.append("### Pre-Scan: AI-Generated Code Detected — extra scrutiny recommended")
    ai_vulns = _ai_tools.check_ai_vulnerabilities(code)
    if ai_vulns:
        vparts = ["### Pre-Scan: AI-Specific Vulnerabilities"]
        for v in ai_vulns:
            vparts.append(f"- [{v['severity']}] {v['name']}")
        parts.append("\n".join(vparts))
    return "\n\n".join(parts)


def _run_zksync(code: str) -> str:
    if not _has_zksync:
        return ""
    zk_result = _zksync.check_vulnerable_patterns(code)
    if not zk_result.get("findings"):
        return ""
    parts = ["### Pre-Scan: ZKsync Era Attack Vectors"]
    for f in zk_result["findings"][:8]:
        sev = f.get("severity", "?")
        name = f.get("name", f.get("pattern", "?"))
        parts.append(f"- [{sev}] {name}")
    logger.info(f"Pre-scan ZKsync: {len(zk_result['findings'])} findings")
    return "\n".join(parts)


def _run_external(code: str) -> str:
    if not _has_external:
        return ""
    ext_findings = run_external_analyzers(code)
    if not ext_findings:
        return ""
    text = findings_to_text(ext_findings, max_per_tool=8)
    logger.info(f"Pre-scan external analyzers: {len(ext_findings)} findings")
    return text


def _run_sbom(code: str) -> str:
    if not _has_sbom:
        return ""
    sbom_result = analyze_sbom(code)
    text = format_sbom_text(sbom_result)
    if not text:
        return ""
    logger.info(f"Pre-scan SBOM: {len(sbom_result.dependencies)} dependencies")
    return text


def _run_learned(code: str) -> str:
    if not _has_pattern_learner:
        return ""
    return _learned_text()


def _run_pragma_warning(code: str) -> str:
    warnings = []
    for match in re.finditer(r'pragma\s+solidity\s+([\d.]+)', code, re.IGNORECASE):
        version = match.group(1)
        if version.startswith(("0.4.", "0.5.", "0.6.")):
            warnings.append(f"- [CRITICAL] Outdated Solidity version {version}: This version is no longer supported and contains known vulnerabilities. Upgrade to >=0.8.0 immediately.")
    if re.search(r'pragma\s+abicoder\s+v1', code, re.IGNORECASE):
        warnings.append("- [CRITICAL] `pragma abicoder v1` is deprecated and may cause issues. Use `pragma abicoder v2` or remove it.")
    if not warnings:
        return ""
    return "### ⚠️ Pragma Warning\n" + "\n".join(warnings)


def _register_learned_classes():
    """Inject learned patterns into bug_detector's _BUG_CLASSES at runtime."""
    if not _has_detector or not _has_pattern_learner:
        return
    global _learned_classes
    if _learned_classes is not None:
        return  # already registered
    _learned_classes = get_learned_bug_classes()
    if not _learned_classes:
        return
    added = 0
    for key, cls in _learned_classes.items():
        if key not in _detector._BUG_CLASSES:
            _detector._BUG_CLASSES[key] = cls
            _detector._BUG_CLASS_ORDER.append(key)
            added += 1
    if added:
        logger.info(f"Registered {added} learned pattern(s) into bug_detector")


_SCAN_TASKS = [
    ("bug_detector", lambda c: _run_detector(c)),
    ("grep_arsenal", lambda c: _run_grep(c)),
    ("mcp", lambda c: _run_mcp(c)),
    ("ai_tools", lambda c: _run_ai_tools(c)),
    ("zksync", lambda c: _run_zksync(c)),
    ("external", lambda c: _run_external(c)),
    ("sbom", lambda c: _run_sbom(c)),
    ("learned", lambda c: _run_learned(c)),
    ("ast_detector", lambda c: _run_ast_analysis(c) if _has_ast_detector else ""),
    ("pragma_warning", lambda c: _run_pragma_warning(c)),
]


def run_pre_scan(code: str) -> str:
    """Run all pre-scan modules in parallel and return concatenated context string."""
    _register_learned_classes()
    parts = []
    with ThreadPoolExecutor(max_workers=7) as pool:
        future_map = {pool.submit(fn, code): name for name, fn in _SCAN_TASKS}
        for future in as_completed(future_map):
            name = future_map[future]
            try:
                result = future.result()
                if result:
                    parts.append(result)
            except Exception as e:
                logger.debug(f"Pre-scan {name} failed: {e}")

    return "\n\n".join(parts) + "\n\n" if parts else ""
