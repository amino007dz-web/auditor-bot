import html
import os
import re
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import List, Dict, Optional, Callable

from cli_display import console, HAS_RICH

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

TYPE_SIZES = {
    "uint8": 1, "uint16": 2, "uint24": 3, "uint32": 4,
    "uint40": 5, "uint48": 6, "uint56": 7, "uint64": 8,
    "uint72": 9, "uint80": 10, "uint88": 11, "uint96": 12,
    "uint104": 13, "uint112": 14, "uint120": 15, "uint128": 16,
    "uint136": 17, "uint144": 18, "uint152": 19, "uint160": 20,
    "uint168": 21, "uint176": 22, "uint184": 23, "uint192": 24,
    "uint200": 25, "uint208": 26, "uint216": 27, "uint224": 28,
    "uint232": 29, "uint240": 30, "uint248": 31, "uint256": 32,
    "int8": 1, "int16": 2, "int24": 3, "int32": 4,
    "int40": 5, "int48": 6, "int56": 7, "int64": 8,
    "int72": 9, "int80": 10, "int88": 11, "int96": 12,
    "int104": 13, "int112": 14, "int120": 15, "int128": 16,
    "int136": 17, "int144": 18, "int152": 19, "int160": 20,
    "int168": 21, "int176": 22, "int184": 23, "int192": 24,
    "int200": 25, "int208": 26, "int216": 27, "int224": 28,
    "int232": 29, "int240": 30, "int248": 31, "int256": 32,
    "address": 20, "bool": 1,
    "bytes1": 1, "bytes2": 2, "bytes3": 3, "bytes4": 4,
    "bytes8": 8, "bytes16": 16, "bytes32": 32,
}


@dataclass
class Finding:
    agent_name: str
    severity: str  # Critical/High/Medium/Low/Info
    category: str
    file: str
    function_name: str
    description: str
    code_snippet: str = ""
    line: int = 0
    fix: str = ""


@dataclass
class Agent:
    name: str
    severity: str
    category: str
    check: Callable[[str, str], List[Finding]]  # (filename, code) -> List[Finding]
    language: str = ""


class LanguageAnalyzer:
    name: str = "base"
    language: str = "unknown"
    extensions: Optional[List[str]] = None
    agents: Optional[List[Agent]] = None

    def __init__(self):
        self._findings = []
        self._files = {}
        self._agent_results: Dict[str, int] = defaultdict(int)
        self._agent_errors = []
        if self.extensions is None:
            self.extensions = []
        if self.agents is None:
            self.agents = []

    def add_agent(self, agent: Agent):
        agent.language = self.language
        self.agents.append(agent)

    def load_file(self, path: str) -> Optional[str]:
        try:
            with open(path, "r", encoding="utf-8") as f:
                return f.read()
        except Exception:
            return None

    def load_directory(self, path: str) -> Dict[str, str]:
        files = {}
        for root, _, filenames in os.walk(path):
            for f in filenames:
                if any(f.endswith(e) for e in self.extensions):
                    fpath = os.path.join(root, f)
                    code = self.load_file(fpath)
                    if code:
                        files[f] = code
        self._files = files
        return files

    def analyze_file(self, filename: str, code: str) -> List[Finding]:
        findings = []
        n = len(self.agents)
        if HAS_RICH:
            from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                          BarColumn(), console=console) as p:
                task = p.add_task(f"  Agents on {filename}", total=n)
                for agent in self.agents:
                    try:
                        result = agent.check(filename, code)
                        findings.extend(result)
                        self._agent_results[agent.name] += len(result)
                    except Exception as e:
                        self._agent_errors.append(f"{agent.name}: {e}")
                    p.advance(task)
        elif HAS_TQDM:
            for agent in tqdm(self.agents, desc=f"  Agents on {filename}", unit="agent", leave=False):
                try:
                    result = agent.check(filename, code)
                    findings.extend(result)
                    self._agent_results[agent.name] += len(result)
                except Exception as e:
                    self._agent_errors.append(f"{agent.name}: {e}")
        else:
            console.log(f"  Agents on {filename} ({n} agents)")
            for agent in self.agents:
                try:
                    result = agent.check(filename, code)
                    findings.extend(result)
                    self._agent_results[agent.name] += len(result)
                except Exception as e:
                    self._agent_errors.append(f"{agent.name}: {e}")
        return findings

    def analyze_all(self, path: str = "") -> Dict[str, List[Finding]]:
        self._findings = []
        self._agent_results = defaultdict(int)
        self._agent_errors = []

        if path:
            self.load_directory(path)
        elif not self._files:
            return {}

        results: Dict[str, List[Finding]] = {}
        items = list(self._files.items())
        n = len(items)
        if HAS_RICH:
            from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                          BarColumn(), console=console) as p:
                task = p.add_task(f"Analyzing with {self.name}", total=n)
                for fname, code in items:
                    findings = self.analyze_file(fname, code)
                    results[fname] = findings
                    self._findings.extend(findings)
                    p.advance(task)
        elif HAS_TQDM:
            for fname, code in tqdm(items, desc=f"Analyzing with {self.name}", unit="file"):
                findings = self.analyze_file(fname, code)
                results[fname] = findings
                self._findings.extend(findings)
        else:
            console.log(f"Analyzing with {self.name} ({n} files)")
            for fname, code in items:
                findings = self.analyze_file(fname, code)
                results[fname] = findings
                self._findings.extend(findings)
        return results

    def generate_report(self, results: Dict[str, List[Finding]] = None) -> str:
        if results is None:
            results = {f: [] for f in self._files}
            for f in self._files:
                fi = [x for x in self._findings if x.file == f]
                results[f] = fi

        all_findings = self._findings
        by_sev = defaultdict(int)
        by_cat = defaultdict(int)
        by_agent = defaultdict(int)
        for f in all_findings:
            by_sev[f.severity] += 1
            by_cat[f.category] += 1
            by_agent[f.agent_name] += 1

        report = []
        report.append("=" * 70)
        report.append(f"  {self.name.upper()} ANALYSIS — {len(self._files)} files, {len(all_findings)} findings")
        report.append("=" * 70)
        report.append(f"\n{'─' * 50}")
        report.append("FINDINGS BY SEVERITY:")
        report.append(f"{'─' * 50}")
        for s in ["Critical", "High", "Medium", "Low", "Info"]:
            report.append(f"  {s}: {by_sev.get(s, 0)}")
        report.append(f"\n{'─' * 50}")
        report.append("FINDINGS BY CATEGORY:")
        report.append(f"{'─' * 50}")
        for cat, cnt in sorted(by_cat.items(), key=lambda x: -x[1]):
            report.append(f"  {cat}: {cnt}")
        report.append(f"\n{'─' * 50}")
        report.append("FINDINGS BY AGENT:")
        report.append(f"{'─' * 50}")
        for agent, cnt in sorted(by_agent.items(), key=lambda x: -x[1]):
            report.append(f"  {agent}: {cnt}")
        report.append(f"\n{'─' * 50}")
        report.append("DETAILED FINDINGS (Critical + High):")
        report.append(f"{'─' * 50}")
        for f in all_findings:
            if f.severity in ("Critical", "High"):
                report.append(f"\n[{f.severity:8s}] {f.agent_name}")
                report.append(f"  File: {f.file}  Func: {f.function_name}")
                report.append(f"  {f.description}")
                if f.fix:
                    report.append(f"  Fix: {f.fix}")
        if self._agent_errors:
            report.append(f"\n{'─' * 50}")
            report.append("AGENT ERRORS:")
            report.append(f"{'─' * 50}")
            for e in self._agent_errors[:10]:
                report.append(f"  ⚠️ {e}")
        return "\n".join(report)

    def run(self, path: str) -> str:
        t0 = time.time()
        results = self.analyze_all(path)
        report = self.generate_report(results)
        elapsed = time.time() - t0
        report += f"\n\n{'─' * 50}\nCompleted in {elapsed:.1f}s — {len(self._files)} files, {len(self._findings)} total findings"
        return report


def detect_language(path: str) -> Optional[str]:
    if not os.path.isdir(path) and not os.path.isfile(path):
        return None
    if os.path.isfile(path):
        ext = os.path.splitext(path)[1].lower()
        return {"sol": "solidity", ".sol": "solidity",
                ".clsp": "chialisp", ".clib": "chialisp",
                ".move": "move", ".vy": "vyper"}.get(ext)
    exts = set()
    for root, _, files in os.walk(path):
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext:
                exts.add(ext)
    if ".sol" in exts:
        return "solidity"
    if ".clsp" in exts or ".clib" in exts:
        return "chialisp"
    if ".move" in exts:
        return "move"
    if ".vy" in exts:
        return "vyper"
    return None


def findings_to_html(all_findings: List[Finding], analyzer_name: str = "Analysis",
                      files_count: int = 1, agent_errors: list = None) -> str:
    """Generate professional HTML report from findings list"""
    by_sev = defaultdict(int)
    for f in all_findings:
        by_sev[f.severity] += 1

    sev_icons = {"Critical": "🔴", "High": "🟠", "Medium": "🔵", "Low": "🟢", "Info": "ℹ️"}
    sev_order = ["Critical", "High", "Medium", "Low", "Info"]

    rows = []
    for f in all_findings:
        snippet = f.code_snippet[:300] if f.code_snippet else ""
        snippet_html = f"<pre class='snippet'>{_escape(snippet)}</pre>" if snippet else ""
        rows.append(f"""
        <div class="finding finding-{f.severity.lower()}">
          <div class="finding-header">
            <span class="severity severity-{f.severity.lower()}">{sev_icons.get(f.severity, '')} {f.severity}</span>
            <span class="agent-name">{_escape(f.agent_name)}</span>
            <span class="category">{_escape(f.category)}</span>
          </div>
          <div class="finding-body">
<p><strong>File:</strong> {_escape(f.file)}</p>
             <p><strong>Function:</strong> {_escape(f.function_name)}</p>
            <p class="desc">{_escape(f.description)}</p>
            {snippet_html}
            {f'<p class="fix"><strong>Fix:</strong> {_escape(f.fix)}</p>' if f.fix else ''}
          </div>
        </div>""")

    sev_summary = "".join(
        f'<span class="sev-bar sev-{s.lower()}" style="width:{max(by_sev.get(s,0)*5, 2)}%">{sev_icons.get(s,"")} {s}: {by_sev.get(s,0)}</span>'
        for s in sev_order
    )

    errors_html = ""
    if agent_errors:
        errors_html = f"""
        <div class="card">
          <h2>⚠️ Agent Errors ({len(agent_errors)})</h2>
          <ul>{"".join(f'<li>{_escape(e)}</li>' for e in agent_errors[:10])}</ul>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{_escape(analyzer_name)} — Analysis Report</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: #0d1117; color: #c9d1d9; padding: 2rem; max-width: 1100px; margin: 0 auto; }}
h1 {{ color: #58a6ff; font-size: 1.8rem; margin-bottom: 0.5rem; text-align: center; }}
h2 {{ color: #58a6ff; margin: 1.5rem 0 1rem; font-size: 1.3rem; }}
.header {{ text-align: center; padding-bottom: 1.5rem; border-bottom: 2px solid #30363d; margin-bottom: 2rem; }}
.header p {{ color: #8b949e; }}
.summary {{ display: flex; gap: 1rem; justify-content: center; flex-wrap: wrap; margin: 1.5rem 0; }}
.stat-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem 1.5rem; text-align: center; min-width: 100px; }}
.stat-card .num {{ font-size: 2rem; font-weight: bold; display: block; }}
.stat-card .label {{ font-size: 0.8rem; color: #8b949e; }}
.stat-critical .num {{ color: #f85149; }}
.stat-high .num {{ color: #d29922; }}
.stat-medium .num {{ color: #58a6ff; }}
.stat-low .num {{ color: #3fb950; }}
.severity-bars {{ display: flex; gap: 0.25rem; height: 24px; border-radius: 12px; overflow: hidden; margin: 1rem 0; }}
.sev-bar {{ display: flex; align-items: center; justify-content: center; font-size: 0.7rem; font-weight: bold; color: #fff; transition: width 0.3s; min-width: fit-content; padding: 0 0.5rem; }}
.sev-critical {{ background: #da3633; }}
.sev-high {{ background: #d29922; }}
.sev-medium {{ background: #58a6ff; }}
.sev-low {{ background: #238636; }}
.sev-info {{ background: #8b949e; }}
.card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem; }}
.finding {{ border-radius: 8px; margin-bottom: 0.75rem; padding: 1rem; border-left: 4px solid #30363d; background: #0d1117; }}
.finding-critical {{ border-left-color: #da3633; }}
.finding-high {{ border-left-color: #d29922; }}
.finding-medium {{ border-left-color: #58a6ff; }}
.finding-low {{ border-left-color: #238636; }}
.finding-info {{ border-left-color: #8b949e; }}
.finding-header {{ display: flex; gap: 0.75rem; align-items: center; flex-wrap: wrap; margin-bottom: 0.5rem; }}
.severity {{ display: inline-block; padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-weight: 700; color: #fff; }}
.severity-critical {{ background: #da3633; }}
.severity-high {{ background: #d29922; color: #000; }}
.severity-medium {{ background: #58a6ff; }}
.severity-low {{ background: #238636; }}
.severity-info {{ background: #8b949e; }}
.agent-name {{ font-weight: 600; color: #e6edf3; }}
.category {{ font-size: 0.8rem; color: #8b949e; background: #21262d; padding: 0.15rem 0.5rem; border-radius: 4px; }}
.finding-body p {{ margin: 0.25rem 0; font-size: 0.9rem; }}
.finding-body .desc {{ color: #e6edf3; margin: 0.5rem 0; line-height: 1.5; }}
.finding-body .fix {{ color: #3fb950; font-size: 0.85rem; margin-top: 0.5rem; padding: 0.5rem; background: rgba(63, 185, 80, 0.1); border-radius: 4px; }}
.snippet {{ background: #1c2128; border: 1px solid #30363d; border-radius: 4px; padding: 0.75rem; font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 0.8rem; overflow-x: auto; direction: ltr; text-align: left; margin-top: 0.5rem; }}
hr {{ border: none; border-top: 1px solid #30363d; margin: 1.5rem 0; }}
footer {{ text-align: center; color: #8b949e; font-size: 0.8rem; padding: 2rem 0; }}
</style>
</head>
<body>
<div class="header">
  <h1>{_escape(analyzer_name)}</h1>
  <p>{files_count} files | {len(all_findings)} findings</p>
</div>

<div class="summary">
  <div class="stat-card stat-critical"><span class="num">{by_sev.get('Critical',0)}</span><span class="label">Critical</span></div>
  <div class="stat-card stat-high"><span class="num">{by_sev.get('High',0)}</span><span class="label">High</span></div>
  <div class="stat-card stat-medium"><span class="num">{by_sev.get('Medium',0)}</span><span class="label">Medium</span></div>
  <div class="stat-card stat-low"><span class="num">{by_sev.get('Low',0)}</span><span class="label">Low</span></div>
  <div class="stat-card" style="border-color: #58a6ff;"><span class="num" style="color:#58a6ff">{len(all_findings)}</span><span class="label">Total</span></div>
</div>

<div class="severity-bars">{sev_summary}</div>

<div class="card">
  <h2>Details ({len(all_findings)})</h2>
  {"".join(rows) if rows else '<p style="color:#8b949e; text-align:center;">No findings found</p>'}
</div>

{errors_html}

<hr>
<footer>Smart Contract Auditor — Auto-generated report | {time.strftime('%Y-%m-%d %H:%M')}</footer>
</body>
</html>"""
    return html


def _escape(text: str) -> str:
    """Escape text for HTML"""
    if not text:
        return ""
    return html.escape(str(text))


def has_pattern(code: str, pattern: str) -> bool:
    return bool(re.search(pattern, code, re.IGNORECASE))


def count_pattern(code: str, pattern: str) -> int:
    return len(re.findall(pattern, code, re.IGNORECASE))
