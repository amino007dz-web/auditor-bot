r"""
Verify findings from unified_audit using AI to confirm true/false positives.
Outputs a submission-ready report.

Usage:
  py verify_findings.py --dir "..\puzzles-main" --lang chialisp
  py verify_findings.py --dir "..\03_Ample\code" --lang solidity --output verified_report.md
"""
import os
import sys
import json
import time
import argparse
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from analyzers import get_analyzer, detect_language
from agents import call_model_with_fallback, truncate_code
from config import FREE_MODELS
from cli_display import console, banner, severity_text, findings_table_simple, HAS_RICH

if HAS_RICH:
    from rich.table import Table
    from rich import box


CONFIRM_PROMPT = """You are a smart contract security expert. Review the following finding from a static analysis tool and determine if it is a TRUE POSITIVE (real vulnerability) or FALSE POSITIVE (incorrect).

Finding Details:
- Agent: {agent_name}
- Severity: {severity}
- Category: {category}
- File: {file}
- Description: {description}

Code snippet:
```
{code_snippet}
```

Respond with EXACTLY ONE of these verdicts:
TRUE POSITIVE  (if this is a real security issue)
FALSE POSITIVE (if this is incorrect or not exploitable)
NEEDS REVIEW   (if you need more context)

Then on the next line, explain your reasoning in one sentence."""


def load_file_content(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return ""


def extract_context(code: str, snippet_hint: str, max_chars: int = 500) -> str:
    if not snippet_hint or snippet_hint.strip() == "":
        return code[:max_chars]
    pos = code.find(snippet_hint[:50])
    if pos >= 0:
        start = max(0, pos - 100)
        end = min(len(code), pos + max_chars)
        return code[start:end]
    return code[:max_chars]


def verify_finding(finding, file_code: str) -> dict:
    snippet = finding.code_snippet or finding.description[:100]
    context = extract_context(file_code, snippet)

    prompt = CONFIRM_PROMPT.format(
        agent_name=finding.agent_name,
        severity=finding.severity,
        category=finding.category,
        file=finding.file,
        description=finding.description,
        code_snippet=context,
    )

    try:
        response = call_model_with_fallback(prompt, timeout=60)
        response = response.strip()
        if response.startswith("TRUE POSITIVE"):
            return {"verdict": "TRUE POSITIVE", "reason": response.split("\n")[1] if "\n" in response else ""}
        elif response.startswith("FALSE POSITIVE"):
            return {"verdict": "FALSE POSITIVE", "reason": response.split("\n")[1] if "\n" in response else ""}
        elif response.startswith("NEEDS REVIEW"):
            return {"verdict": "NEEDS REVIEW", "reason": response.split("\n")[1] if "\n" in response else ""}
        else:
            return {"verdict": "NEEDS REVIEW", "reason": f"Unexpected response: {response[:100]}"}
    except Exception as e:
        return {"verdict": "NEEDS REVIEW", "reason": f"AI call failed: {e}"}


def main():
    parser = argparse.ArgumentParser(description="Verify static analysis findings with AI")
    parser.add_argument("--dir", help="Project directory")
    parser.add_argument("--file", help="Single file")
    parser.add_argument("--lang", help="Force language")
    parser.add_argument("--output", default="verified_report.md", help="Output file")
    parser.add_argument("--limit", type=int, default=20, help="Max findings to verify (0=all)")
    parser.add_argument("--min-severity", default="Medium",
                        choices=["Critical", "High", "Medium", "Low", "Info"],
                        help="Minimum severity to verify")

    args = parser.parse_args()

    if not args.dir and not args.file:
        console.print("[red]Use --dir or --file[/]")
        return

    path = args.dir or args.file
    if not os.path.exists(path):
        console.print(f"[red]Path not found:[/] {path}")
        return

    lang = args.lang or detect_language(path)
    if not lang:
        console.print("[red]Could not detect language[/]")
        return

    analyzer = get_analyzer(lang)
    if not analyzer:
        console.print(f"[red]No analyzer for {lang}[/]")
        return

    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    min_sev = sev_order.get(args.min_severity, 2)

    console.log(f"Analyzing [bold]{path}[/] ([cyan]{lang}[/])")
    t0 = time.time()

    if args.file:
        code = analyzer.load_file(path)
        if not code:
            console.print("[red]Failed to read file[/]")
            return
        analyzer._files = {os.path.basename(path): code}
        results = analyzer.analyze_all()
    else:
        results = analyzer.analyze_all(path)

    elapsed = time.time() - t0
    findings = analyzer._findings

    sev_counts = defaultdict(int)
    for f in findings:
        sev_counts[f.severity] += 1

    console.print(f"\n[bold]Static analysis:[/] {len(analyzer._files)} files, [yellow]{len(findings)}[/] findings ([dim]{elapsed:.1f}s[/])")
    sev_table = findings_table_simple(dict(sev_counts))
    if sev_table:
        console.print(sev_table)
    else:
        console.print(f"  Critical: {sev_counts.get('Critical', 0)}, High: {sev_counts.get('High', 0)}, "
                      f"Medium: {sev_counts.get('Medium', 0)}, Low: {sev_counts.get('Low', 0)}, "
                      f"Info: {sev_counts.get('Info', 0)}")

    to_verify = [f for f in findings if sev_order.get(f.severity, 99) <= min_sev]
    to_verify.sort(key=lambda x: (sev_order.get(x.severity, 99), x.agent_name))

    limit = args.limit if args.limit > 0 else len(to_verify)
    to_verify = to_verify[:limit]

    if not to_verify:
        console.print("[yellow]No findings to verify at this severity level[/]")
        return

    console.print(f"\n[bold]Verifying {len(to_verify)} findings with AI[/] (limit={limit})...")

    if HAS_RICH:
        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
        progress = Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                            BarColumn(), console=console)
    else:
        progress = None

    verified = []
    iterable = to_verify
    if HAS_RICH:
        with progress:
            task = progress.add_task("Verifying", total=len(to_verify))
            for i, finding in enumerate(iterable, 1):
                file_code = analyzer._files.get(finding.file, "")
                result = verify_finding(finding, file_code)
                verdict = result["verdict"]
                verified.append({"finding": finding, "verdict": verdict, "reason": result["reason"]})
                progress.update(task, advance=1)
                time.sleep(0.5)
    else:
        for i, finding in enumerate(iterable, 1):
            file_code = analyzer._files.get(finding.file, "")
            result = verify_finding(finding, file_code)
            verdict = result["verdict"]
            icon = {"TRUE POSITIVE": "✓", "FALSE POSITIVE": "✗", "NEEDS REVIEW": "?"}[verdict]
            console.print(f"  [{i}/{len(to_verify)}] {icon} {finding.severity:8s} {finding.agent_name[:30]:30s} → [bold]{verdict}[/]")
            verified.append({"finding": finding, "verdict": verdict, "reason": result["reason"]})
            time.sleep(0.5)

    console.print(f"\n[green]Generating verified report:[/] {args.output}")
    generate_verified_report(verified, args.output, analyzer)

    by_verdict = defaultdict(int)
    for v in verified:
        by_verdict[v["verdict"]] += 1
    print(f"\nSummary: {by_verdict.get('TRUE POSITIVE', 0)} TP, "
          f"{by_verdict.get('FALSE POSITIVE', 0)} FP, "
          f"{by_verdict.get('NEEDS REVIEW', 0)} ?")


def generate_verified_report(verified: list, output_path: str, analyzer):
    lines = []
    lines.append("# Verified Security Analysis Report")
    lines.append("")
    lines.append(f"**Project:** Static analysis by `{analyzer.name}` with AI verification")
    lines.append(f"**Files analyzed:** {len(analyzer._files)}")
    lines.append(f"**Total findings:** {len(analyzer._findings)} (AI-verified: {len(verified)})")
    lines.append("")

    by_sev = defaultdict(int)
    for v in verified:
        by_sev[v["finding"].severity] += 1

    lines.append("## Verified Findings by Severity")
    lines.append("")
    for s in ["Critical", "High", "Medium", "Low", "Info"]:
        if by_sev.get(s, 0) > 0:
            lines.append(f"- **{s}**: {by_sev[s]}")
    lines.append("")

    by_v = defaultdict(int)
    for v in verified:
        by_v[v["verdict"]] += 1
    lines.append(f"- **TRUE POSITIVE**: {by_v.get('TRUE POSITIVE', 0)}")
    lines.append(f"- **FALSE POSITIVE**: {by_v.get('FALSE POSITIVE', 0)}")
    lines.append(f"- **NEEDS REVIEW**: {by_v.get('NEEDS REVIEW', 0)}")
    lines.append("")
    lines.append("---")
    lines.append("")

    tp = [v for v in verified if v["verdict"] == "TRUE POSITIVE"]
    if tp:
        lines.append("## Confirmed Vulnerabilities (True Positives)")
        lines.append("")
        for v in tp:
            f = v["finding"]
            lines.append(f"### [{f.severity}] {f.agent_name} — `{f.file}`")
            lines.append("")
            lines.append(f"**Description:** {f.description}")
            if f.function_name:
                lines.append(f"**Function:** `{f.function_name}`")
            if v["reason"]:
                lines.append(f"**AI Reasoning:** {v['reason']}")
            if f.fix:
                lines.append(f"**Recommended Fix:** {f.fix}")
            lines.append("")

    nr = [v for v in verified if v["verdict"] == "NEEDS REVIEW"]
    if nr:
        lines.append("## Needs Manual Review")
        lines.append("")
        for v in nr:
            f = v["finding"]
            lines.append(f"### [{f.severity}] {f.agent_name} — `{f.file}`")
            lines.append(f"**Description:** {f.description}")
            if v["reason"]:
                lines.append(f"**Note:** {v['reason']}")
            lines.append("")

    fp = [v for v in verified if v["verdict"] == "FALSE POSITIVE"]
    if fp:
        lines.append("## False Positives")
        lines.append("")
        for v in fp:
            f = v["finding"]
            lines.append(f"- **[{f.severity}] {f.agent_name}** — `{f.file}`: {v['reason']}")
        lines.append("")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"Report written to {output_path}")


if __name__ == "__main__":
    main()
