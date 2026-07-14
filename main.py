import argparse
import json
import logging
import os
import sys
import time
from typing import Dict, Optional, Callable

from audit_service import AuditService
from agents import cache_stats
from multiaudit import DEFAULT_TEAM
from github_loader import download_contracts
from hierarchical_audit import (
    run_hierarchical_audit_interactive,
)
from static_analysis import (
    generate_combined_report_interactive,
)
from config import PROGRESS_FILE, KB_ENABLED, KB_DB_PATH
from orchestrator import dispatch_analysis
from bytecode_analyzer import analyze_bytecode, analyze_contract_from_explorer
from agentic_auditor import analyze_project_agentic
from webhook_notifier import send_report
from cli_display import console, banner as show_banner, prompt_input, confirm_action, HAS_RICH

if HAS_RICH:
    from rich.table import Table
    from rich import box
    from rich.markdown import Markdown

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

REPORT_DIR: str = AuditService.REPORT_DIR
svc: AuditService = AuditService()


def setup_output() -> None:
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding='utf-8')
        except Exception:
            pass


def ensure_report_dir() -> None:
    os.makedirs(REPORT_DIR, exist_ok=True)


def save_report_txt(filename: str, content: str) -> str:
    return svc.save_report(filename, content)


def load_local_contract(path: str) -> Optional[str]:
    code = svc.load_code(path)
    if code is None:
        console.log(f"[red]File not found:[/] {path}")
    elif not path.endswith(".sol"):
        console.log("[yellow]File is not .sol, will attempt to read anyway.[/]")
    return code


DEMO_CODE = """
contract Bank {
    mapping(address => uint) public balances;
    function withdraw(uint _amount) public {
        require(balances[msg.sender] >= _amount);
        (bool success,) = msg.sender.call{value:_amount}("");
        balances[msg.sender] -= _amount;
    }
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
}
"""

# ─── Interactive mode handlers ───

def _handle_demo() -> None:
    console.rule("[bold cyan]Demo Analysis[/]")
    console.print(DEMO_CODE.replace("contract Bank", "[bold]contract Bank[/]"), markup=True)
    prompt_input("Press [bold]Enter[/] to start analysis")
    report = svc.run_audit(DEMO_CODE)
    path = svc.save_report("audit_report.txt", report)
    console.log(f"[green]Report saved:[/] {path}")
    console.print(Markdown(report) if HAS_RICH else report)
    svc.collect_feedback(DEMO_CODE, "demo", report)
    prompt_input("Press [dim]Enter[/] to continue")


def _github_flow() -> tuple:
    repo_url = prompt_input("Enter [bold]GitHub repo URL[/]")
    if not repo_url:
        console.log("[red]URL cannot be empty[/]")
        return None, None
    token: Optional[str] = None
    if confirm_action("Do you have a [bold]GitHub Token[/]?", default=False):
        token = prompt_input("Enter GitHub Token")
    console.log("[bold]Downloading contracts...[/]")
    contracts = download_contracts(repo_url, token)
    if not contracts:
        return None, None
    if HAS_RICH:
        t = Table(title=f"Contracts ({len(contracts)})", box=box.SIMPLE)
        t.add_column("#", style="dim", width=3)
        t.add_column("Name", style="bold")
        for i, c in enumerate(contracts, 1):
            t.add_row(str(i), c['name'])
        console.print(t)
    else:
        console.print(f"Contracts ({len(contracts)}):")
        for i, c in enumerate(contracts, 1):
            console.print(f"  {i}. {c['name']}")
    if len(contracts) == 1:
        idx = 0
    else:
        choice_idx = prompt_input(f"Choose contract (1-[cyan]{len(contracts)}[/]), or [bold]0[/] for all")
        if choice_idx == "0":
            for contract in contracts:
                console.rule(f"[cyan]{contract['name']}[/]")
                report = svc.run_audit(contract['code'])
                safe_name = contract['name'].replace('/', '_').replace('.sol', '')
                path = svc.save_report(f"audit_{safe_name}.txt", report)
                console.log(f"[green]Report saved:[/] {path}")
            console.log("[green]All contracts analyzed.[/]")
            return "__ALL_DONE__", None
        else:
            try:
                idx = int(choice_idx) - 1
                if idx < 0 or idx >= len(contracts):
                    console.log("[red]Invalid number[/]")
                    return None, None
            except ValueError:
                console.log("[red]Invalid input[/]")
                return None, None
    code = contracts[idx]['code']
    label = contracts[idx]['name'].replace('/', '_').replace('.sol', '')
    console.rule(f"[cyan]Analyzing: {contracts[idx]['name']}[/]")
    preview = code[:500] + "..." if len(code) > 500 else code
    console.print(preview)
    return code, label


def _handle_github_audit() -> None:
    code, label = _github_flow()
    if code is None and label is None:
        return
    if code == "__ALL_DONE__":
        prompt_input("Press [dim]Enter[/] to continue")
        return
    prompt_input("Press [bold]Enter[/] to start analysis")
    report = svc.run_audit(code)
    path = svc.save_report(f"audit_{label}.txt", report)
    console.log(f"[green]Report saved:[/] {path}")
    console.print(Markdown(report) if HAS_RICH else report)
    prompt_input("Press [dim]Enter[/] to continue")


def _handle_local_file() -> None:
    path = prompt_input("Enter full path to [bold].sol[/] file")
    if not path:
        console.log("[red]Path cannot be empty[/]")
        return
    code = load_local_contract(path)
    if code is None:
        return
    console.print(f"\n[bold]Loaded file[/] ({len(code)} chars)")
    prompt_input("Press [bold]Enter[/] to start analysis")
    report = svc.run_audit(code)
    name = os.path.basename(path).replace('.sol', '')
    rpath = svc.save_report(f"audit_{name}.txt", report)
    console.log(f"[green]Report saved:[/] {rpath}")
    console.print(Markdown(report) if HAS_RICH else report)
    svc.collect_feedback(code, name, report)
    prompt_input("Press [dim]Enter[/] to continue")


def _handle_multi_audit() -> None:
    code, label = _github_flow()
    if code is None:
        return
    prompt_input("Press [bold]Enter[/] to start multi-model analysis")
    team_str = prompt_input(f"Model names (comma-separated) or Enter for default", default=', '.join(DEFAULT_TEAM))
    team = [t.strip() for t in team_str.split(",")] if team_str else None
    report = svc.run_multi(code, team)
    rpath = svc.save_report(f"multi_audit_{label}.txt", report)
    console.log(f"[green]Report saved:[/] {rpath}")
    console.print(Markdown(report) if HAS_RICH else report)
    svc.collect_feedback(code, label, report)
    prompt_input("Press [dim]Enter[/] to continue")


def _handle_hierarchical() -> None:
    code, label = _github_flow()
    if code is None:
        return
    focus = prompt_input("Analyze specific contract only? (Enter for all)")
    prompt_input("Press [bold]Enter[/] to start hierarchical analysis")
    report = run_hierarchical_audit_interactive(code, focus)
    rpath = svc.save_report(f"hierarchical_{label}.txt", report)
    console.log(f"[green]Report saved:[/] {rpath}")
    console.print(Markdown(report) if HAS_RICH else report)
    svc.collect_feedback(code, label, report)
    prompt_input("Press [dim]Enter[/] to continue")


def _handle_opcodes() -> None:
    fpath = prompt_input("Enter full path to [bold].sol[/] file")
    if not fpath:
        console.log("[red]Path cannot be empty[/]")
        return
    code = load_local_contract(fpath)
    if code is None:
        return
    console.rule(f"[cyan]Opcodes: {os.path.basename(fpath)}[/]")
    report = svc.analyze_opcodes(code)
    console.print(report)
    rpath = svc.save_report(f"opcodes_{os.path.basename(fpath).replace('.sol', '')}.txt", report)
    console.log(f"[green]Report saved:[/] {rpath}")
    prompt_input("Press [dim]Enter[/] to continue")


def _resume_progress() -> None:
    if not os.path.exists(PROGRESS_FILE):
        console.log("[red]No saved progress found.[/]")
        prompt_input("Press [dim]Enter[/] to continue")
        return
    try:
        with open(PROGRESS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        console.log(f"[red]Failed to read progress file:[/] {e}")
        prompt_input("Press [dim]Enter[/] to continue")
        return
    keys = sorted(data.keys())
    if HAS_RICH:
        t = Table(title=f"Saved progress ({len(data)} checkpoints)", box=box.SIMPLE)
        t.add_column("#", style="dim", width=3)
        t.add_column("Key", style="bold")
        t.add_column("Stage", width=10)
        t.add_column("Time", width=10)
        for i, key in enumerate(keys, 1):
            entry = data[key]
            t.add_row(str(i), key, entry.get("stage", "?"), time.strftime('%H:%M:%S', time.localtime(entry.get("timestamp", 0))))
        console.print(t)
    else:
        console.print(f"\nSaved progress ({len(data)} checkpoints):")
        for i, key in enumerate(keys, 1):
            entry = data[key]
            console.print(f"  {i}. {key} (stage: {entry.get('stage', '?')})")
    choice = prompt_input("Choose checkpoint number (or Enter to exit)")
    if not choice:
        return
    try:
        idx = int(choice) - 1
        if idx < 0 or idx >= len(keys):
            console.log("[red]Invalid number[/]")
            return
        key = keys[idx]
        entry = data[key]
        console.rule(f"[bold]Stage: {entry.get('stage', '?')}[/]")
        content = entry.get("data", {})
        if isinstance(content, dict):
            for k, v in content.items():
                console.print(f"\n[bold]--- {k} ---[/]")
                console.print(str(v)[:300])
        else:
            console.print(str(content)[:1000])
    except (ValueError, IndexError):
        console.log("[red]Invalid input[/]")
    prompt_input("Press [dim]Enter[/] to continue")


def _load_single_sol_file() -> Optional[tuple]:
    path = prompt_input("Enter full path to [bold].sol[/] file")
    if not path:
        console.log("[red]Path cannot be empty[/]")
        return None
    code = load_local_contract(path)
    if code is None:
        return None
    name = os.path.basename(path).replace('.sol', '')
    return (code, name)


def _handle_combined_report() -> None:
    result = _load_single_sol_file()
    if result is None:
        return
    code, name = result
    console.rule("[bold cyan]Combined Report[/]")
    report = generate_combined_report_interactive(code)
    console.print(report[:2000])
    rpath = svc.save_report(f"combined_{name}.txt", report)
    console.log(f"[green]Full report ({len(report)} chars) saved:[/] {rpath}")
    prompt_input("Press [dim]Enter[/] to continue")


def _handle_storage() -> None:
    result = _load_single_sol_file()
    if result is None:
        return
    code, name = result
    console.rule("[bold cyan]Storage Analysis[/]")
    report = svc.analyze_storage(code)
    console.print(report)
    rpath = svc.save_report(f"storage_{name}.txt", report)
    console.log(f"[green]Report saved:[/] {rpath}")
    prompt_input("Press [dim]Enter[/] to continue")


def _handle_inheritance() -> None:
    result = _load_single_sol_file()
    if result is None:
        return
    code, name = result
    console.rule("[bold cyan]Inheritance Analysis[/]")
    report = svc.analyze_inheritance(code)
    console.print(report)
    rpath = svc.save_report(f"inheritance_{name}.txt", report)
    console.log(f"[green]Report saved:[/] {rpath}")
    prompt_input("Press [dim]Enter[/] to continue")


def _handle_json_output() -> None:
    result = _load_single_sol_file()
    if result is None:
        return
    code, name = result
    console.rule("[bold cyan]JSON Analysis[/]")
    report = svc.analyze_combined(code, name)
    data = svc.json_output(report, "combined", name)
    console.print("\n[bold]JSON Output:[/]")
    console.print(json.dumps(data, ensure_ascii=False, indent=2))
    prompt_input("Press [dim]Enter[/] to continue")


def _handle_cache_stats() -> None:
    stats = svc.cache_stats()
    if HAS_RICH:
        t = Table(title="Cache Stats", box=box.SIMPLE)
        t.add_column("Metric", style="bold")
        t.add_column("Value", justify="right")
        t.add_row("Enabled", "✅ Yes" if stats.get('enabled') else "❌ No")
        if stats.get('enabled'):
            t.add_row("Entries", str(stats.get('entries', 0)))
            t.add_row("Total Hits", str(stats.get('total_hits', 0)))
        console.print(t)
    else:
        console.print(f"\nCache stats:")
        console.print(f"   Enabled: {'Yes' if stats.get('enabled') else 'No'}")
        if stats.get('enabled'):
            console.print(f"   Entries: {stats.get('entries', 0)}")
            console.print(f"   Total hits: {stats.get('total_hits', 0)}")
    console.print()
    prompt_input("Press [dim]Enter[/] to continue")


def _handle_kb_stats() -> None:
    stats = svc.kb_stats()
    if not stats.get("enabled", True):
        console.print("\n[yellow]Knowledge Base is disabled (kb_enabled: false)[/]")
        prompt_input("Press [dim]Enter[/] to continue")
        return
    if HAS_RICH:
        t = Table(title="📚 Knowledge Base Stats", box=box.SIMPLE)
        t.add_column("Metric", style="bold")
        t.add_column("Value", justify="right")
        t.add_row("Patterns stored", str(stats.get('patterns', 0)))
        t.add_row("False positives", str(stats.get('false_positives', 0)))
        t.add_row("Audit sessions", str(stats.get('sessions', 0)))
        t.add_row("User feedback", str(stats.get('feedback', 0)))
        t.add_row("Models tracked", str(stats.get('models_tracked', 0)))
        console.print(t)
    else:
        console.print(f"\n📚 Knowledge Base Stats:")
        console.print(f"   Patterns stored:      {stats.get('patterns', 0)}")
        console.print(f"   False positives:      {stats.get('false_positives', 0)}")
        console.print(f"   Audit sessions:       {stats.get('sessions', 0)}")
        console.print(f"   User feedback:        {stats.get('feedback', 0)}")
        console.print(f"   Models tracked:       {stats.get('models_tracked', 0)}")
    top = stats.get('top_patterns', [])
    if top:
        console.print("\n[bold]Top patterns:[/]")
        for t in top:
            console.print(f"   • {t['name']} (score: {t['score']})")
    rankings = stats.get('rankings', [])
    if rankings:
        console.print("\n[bold]Model rankings:[/]")
        for r in rankings:
            acc = r.get('avg_accuracy', 0) * 100
            console.print(f"   • {r['model_name']}: {acc:.0f}% ({r.get('total_tp',0)} TP / {r.get('total_fp',0)} FP)")
    console.print()
    prompt_input("Press [dim]Enter[/] to continue")


def _collect_feedback(code: str, label: str = "", report: str = "") -> None:
    if not KB_ENABLED:
        return
    sid, _ = svc.collect_feedback(code, label, report)
    if sid <= 0:
        return
    try:
        from knowledge_base import KnowledgeBase
        kb = KnowledgeBase(KB_DB_PATH)
        console.rule("[bold yellow]Report Quality Assessment[/]")
        rating = prompt_input("Rate the report from [bold]1[/] to [bold]5[/] (Enter to skip)")
        if rating and rating.isdigit():
            kb.update_session(sid, user_rating=int(rating))
        has_fp = prompt_input("Are there false positive classifications? (comma-separated names / Enter to skip)")
        if has_fp:
            for fp_name in has_fp.split(","):
                fp_name = fp_name.strip()
                if fp_name:
                    kb.add_feedback(sid, fp_name, is_fp=True)
                    console.log(f"[yellow]KB:[/] {fp_name} recorded as False Positive")
        kb.close()
    except Exception as e:
        logger.debug(f"Feedback collection skipped: {e}")


def _handle_critique() -> None:
    result = _load_single_sol_file()
    if result is None:
        return
    code, name = result
    console.rule("[bold cyan]Initial Analysis + Critique[/]")
    initial, critique = svc.run_critique(code)
    rpath = svc.save_report(f"critique_{name}.txt", critique)
    console.log(f"[green]Report saved:[/] {rpath}")
    console.print(Markdown(critique) if HAS_RICH else critique)
    svc.collect_feedback(code, name, critique)
    prompt_input("Press [dim]Enter[/] to continue")


def _handle_init_config() -> None:
    from config import DEFAULT_CONFIG
    cpath = os.path.join(os.path.dirname(__file__), 'config.json')
    if os.path.exists(cpath) and not confirm_action("[yellow]config.json exists. Overwrite?[/]", default=False):
        console.print("[yellow]Cancelled.[/]")
        return
    with open(cpath, 'w', encoding='utf-8') as f:
        json.dump(DEFAULT_CONFIG, f, ensure_ascii=False, indent=2)
    console.log(f"[green]Created[/] {cpath}")
    prompt_input("Press [dim]Enter[/] to continue")


def _handle_parallel() -> None:
    result = _load_single_sol_file()
    if result is None:
        return
    code, name = result
    n_workers = prompt_input("Number of parallel models (Enter for [bold]3[/])", default="3")
    try:
        n_workers = int(n_workers)
    except ValueError:
        n_workers = 3
    console.print(f"[bold]Running {n_workers} parallel analyzers...[/]")
    combined, _ = svc.run_parallel(code, n_workers)
    rpath = svc.save_report(f"parallel_{name}.txt", combined)
    console.log(f"[green]Report saved:[/] {rpath}")
    console.print(combined[:2000])
    svc.collect_feedback(code, name, combined)
    prompt_input("Press [dim]Enter[/] to continue")


def _handle_diff_audit() -> None:
    console.rule("[bold cyan]Diff Audit[/]")
    path1 = prompt_input("Full path for first version (v1)")
    if not path1:
        return
    path2 = prompt_input("Full path for second version (v2)")
    if not path2:
        return
    v1 = svc.load_code(path1)
    v2 = svc.load_code(path2)
    if v1 is None or v2 is None:
        console.log("[red]Failed to read one of the files[/]")
        return
    console.print(f"Loaded v1: [bold]{len(v1):,}[/] chars, v2: [bold]{len(v2):,}[/] chars")
    diff_summary = svc.compute_diff(v1, v2)
    console.print(f"\n[bold]Diff summary:[/]\n{diff_summary}")
    prompt_input("Press [bold]Enter[/] to start diff analysis")
    report = svc.run_diff_audit(v1, v2)
    name1 = os.path.splitext(os.path.basename(path1))[0]
    name2 = os.path.splitext(os.path.basename(path2))[0]
    rpath = svc.save_report(f"diff_{name1}_vs_{name2}.txt", report)
    console.log(f"[green]Report saved:[/] {rpath}")
    console.print(Markdown(report) if HAS_RICH else report)
    prompt_input("Press [dim]Enter[/] to continue")


def _handle_move_audit() -> None:
    fpath = prompt_input("Enter path to [bold]Move (.move)[/] file or directory")
    if not fpath:
        console.log("[red]Path cannot be empty[/]")
        return
    if not os.path.exists(fpath):
        console.log(f"[red]Path not found:[/] {fpath}")
        return

    from move_audit import move_hierarchical_audit

    combined = ""
    if os.path.isfile(fpath):
        with open(fpath, "r", encoding="utf-8") as f:
            combined = f.read()
        name = os.path.basename(fpath).replace('.move', '')
    else:
        for root, _, files in os.walk(fpath):
            for f in files:
                if f.endswith('.move'):
                    with open(os.path.join(root, f), encoding="utf-8") as fh:
                        combined += f"\n\n// File: {f}\n{fh.read()}"
        name = os.path.basename(fpath)

    console.print(f"\nLoaded [bold]{len(combined):,}[/] chars from [cyan]{fpath}[/]")
    prompt_input("Press [bold]Enter[/] to start Move/Sui analysis")
    report = move_hierarchical_audit(combined)
    rpath = svc.save_report(f"move_audit_{name}.txt", report)
    console.print(report[:2000])
    console.log(f"[green]Report saved:[/] {rpath} ({len(report):,} chars)")
    prompt_input("Press [dim]Enter[/] to continue")


def _handle_bytecode() -> None:
    console.rule("[bold cyan]Bytecode Analysis[/]")
    source = prompt_input("Enter bytecode (hex), address (0x...), or file path")
    if not source:
        return
    findings = []
    if source.startswith("0x") and len(source) > 42:
        findings = analyze_bytecode(source, "manual")
    elif source.startswith("0x") and len(source) == 42:
        console.log("[bold]Fetching from Etherscan...[/]")
        findings = analyze_contract_from_explorer(source)
    else:
        try:
            with open(source, "r", encoding="utf-8") as f:
                data = f.read()
            if data.startswith("0x"):
                findings = analyze_bytecode(data, os.path.basename(source))
            else:
                console.log("[red]File does not contain hex bytecode[/]")
                return
        except FileNotFoundError:
            console.log(f"[red]File not found:[/] {source}")
            return
    if HAS_RICH:
        from rich.table import Table
        from rich import box
        t = Table(title=f"Bytecode Findings ({len(findings)})", box=box.SIMPLE)
        t.add_column("Severity", style="bold")
        t.add_column("Agent", style="cyan")
        t.add_column("File")
        t.add_column("Description")
    else:
        console.print(f"\nBytecode Findings ({len(findings)}):")
    for f in findings:
        if HAS_RICH:
            t.add_row(f.severity, f.agent_name, f.file, f.description[:80])
        else:
            console.print(f"  [{f.severity}] {f.agent_name}: {f.description[:80]}")
    if HAS_RICH:
        console.print(t)
    rpath = svc.save_report("bytecode_analysis.txt", "\n".join(str(f) for f in findings))
    console.log(f"[green]Report saved:[/] {rpath}")
    prompt_input("Press [dim]Enter[/] to continue")

def _handle_agentic() -> None:
    console.rule("[bold cyan]Agentic Architecture Analysis[/]")
    directory = prompt_input("Enter project directory path")
    if not directory or not os.path.isdir(directory):
        console.log("[red]Invalid directory[/]")
        return
    console.log("[bold]Analyzing project architecture...[/]")
    result = analyze_project_agentic(directory)
    console.print(result[:2000])
    rpath = svc.save_report("agentic_analysis.txt", result)
    console.log(f"[green]Report saved:[/] {rpath}")
    prompt_input("Press [dim]Enter[/] to continue")

def _handle_webhook() -> None:
    console.rule("[bold cyan]Send Report via Webhook[/]")
    result = _load_single_sol_file()
    if result is None:
        return
    code, name = result
    webhook_url = prompt_input("Discord/Slack webhook URL")
    if not webhook_url:
        return
    webhook_type = "slack" if "slack" in webhook_url.lower() else "discord"
    console.log(f"[bold]Running audit for webhook...[/]")
    report = svc.run_audit(code)
    from analyzers.base import Finding
    dummy = [Finding(agent_name="Audit", severity="Info", category="Webhook",
                     file=f"{name}.sol", line=1,
                     description="Audit completed via webhook", fix="")]
    send_report(webhook_url, dummy, webhook_type, project=name)
    console.log(f"[green]Report sent to {webhook_type} webhook[/]")
    prompt_input("Press [dim]Enter[/] to continue")


INTERACTIVE_DISPATCH: Dict[str, Callable] = {
    "1": _handle_demo,
    "2": _handle_github_audit,
    "3": _handle_local_file,
    "4": _handle_multi_audit,
    "5": _handle_hierarchical,
    "6": _handle_opcodes,
    "7": _resume_progress,
    "8": _handle_combined_report,
    "9": _handle_storage,
    "10": _handle_inheritance,
    "11": _handle_json_output,
    "12": _handle_cache_stats,
    "13": _handle_critique,
    "14": _handle_init_config,
    "15": _handle_parallel,
    "16": _handle_move_audit,
    "17": _handle_kb_stats,
    "18": _handle_diff_audit,
    "19": _handle_bytecode,
    "20": _handle_agentic,
    "21": _handle_webhook,
}

MENU_ITEMS = [
    ("1", "Analyze demo contract (test)"),
    ("2", "Analyze GitHub repo"),
    ("3", "Analyze local Solidity file"),
    ("4", "Multi-model analysis (from GitHub)"),
    ("5", "Hierarchical analysis (Layer 1 + The Crucible)"),
    ("6", "Opcodes only (fast)"),
    ("7", "Resume saved progress"),
    ("8", "Combined report (Opcodes + Storage + Inheritance)"),
    ("9", "Storage analysis"),
    ("10", "Inheritance analysis"),
    ("11", "JSON output"),
    ("12", "Cache stats"),
    ("13", "Self-critique"),
    ("14", "Create config.json"),
    ("15", "Parallel analysis"),
    ("16", "Move/Sui hierarchical analysis"),
    ("17", "📚 Knowledge Base stats"),
    ("18", "Diff Audit"),
    ("19", "Bytecode analysis (hex/address/file)"),
    ("20", "Agentic architecture analysis"),
    ("21", "Send audit via Discord/Slack webhook"),
    ("0", "Exit"),
]


def interactive_mode() -> None:
    show_banner("Smart Contract Auditor")
    while True:
        if HAS_RICH:
            t = Table(box=box.SIMPLE, show_header=False)
            t.add_column("Key", style="bold cyan", width=4)
            t.add_column("Description")
            for k, desc in MENU_ITEMS:
                t.add_row(k, desc)
            console.print(t)
        else:
            console.print("Choose source:")
            for k, desc in MENU_ITEMS:
                console.print(f"  {k}. {desc}")
        choice = prompt_input("Enter choice")

        if choice == "0":
            console.print("[yellow]Exiting...[/]")
            return

        handler = INTERACTIVE_DISPATCH.get(choice)
        if handler:
            handler()
        else:
            console.log("[red]Invalid choice, try again[/]")


class CLIApp:
    """Separated CLI interface from business logic"""

    @staticmethod
    def run() -> None:
        setup_output()
        ensure_report_dir()

        parser = argparse.ArgumentParser(
            description="Smart Contract Auditor",
            epilog="Example: python main.py --file MyContract.sol"
        )
        group = parser.add_mutually_exclusive_group()
        group.add_argument("--demo", action="store_true", help="Demo analysis")
        group.add_argument("--file", type=str, help="Local Solidity file")
        group.add_argument("--github", type=str, help="GitHub repo URL")

        parser.add_argument("--multi", action="store_true", help="Multi-model analysis")
        parser.add_argument("--hierarchical", action="store_true", help="Hierarchical analysis")
        parser.add_argument("--opcodes", action="store_true", help="Opcodes analysis (no API)")
        parser.add_argument("--combined", action="store_true", help="Combined report")
        parser.add_argument("--storage", action="store_true", help="Storage analysis")
        parser.add_argument("--inheritance", action="store_true", help="Inheritance analysis")
        parser.add_argument("--critique", action="store_true", help="Analysis + self-critique")
        parser.add_argument("--json", action="store_true", help="JSON output")
        parser.add_argument("--parallel", action="store_true", help="Parallel analysis")
        parser.add_argument("--cache-stats", action="store_true", help="Cache stats")
        parser.add_argument("--kb-stats", action="store_true", help="Knowledge Base stats")
        parser.add_argument("--init-config", action="store_true", help="Create config.json")
        parser.add_argument("--unified", action="store_true", help="Full audit: opcodes + storage + inheritance + combined")
        parser.add_argument("--focus", type=str, help="Specific contract name")
        parser.add_argument("--resume", action="store_true", help="Resume progress")
        parser.add_argument("--team", type=str, nargs="*", help="Model names")
        parser.add_argument("--token", type=str, help="GitHub Token")
        parser.add_argument("--contract-index", type=int, help="Contract index (1-based)")
        parser.add_argument("--name", type=str, help="Protocol name")

        parser.add_argument("--parallel-workers", type=int, default=3, help="Parallel workers")
        parser.add_argument("--sarif", action="store_true", help="Export results as SARIF format for GitHub/VSCode")
        parser.add_argument("--autopoc", action="store_true", help="Auto-PoC: validate Critical findings with Foundry tests")
        parser.add_argument("--grant-audit", action="store_true", help="Gitcoin/Allo protocol compliance check")
        parser.add_argument("--bytecode", type=str, help="Bytecode hex string, address, or file path for bytecode analysis")
        parser.add_argument("--agentic", type=str, help="Project directory for agentic architecture analysis")
        parser.add_argument("--webhook", type=str, help="Discord/Slack webhook URL to send audit report")
        parser.add_argument("--webhook-type", type=str, choices=["discord", "slack"], default="discord")

        args = parser.parse_args()

        if args.resume:
            _resume_progress()
            return

        if len(sys.argv) == 1:
            interactive_mode()
        else:
            cli_mode(args)


def _output_json(data: dict) -> None:
    console.print("\n[bold]JSON Output:[/]")
    console.print(json.dumps(data, ensure_ascii=False, indent=2))
    rpath = svc.save_report(f"report_{data.get('type', 'output')}.json",
                             json.dumps(data, ensure_ascii=False, indent=2))
    console.log(f"[green]JSON saved:[/] {rpath}")


def cli_mode(args: argparse.Namespace) -> None:
    show_banner("Smart Contract Auditor")
    code: Optional[str] = None
    label: str = "contract"

    if args.cache_stats:
        _handle_cache_stats()
        return

    if args.kb_stats:
        _handle_kb_stats()
        return

    if args.init_config:
        _handle_init_config()
        return

    if args.bytecode:
        source = args.bytecode
        findings = []
        if source.startswith("0x") and len(source) > 42:
            findings = analyze_bytecode(source, "cli")
        elif source.startswith("0x") and len(source) == 42:
            findings = analyze_contract_from_explorer(source)
        else:
            try:
                with open(source, "r", encoding="utf-8") as f:
                    data = f.read()
                if data.startswith("0x"):
                    findings = analyze_bytecode(data, os.path.basename(source))
            except FileNotFoundError:
                console.log(f"[red]File not found:[/] {source}")
                return
        for f in findings:
            console.print(f"  [{f.severity}] {f.agent_name}: {f.description[:120]}")
        rpath = svc.save_report("bytecode_analysis.txt", "\n".join(str(f) for f in findings))
        console.log(f"[green]Report saved:[/] {rpath}")
        return

    if args.agentic:
        if not os.path.isdir(args.agentic):
            console.log(f"[red]Directory not found:[/] {args.agentic}")
            return
        result = analyze_project_agentic(args.agentic)
        console.print(result[:2000])
        rpath = svc.save_report("agentic_analysis.txt", result)
        console.log(f"[green]Report saved:[/] {rpath}")
        return

    if args.demo:
        code = DEMO_CODE
        label = "demo"
    elif args.file:
        code = svc.load_code(args.file)
        if code is None:
            console.log(f"[red]File not found:[/] {args.file}")
            sys.exit(1)
        label = os.path.basename(args.file).replace('.sol', '')
    elif args.github:
        contracts = download_contracts(args.github, args.token)
        if not contracts:
            sys.exit(1)
        if args.contract_index is not None:
            idx = args.contract_index - 1
            if idx < 0 or idx >= len(contracts):
                console.log(f"[red]Invalid index. Choose 1-{len(contracts)}[/]")
                sys.exit(1)
            code = contracts[idx]['code']
            label = contracts[idx]['name'].replace('/', '_').replace('.sol', '')
        else:
            for contract in contracts:
                console.rule(f"[cyan]{contract['name']}[/]")
                report = svc.run_audit(contract['code'])
                safe_name = contract['name'].replace('/', '_').replace('.sol', '')
                rpath = svc.save_report(f"audit_{safe_name}.txt", report)
                console.log(f"[green]Report saved:[/] {rpath}")
            console.log("[green]All contracts analyzed.[/]")
            return

    if code is None:
        console.log("[red]No code provided for analysis.[/]")
        sys.exit(1)

    if args.autopoc:
        console.log("[bold]Initial analysis + self-critique + Auto-PoC validation...[/]")
        report = dispatch_analysis(code, "autopoc")
        rpath = svc.save_report(f"autopoc_{label}.txt", report)
        console.log(f"[green]Report saved:[/] {rpath}")
        console.print(Markdown(report) if HAS_RICH else report)
        return

    if args.critique:
        console.log("[bold]Initial analysis + self-critique...[/]")
        initial, critique = svc.run_critique(code)
        r1 = svc.save_report(f"audit_{label}.txt", initial)
        r2 = svc.save_report(f"critique_{label}.txt", critique)
        console.log(f"[green]Reports saved:[/]  {r1}  {r2}")
        console.print(Markdown(critique) if HAS_RICH else critique)
        return

    analysis_type = "audit"
    if args.autopoc:
        analysis_type = "autopoc"
    elif args.opcodes:
        analysis_type = "opcodes"
    elif args.combined:
        analysis_type = "combined"
    elif args.storage:
        analysis_type = "storage"
    elif args.inheritance:
        analysis_type = "inheritance"
    elif args.unified:
        analysis_type = "unified"
    elif args.hierarchical:
        analysis_type = "hierarchical"
    elif args.multi:
        analysis_type = "multi"

    if analysis_type == "unified":
        op = dispatch_analysis(code, "opcodes")
        st = dispatch_analysis(code, "storage")
        ih = dispatch_analysis(code, "inheritance")
        cm = dispatch_analysis(code, "combined", name=args.name or label.replace('_', ' ').title())
        report = f"=== Opcodes ===\n{op}\n\n=== Storage ===\n{st}\n\n=== Inheritance ===\n{ih}\n\n=== Combined ===\n{cm}"
    elif analysis_type == "hierarchical":
        protocol = args.name or label.replace('_', ' ').title()
        if args.focus:
            console.log(f"[bold]Focus:[/] {args.focus}")
        report = dispatch_analysis(code, "hierarchical", protocol_name=protocol,
                                    focus=args.focus or "", repo_url=args.github or "")
    elif analysis_type == "multi":
        report = dispatch_analysis(code, "multi", team=args.team)
    else:
        report = dispatch_analysis(code, analysis_type,
                                    name=args.name or label.replace('_', ' ').title())
    rpath = svc.save_report(f"{analysis_type}_{label}.txt", report)

    if args.sarif:
        from sarif_export import generate_sarif
        from analyzers.base import Finding
        dummy = []
        if code:
            dummy = [Finding(agent_name="StaticAnalysis", severity="Info", category="Report",
                             file=args.file or "demo.sol", function_name="",
                             description=f"Analysis report generated ({analysis_type})",
                             fix="")]
        sarif_path = os.path.join(REPORT_DIR, f"{analysis_type}_{label}.sarif")
        generate_sarif(dummy, sarif_path)
        console.log(f"[green]SARIF saved:[/] {sarif_path}")

    if args.webhook and code:
        from analyzers.base import Finding
        dummy = [Finding(agent_name="StaticAnalysis", severity="Info", category="Webhook",
                         file=args.file or "demo.sol", function_name="",
                         description=f"Analysis report ({analysis_type})", fix="")]
        send_report(args.webhook, dummy, args.webhook_type, project=label)
        console.log(f"[green]Report sent via {args.webhook_type} webhook[/]")

    console.log(f"[green]Report saved:[/] {rpath}")
    console.print(Markdown(report) if HAS_RICH else report)


def main() -> None:
    CLIApp.run()


if __name__ == "__main__":
    main()
