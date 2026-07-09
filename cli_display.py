"""Rich CLI module — colors, tables, Progress Bar for all CLI interfaces."""

from contextlib import contextmanager
from typing import Dict, List, Optional

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskID
    from rich.panel import Panel
    from rich.markdown import Markdown
    from rich.prompt import Prompt, Confirm
    from rich.text import Text
    from rich import box
    from rich.rule import Rule
    from rich.syntax import Syntax
    from rich.traceback import install as rich_tb_install

    HAS_RICH = True
    rich_tb_install()
except ImportError:
    HAS_RICH = False

# Fallback: if Rich not installed, use plain print
if not HAS_RICH:

    class _FakeConsole:
        def print(self, *args, **kwargs):
            import builtins
            builtins.print(*args)

        def log(self, *args, **kwargs):
            import builtins
            builtins.print(*args)

        def rule(self, title="", **kwargs):
            import builtins
            builtins.print(f"\n{'='*60}\n{title}\n{'='*60}")

        def input(self, prompt="", **kwargs):
            import builtins
            return builtins.input(prompt)

    Console = _FakeConsole
    Table = None
    Progress = None
    SpinnerColumn = None
    TextColumn = None
    BarColumn = None
    TaskID = None
    Panel = None
    Markdown = None
    Prompt = None
    Confirm = None
    Text = None
    box = None
    Rule = None
    Syntax = None
    HAS_RICH = False


_SEVERITY_STYLES: Dict[str, str] = {
    "Critical": "bold red",
    "High": "bold yellow",
    "Medium": "bold blue",
    "Low": "cyan",
    "Info": "white",
}
_SEVERITY_ICONS: Dict[str, str] = {
    "Critical": "🔴",
    "High": "🟡",
    "Medium": "🔵",
    "Low": "ℹ️",
    "Info": "💡",
}

console = Console()


def severity_style(severity: str) -> str:
    return _SEVERITY_STYLES.get(severity, "white")


def severity_text(severity: str) -> Text:
    style = severity_style(severity)
    icon = _SEVERITY_ICONS.get(severity, "")
    t = Text(f"{icon} {severity}")
    t.stylize(style)
    return t


def findings_table(findings: List[Dict]) -> Optional[Table]:
    if not HAS_RICH:
        return None
    t = Table(title="Findings Summary", box=box.ROUNDED,
              header_style="bold magenta")
    t.add_column("#", style="dim", width=3)
    t.add_column("Severity", width=10)
    t.add_column("Agent", style="bold")
    t.add_column("File", style="dim", width=20)
    t.add_column("Description", width=50)
    for i, f in enumerate(findings, 1):
        t.add_row(str(i), severity_text(f.get("severity", "Info")),
                  f.get("agent", "")[:30], f.get("file", "")[:18],
                  f.get("description", "")[:48])
    return t


def findings_table_simple(severities: Dict[str, int]) -> Optional[Table]:
    if not HAS_RICH:
        return None
    t = Table(title="Findings by Severity", box=box.SIMPLE)
    t.add_column("Severity", style="bold", width=12)
    t.add_column("Count", justify="right", width=6)
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        count = severities.get(sev, 0)
        t.add_row(severity_text(sev), str(count))
    return t


def progress_bar(description: str = "Working", total: int = 1):
    if HAS_RICH:
        return Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                        BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                        console=console)
    return None


@contextmanager
def progress_context(description: str = "Working", total: int = 1):
    """Context manager for progress bar — safe fallback if Rich absent."""
    if HAS_RICH:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                      console=console) as p:
            task = p.add_task(description, total=total)
            yield p, task
    else:
        import builtins
        builtins.print(f"{description}... ({total} items)")
        yield None, None


def info_panel(title: str, content: str, style: str = "cyan") -> Optional[Panel]:
    if not HAS_RICH:
        return None
    return Panel(content, title=title, border_style=style)


def banner(text: str):
    if HAS_RICH:
        console.print(Rule(style="bold green"))
        console.print(Text(text, style="bold green", justify="center"))
        console.print(Rule(style="bold green"))
    else:
        import builtins
        builtins.print(f"\n{'='*60}\n{text}\n{'='*60}")


def markdown_report(text: str):
    if HAS_RICH:
        console.print(Markdown(text))
    else:
        import builtins
        builtins.print(text)


def prompt_input(prompt_text: str, default: str = "") -> str:
    if HAS_RICH:
        return Prompt.ask(prompt_text, default=default) if default else Prompt.ask(prompt_text)
    else:
        import builtins
        d = builtins.input(f"{prompt_text} [{default}]: ").strip() if default else builtins.input(f"{prompt_text}: ").strip()
        return d or default


def confirm_action(prompt_text: str, default: bool = True) -> bool:
    if HAS_RICH:
        return Confirm.ask(prompt_text, default=default)
    else:
        import builtins
        r = builtins.input(f"{prompt_text} (Y/n): ").strip().lower() if default else builtins.input(f"{prompt_text} (y/N): ").strip().lower()
        if default:
            return r != "n"
        return r == "y"
