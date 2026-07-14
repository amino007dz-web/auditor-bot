import logging
from typing import List, Dict, Optional

from config import FREE_MODELS
from agents import analyze_code, call_model
from cli_display import console, banner, HAS_RICH

if HAS_RICH:
    from rich.rule import Rule

if not logging.getLogger().hasHandlers():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# Three different free models for diverse analysis
DEFAULT_TEAM: List[str] = ["openrouter-free", "qwen3-coder", "nemotron-3-ultra"]
LEAD_MODEL: str = "openrouter-free"


def multi_audit(code: str, team: Optional[List[str]] = None) -> str:
    if team is None:
        team = DEFAULT_TEAM

    team = [m for m in team if m in FREE_MODELS]
    if not team:
        console.log("[red]❌ No valid models in the team[/]")
        return ""

    banner("🧠 Multi-Model Analysis")
    console.log(f"[bold]Team:[/] {', '.join(team)}")

    # ─── Phase 1: Analyze each model individually ───
    reports: Dict[str, str] = {}
    for i, model_key in enumerate(team, 1):
        label = f"Analyst #{i} ({model_key})"
        console.rule(f"[bold cyan]{label}[/]" if HAS_RICH else f"\n--- {label} ---")
        try:
            result = analyze_code(code, model_key=model_key)
            reports[label] = result
            console.log(f"[green]✅ {label} completed analysis[/]")
        except Exception as e:
            console.log(f"[red]❌ {label} failed: {e}[/]")
            try:
                console.log("[yellow]🔄 Trying fallback...[/]")
                result = analyze_code(code, model_key="openrouter-free")
                reports[f"{label} (fallback)"] = result
                console.log("[green]✅ Success via fallback[/]")
            except:
                console.log("[red]❌ Fallback also failed[/]")

    reports = {k: v for k, v in reports.items() if v}

    if not reports:
        console.log("[red]❌ All models failed![/]")
        return "Analysis failed - all models currently unavailable. Try again later."

    # ─── Phase 2: Discussion between models ───
    banner("🗣️ Phase 2: Discussion")

    discussion_prompt = _build_discussion_prompt(code, reports)

    for lead_key in [LEAD_MODEL, "openrouter-free"]:
        if lead_key not in FREE_MODELS:
            continue
        lead_id = FREE_MODELS[lead_key]["id"]
        try:
            console.log(f"[bold]🤖 Lead: {lead_key}[/] — generating final report...")
            final_report = call_model(lead_id, discussion_prompt, timeout=300)
            console.log("[green]✅ Final report ready![/]")
            return final_report
        except Exception as e:
            console.log(f"[yellow]⚠️ Lead model {lead_key} failed: {e}[/]")

    console.log("[yellow]⚠️ Could not generate unified report. Showing individual analyses.[/]")
    merged = "Multi-Model Report (without discussion):\n\n"
    for model, report in reports.items():
        merged += f"\n{'='*60}\n## Analysis: {model}\n{'='*60}\n{report}\n"
    return merged


def _build_discussion_prompt(code: str, reports: Dict[str, str]) -> str:
    summaries = ""
    for i, (model, report) in enumerate(reports.items(), 1):
        summaries += f"\n--- Analysis #{i} ({model}) ---\n"
        summaries += (report or "")[:2000] + "\n...\n"

    prompt = f"""You are a smart contract security expert leading a team of analysts.

Task: Review the team's analysis summaries below, compare them, then output a unified final report.

Original code (first 2000 chars):
```solidity
{(code or "")[:2000]}
```

Team analysis summaries:
{summaries}

Output the report in English with the following format:
## Unified Final Report
### Unified Assessment
### Comparison Table (Analyst | Rating | Top Finding)
### Final Vulnerability List (Name - Severity - Discoverer - Fix)
### Gas Optimizations
### Summary of Disagreements Between Analysts
"""
    return prompt
