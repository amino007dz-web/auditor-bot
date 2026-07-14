"""
Shared base for hierarchical multi-agent analysis.
Layer 1: N specialized agents (parallel, independent)
Layer 2: The Crucible (investigator + skeptic + critic)
"""
import json
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

from config import FREE_MODELS, REPORT_DIR, PROGRESS_FILE, PARALLEL_MAX_WORKERS
from agents import call_model_with_fallback, truncate_code

try:
    from tqdm import tqdm as _tqdm
    HAVE_TQDM = True
    tqdm = _tqdm
except ImportError:
    HAVE_TQDM = False
    tqdm = None

from cli_display import console, progress_context, HAS_RICH

logger = logging.getLogger(__name__)


class _RichProgressWrapper:
    """Wrap futures/iterable with Rich Progress bar, falling back to tqdm."""
    def __init__(self, items, desc: str = "Processing"):
        self.items = list(items)
        self.desc = desc
        self.total = len(self.items)

    def __iter__(self):
        if HAS_RICH:
            from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                          BarColumn(), console=console) as p:
                task = p.add_task(self.desc, total=self.total)
                for item in self.items:
                    yield item
                    p.advance(task)
        elif HAVE_TQDM:
            for item in tqdm(self.items, desc=self.desc, unit="item"):
                yield item
        else:
            console.log(f"{self.desc} ({self.total} items)")
            yield from self.items


class HierarchicalAuditor:
    """Reusable hierarchical auditor with configurable agents."""

    def __init__(self, layer1_agents: List[dict], layer2_agents: List[dict],
                 default_model: str = "llama-3.3-70b", protocol_name: str = "Protocol"):
        self.layer1_agents = layer1_agents
        self.layer2_agents = layer2_agents
        self.default_model = default_model
        self.protocol_name = protocol_name

    def _save_progress(self, stage: str, data: dict) -> None:
        os.makedirs(REPORT_DIR, exist_ok=True)
        existing = {}
        if os.path.exists(PROGRESS_FILE):
            try:
                with open(PROGRESS_FILE, "r", encoding="utf-8") as f:
                    existing = json.load(f)
            except (json.JSONDecodeError, IOError):
                existing = {}
        key = f"{self.protocol_name}_{stage}"
        existing[key] = {
            "timestamp": time.time(), "stage": stage,
            "protocol": self.protocol_name, "data": data,
        }
        with open(PROGRESS_FILE, "w", encoding="utf-8") as f:
            json.dump(existing, f, ensure_ascii=False, indent=2)

    def _load_progress(self, stage: str) -> Optional[dict]:
        if not os.path.exists(PROGRESS_FILE):
            return None
        try:
            with open(PROGRESS_FILE, "r", encoding="utf-8") as f:
                existing = json.load(f)
            return existing.get(f"{self.protocol_name}_{stage}")
        except (json.JSONDecodeError, IOError):
            return None

    def _save_intermediate(self, stage: str, content: str) -> str:
        os.makedirs(REPORT_DIR, exist_ok=True)
        safe = self.protocol_name.replace(" ", "_").replace("/", "_")
        path = os.path.join(REPORT_DIR, f"partial_{safe}_{stage}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    def _run_agent(self, model_key: str, prompt: str, agent_name: str) -> Optional[str]:
        from config import MODEL_FALLBACK_CHAIN
        chain = [model_key] + [m for m in MODEL_FALLBACK_CHAIN if m != model_key]
        try:
            return call_model_with_fallback(prompt, timeout=600, model_chain=chain)
        except Exception as e:
            logger.error(f"{agent_name} failed: {e}")
            return None

    def _summarize(self, reports: Dict[str, str], max_chars: int = 2000) -> str:
        out = ""
        for key, text in reports.items():
            out += f"\n--- {key} ---\n"
            if not text or text == "(failed)":
                out += "(analysis failed)\n"
                continue
            structured = self._extract_structured(text)
            out += structured[:max_chars] + "\n"
        return out

    def _extract_structured(self, report: str) -> str:
        """Extract structured summary: key vulnerabilities, severity, fixes"""
        lines = report.split("\n")
        kept = []
        seen_headers = set()
        for line in lines:
            stripped = line.strip()
            # Keep main headers
            if stripped.startswith("###") or stripped.startswith("##"):
                if stripped not in seen_headers:
                    seen_headers.add(stripped)
                    kept.append(line)
            # Keep vulnerability, severity, and fix lines
            elif any(stripped.startswith(x) for x in ("- **", "* **", "|", "Severity", "Fix", "Severity", "Fix", "Name")):
                if len(kept) < 80:
                    kept.append(line)
            # Keep short lines (< 100 chars) first 40 lines
            elif len(stripped) < 100 and len(kept) < 40:
                kept.append(line)
        return "\n".join(kept)

    def _progress_iter(self, items, desc: str = "Processing"):
        """Wrap iterable with progress: Rich > tqdm > plain."""
        if HAS_RICH:
            from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
            return _RichProgressWrapper(items, desc)
        if HAVE_TQDM:
            return tqdm(items, desc=desc, unit="item")
        return items

    def run_layer1(self, code: str) -> Dict[str, str]:
        """Run layer 1 agents in parallel (independent specialized views)."""
        console.rule("[bold cyan]Layer 1: Specialized analysis[/]")
        saved = self._load_progress("layer1")
        if saved:
            logger.info("Resuming saved Layer 1 progress")
            return saved["data"]

        truncated = truncate_code(code, self.default_model)
        base = f"### Original code\n```solidity\n{truncated}\n```\n\n"
        results: Dict[str, str] = {}
        cumulative = base

        with ThreadPoolExecutor(max_workers=PARALLEL_MAX_WORKERS) as executor:
            futures = {}
            for agent in self.layer1_agents:
                prompt = f"{agent['prompt']}\n\n{base}"
                future = executor.submit(self._run_agent, agent["model"], prompt, agent["name"])
                futures[future] = agent

            for future in self._progress_iter(list(futures.keys()), f"Layer 1 ({len(futures)} agents)"):
                agent = futures[future]
                result = future.result()
                results[agent["name"]] = result or "(failed)"
                if result:
                    cumulative += f"\n\n### {agent['name']}\n{result[:3000]}\n"
                self._save_intermediate(f"layer1_{agent['key']}", result or "(failed)")
                self._save_progress("layer1", results)

        return results

    def run_layer2(self, code: str, layer1_results: Dict[str, str],
                   extra_context: str = "") -> Dict[str, str]:
        """Run Layer 2: The Crucible (investigator, skeptic, critic)."""
        console.rule("[bold magenta]Layer 2: The Crucible[/]")
        saved = self._load_progress("layer2")
        if saved:
            logger.info("Resuming saved Layer 2 progress")
            return saved["data"]

        truncated = truncate_code(code, self.default_model)
        l1_summary = self._summarize(layer1_results, max_chars=2500)

        crucible = f"### Original code\n```solidity\n{truncated[:3000]}\n```\n\n"
        crucible += f"### Layer 1 analyses\n{l1_summary}\n"
        if extra_context:
            crucible += f"\n{extra_context}\n"

        results: Dict[str, str] = {}
        for agent in self._progress_iter(self.layer2_agents, f"Crucible ({len(self.layer2_agents)} agents)"):
            prompt = f"{agent['prompt']}\n\n{crucible}"
            if results:
                prev_key = list(results.keys())[-1]
                prompt += f"\n\n### Previous agent ({prev_key})\n{results[prev_key][:3000]}"
            result = self._run_agent(agent["model"], prompt, agent["name"])
            results[agent["name"]] = result or "(failed)"
            if result:
                crucible += f"\n\n### {agent['name']}\n{result[:3000]}\n"
            self._save_intermediate(f"layer2_{agent['key']}", result or "(failed)")
            self._save_progress("layer2", results)

        return results

    def _merge_fallback(self, layer1: Dict[str, str], layer2: Dict[str, str]) -> str:
        report = f"# {self.protocol_name} — Security Report (Hierarchical)\n\n"
        for name, text in layer1.items():
            report += f"\n### {name}\n{text[:2000]}\n---\n"
        for name, text in layer2.items():
            report += f"\n### {name}\n{text[:2000]}\n---\n"
        report += "\n\nAuto-merged report."
        return report

    def run(self, code: str,
            extra_context: str = "") -> Tuple[Dict[str, str], Dict[str, str], str]:
        """Run full hierarchical analysis. Returns (layer1, layer2, final_report)."""
        layer1 = self.run_layer1(code)
        layer2 = self.run_layer2(code, layer1, extra_context)

        critic_report = layer2.get("Critic")
        if critic_report and critic_report != "(failed)":
            final = critic_report
        else:
            logger.warning("Critic failed — using manual merge")
            final = self._merge_fallback(layer1, layer2)

        return layer1, layer2, final
