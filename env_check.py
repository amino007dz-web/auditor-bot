"""
Environment Check Tool
Ensures all tools and programs required for analysis are installed
"""
import importlib
import json
import os
import shutil
import subprocess
import sys
import warnings
from dataclasses import dataclass, field
from typing import List

from cli_display import console, banner, HAS_RICH

warnings.filterwarnings("ignore", category=DeprecationWarning)

if HAS_RICH:
    from rich.table import Table
    from rich import box


@dataclass
class Check:
    name: str
    category: str
    status: bool = False
    version: str = ""
    error: str = ""
    optional: bool = False


class EnvChecker:
    def __init__(self):
        self.checks: List[Check] = []

    def run(self):
        self._check_python()
        self._check_packages()
        self._check_solc()
        self._check_slither()
        self._check_mythril()
        self._check_foundry()
        self._check_hardhat()
        self._check_truffle()
        self._check_git()
        self._check_chisel()
        self._check_npm()
        self._check_node()
        self._check_rust()
        self._check_net()
        self._check_env_file()
        self._check_disk_space()
        self._check_ram()
        self._print_report()

    def _cmd(self, cmd: str) -> tuple:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=8, shell=True)
            out = (r.stdout or "").strip().split("\n")[0][:60] or (r.stderr or "").strip().split("\n")[0][:60]
            return r.returncode == 0, out
        except FileNotFoundError:
            return False, ""
        except subprocess.TimeoutExpired:
            return False, "timeout"
        except Exception as e:
            return False, str(e)[:60]

    def _add(self, name, category, ok, version="", error="", optional=False):
        safe_ver = version.encode("ascii", errors="replace").decode()[:60] if version else ""
        safe_err = error.encode("ascii", errors="replace").decode()[:60] if error else ""
        self.checks.append(Check(name, category, ok, safe_ver, safe_err, optional))

    def _check_python(self):
        ok = sys.version_info >= (3, 10)
        self._add("Python >= 3.10", "Core", ok, sys.version)

    def _check_packages(self):
        required = [
            ("requests", "requests"),
            ("python_dotenv", "python-dotenv"),
            ("flask", "flask"),
            ("pytest", "pytest"),
        ]
        optional = [
            ("PyGithub", "PyGithub"),
            ("groq", "groq"),
            ("fpdf2", "fpdf2"),
            ("solcast", "solcast"),
            ("solcx", "solcx"),
            ("tqdm", "tqdm"),
        ]
        for name, mod in required:
            try:
                m = importlib.import_module(mod)
                v = getattr(m, "__version__", "?")[:20]
                self._add(f"pip: {name}", "Packages", True, v)
            except ImportError:
                self._add(f"pip: {name}", "Packages", False, error="not installed")
        for name, mod in optional:
            try:
                importlib.import_module(mod)
                self._add(f"pip: {name}", "Packages (opt)", True, optional=True)
            except ImportError:
                self._add(f"pip: {name}", "Packages (opt)", False, error="not installed", optional=True)

    def _check_solc(self):
        ok, ver = self._cmd("solc --version")
        self._add("solc (Solidity)", "Static Analysis", ok, ver, optional=True)

    def _check_slither(self):
        ok, ver = self._cmd("slither --version")
        self._add("Slither (Solidity)", "Static Analysis", ok, ver, optional=True)

    def _check_mythril(self):
        ok, ver = self._cmd("mythril version")
        self._add("Mythril (Solidity)", "Static Analysis", ok, ver, optional=True)

    def _check_foundry(self):
        ok1, v1 = self._cmd("forge --version")
        ok2, v2 = self._cmd("cast --version")
        ok = ok1 and ok2
        self._add("Foundry (forge + cast)", "Frameworks", ok, v1 or "", optional=True)

    def _check_hardhat(self):
        ok = shutil.which("npx") is not None
        if ok:
            ok2, v2 = self._cmd("npx hardhat --version")
            self._add("Hardhat", "Frameworks", ok2, v2, optional=True)
        else:
            self._add("Hardhat", "Frameworks", False, error="npx not found", optional=True)

    def _check_truffle(self):
        ok, ver = self._cmd("truffle --version")
        self._add("Truffle", "Frameworks", ok, ver.split("\n")[0] if ver else "", optional=True)

    def _check_git(self):
        ok, ver = self._cmd("git --version")
        self._add("Git", "Core", ok, ver)

    def _check_chisel(self):
        self._add("chisel (Foundry)", "Frameworks", shutil.which("chisel") is not None, optional=True)

    def _check_npm(self):
        ok, ver = self._cmd("npm --version")
        self._add("npm", "Core", ok, f"v{ver}" if ver else "")

    def _check_node(self):
        ok, ver = self._cmd("node --version")
        self._add("Node.js", "Core", ok, ver)

    def _check_rust(self):
        ok, ver = self._cmd("rustc --version")
        self._add("Rust (rustc)", "Optional", ok, ver, optional=True)

    def _check_net(self):
        try:
            import requests
            requests.get("https://openrouter.ai", timeout=4)
            self._add("Internet", "Core", True, "connected")
        except Exception:
            self._add("Internet", "Core", False, error="no connection")

    def _check_env_file(self):
        env_path = os.path.join(os.path.dirname(__file__), ".env")
        if os.path.exists(env_path):
            with open(env_path, encoding="utf-8") as f:
                content = f.read()
            has_key = "OPENROUTER_API_KEY=sk-" in content or "OPENROUTER_API_KEY=or-" in content
            if has_key:
                self._add(".env + API Key", "Config", True, "key found")
            else:
                self._add(".env + API Key", "Config", False, error="file exists but key is empty")
        else:
            self._add(".env + API Key", "Config", False, error=".env file missing")

    def _check_disk_space(self):
        try:
            import shutil
            usage = shutil.disk_usage(os.path.dirname(__file__))
            free_gb = usage.free / (1024**3)
            ok = free_gb > 1
            self._add(f"Disk space ({free_gb:.1f} GB free)", "System", ok)
        except Exception:
            self._add("Disk space", "System", True, optional=True)

    def _check_ram(self):
        try:
            import psutil
            mem = psutil.virtual_memory()
            ok = mem.available > 512 * 1024 * 1024
            self._add(f"RAM ({mem.available/1024**3:.1f} GB free)", "System", ok)
        except ImportError:
            self._add("RAM (psutil not available)", "System", True, optional=True)

    def _print_report(self):
        banner("ENVIRONMENT CHECK REPORT")

        cats = {}
        for c in self.checks:
            cats.setdefault(c.category, []).append(c)

        required_ok = True
        if HAS_RICH:
            for cat, items in cats.items():
                t = Table(title=f"[{cat}]", box=box.SIMPLE, header_style="bold")
                t.add_column("Status", width=4)
                t.add_column("Check", style="bold")
                t.add_column("Version", style="dim")
                t.add_column("Error", style="red")
                for c in items:
                    icon = "✅" if c.status else ("⚠️" if c.optional else "❌")
                    ver = c.version if c.version else ""
                    err = c.error if c.error else ""
                    t.add_row(icon, c.name, ver, err)
                    if not c.status and not c.optional:
                        required_ok = False
                console.print(t)
                console.print()
        else:
            for cat, items in cats.items():
                console.print(f"  [{cat}]")
                console.print(f"  {'-' * 50}")
                for c in items:
                    iv = " [" + c.version + "]" if c.version else ""
                    ie = " (" + c.error + ")" if c.error else ""
                    icon = "[OK]" if c.status else ("[--]" if c.optional else "[!!]")
                    console.print(f"    {icon} {c.name}{iv}{ie}")
                    if not c.status and not c.optional:
                        required_ok = False
                console.print()

        total_ok = sum(1 for c in self.checks if c.status)
        total = len(self.checks)
        required = [c for c in self.checks if not c.optional]
        req_ok = sum(1 for c in required if c.status)

        if HAS_RICH:
            from rich.table import Table as T2
            s = T2(box=box.SIMPLE)
            s.add_column("Metric", style="bold")
            s.add_column("Value", justify="right")
            s.add_row("Total checks", str(total))
            s.add_row("Passed", f"[green]{total_ok}[/]")
            s.add_row("Required passed", f"{req_ok}/{len(required)}")
            console.print(s)
        else:
            console.print(f"  {total_ok}/{total} checks passed ({total_ok - req_ok} optional)")
            console.print(f"  {req_ok}/{len(required)} required checks passed")

        console.print()
        if not required_ok:
            console.print("[red]❌ Some required checks failed.[/]")
        else:
            console.print("[green]✅ Environment is ready for analysis.[/]")
        console.print()


if __name__ == "__main__":
    EnvChecker().run()
