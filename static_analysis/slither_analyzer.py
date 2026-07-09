import json
import logging
import subprocess
import tempfile
import os
from typing import Optional, List, Dict

logger = logging.getLogger(__name__)

_SLITHER_AVAILABLE = None

def is_slither_available() -> bool:
    global _SLITHER_AVAILABLE
    if _SLITHER_AVAILABLE is not None:
        return _SLITHER_AVAILABLE
    try:
        subprocess.run(["slither", "--version"], capture_output=True, timeout=10)
        _SLITHER_AVAILABLE = True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        _SLITHER_AVAILABLE = False
    return _SLITHER_AVAILABLE


def run_slither(code: str, contract_name: str = "contract") -> Optional[str]:
    if not is_slither_available():
        logger.info("⚠️ Slither not installed. Install it: pip install slither-analyzer")
        return None

    tmp_dir = tempfile.mkdtemp()
    tmp_file = os.path.join(tmp_dir, f"{contract_name}.sol")
    try:
        with open(tmp_file, "w", encoding="utf-8") as f:
            f.write(code)

        result = subprocess.run(
            ["slither", tmp_file, "--json", "-"],
            capture_output=True, text=True, timeout=120
        )

        if result.returncode != 0:
            logger.warning(f"⚠️ Slither errors: {result.stderr[:500]}")
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                return result.stdout[:2000]

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return result.stdout[:2000]

        return _format_slither_output(data)

    except subprocess.TimeoutExpired:
        logger.warning("⏳ Slither timed out")
        return None
    except Exception as e:
        logger.warning(f"⚠️ Slither failed: {e}")
        return None
    finally:
        try:
            import shutil
            shutil.rmtree(tmp_dir)
        except:
            pass


def _format_slither_output(data: dict) -> str:
    detectors = data.get("results", {}).get("detectors", [])
    if not detectors:
        return "## Slither Analysis\n\n✅ Slither found no vulnerabilities.\n"

    report = "## Slither Analysis (Static Analysis)\n\n"
    report += f"| # | Vulnerability | Severity |\n|-------|--------|---------|\n"
    for i, d in enumerate(detectors, 1):
        sev = d.get("impact", "Medium").upper()
        check = d.get("check", "unknown")
        desc = d.get("description", "")[:80]
        report += f"| {i} | {check} | **{sev}** |\n"

    report += "\n### Details\n\n"
    for d in detectors:
        report += f"- **{d.get('check', 'unknown')}** [{d.get('impact', 'Medium').upper()}]\n"
        report += f"  {d.get('description', '')[:300]}\n"
        for elem in d.get("elements", [])[:2]:
            sc = elem.get("source_mapping", {})
            if sc:
                report += f"  - Line {sc.get('start', 0)}\n"
        report += "\n"

    return report


def detect_foundry_project(path: str) -> Optional[Dict]:
    if not os.path.isdir(path):
        return None
    has_foundry = os.path.exists(os.path.join(path, "foundry.toml"))
    has_hardhat = os.path.exists(os.path.join(path, "hardhat.config.js")) or \
                  os.path.exists(os.path.join(path, "hardhat.config.ts"))
    if not has_foundry and not has_hardhat:
        return None
    result = {"type": "foundry" if has_foundry else "hardhat", "path": path, "contracts": []}
    src_dir = os.path.join(path, "src" if has_foundry else "contracts")
    if os.path.isdir(src_dir):
        for root, _, files in os.walk(src_dir):
            for f in files:
                if f.endswith(".sol"):
                    fpath = os.path.join(root, f)
                    try:
                        with open(fpath, "r", encoding="utf-8") as fh:
                            result["contracts"].append({"name": os.path.relpath(fpath, path), "code": fh.read()})
                    except:
                        pass
    return result
