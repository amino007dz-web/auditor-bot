"""Foundry/Hardhat/Truffle - detect project structure and analyze all contracts."""
import os
import json
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class ProjectDetector:
    """Detect smart contract project type."""

    @staticmethod
    def detect(root: str) -> Optional[dict]:
        """Detect project type and return its info."""
        if not os.path.isdir(root):
            return None

        info = {"root": root, "type": None, "contract_dirs": [], "config": {}}

        # Foundry
        if os.path.isfile(os.path.join(root, "foundry.toml")):
            info["type"] = "foundry"
            src = os.path.join(root, "src")
            if os.path.isdir(src):
                info["contract_dirs"].append(src)
            info["config"] = {"test_cmd": "forge test", "build_cmd": "forge build"}
            return info

        # Hardhat
        if os.path.isfile(os.path.join(root, "hardhat.config.js")) or \
           os.path.isfile(os.path.join(root, "hardhat.config.ts")) or \
           os.path.isfile(os.path.join(root, "hardhat.config.cjs")):
            info["type"] = "hardhat"
            for d in ["contracts", "src"]:
                p = os.path.join(root, d)
                if os.path.isdir(p):
                    info["contract_dirs"].append(p)
            info["config"] = {"test_cmd": "npx hardhat test", "build_cmd": "npx hardhat compile"}
            return info

        # Truffle
        if os.path.isfile(os.path.join(root, "truffle-config.js")):
            info["type"] = "truffle"
            for d in ["contracts"]:
                p = os.path.join(root, d)
                if os.path.isdir(p):
                    info["contract_dirs"].append(p)
            info["config"] = {"test_cmd": "truffle test", "build_cmd": "truffle compile"}
            return info

        # Brownie
        if os.path.isfile(os.path.join(root, "brownie-config.yaml")):
            info["type"] = "brownie"
            for d in ["contracts"]:
                p = os.path.join(root, d)
                if os.path.isdir(p):
                    info["contract_dirs"].append(p)
            info["config"] = {"test_cmd": "brownie test", "build_cmd": "brownie compile"}
            return info

        # Generic — look for any contracts folder
        for d in ["contracts", "src"]:
            p = os.path.join(root, d)
            if os.path.isdir(p):
                info["contract_dirs"].append(p)
        if info["contract_dirs"]:
            info["type"] = "generic"
            return info

        return None


def analyze_project(root: str) -> str:
    """Detect project and audit all its contracts."""
    from batch_audit import batch_audit

    info = ProjectDetector.detect(root)
    if not info:
        return "Project structure was not recognized"

    lines = [f"=== Project Analysis ===",
             f"Root: {root}",
             f"Type: {info['type'] or 'generic'}",
             f"Contract directories: {', '.join(info['contract_dirs']) or 'none'}",
             f"Config: {json.dumps(info.get('config', {}))}",
             ""]

    for d in info["contract_dirs"]:
        result = batch_audit(d)
        lines.append(f"--- {d} ---")
        lines.append(f"Total: {result['total']} | Done: {result['done']} | Errors: {result['errors']}")
        for r in result.get("results", []):
            lines.append(f"  {'✅' if r['status']=='done' else '❌'} {r['file']} — {r['status']}")
        lines.append("")

    txt = "\n".join(lines)
    from main import save_report_txt
    save_report_txt(f"project_{os.path.basename(root)}_english.txt", txt)
    return txt
