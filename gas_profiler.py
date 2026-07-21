"""gas_profiler — compiles Solidity code and estimates gas via bytecode analysis + Foundry integration."""

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from typing import Optional

logger = logging.getLogger(__name__)

_GAS_SCHEDULE = {
    "ADD": 3, "SUB": 3, "MUL": 5, "DIV": 5, "SDIV": 5, "MOD": 5, "SMOD": 5,
    "ADDMOD": 8, "MULMOD": 8, "EXP": 10, "SIGNEXTEND": 5,
    "LT": 3, "GT": 3, "SLT": 3, "SGT": 3, "EQ": 3, "ISZERO": 3, "AND": 3,
    "OR": 3, "XOR": 3, "NOT": 3, "BYTE": 3, "SHL": 3, "SHR": 3, "SAR": 3,
    "KECCAK256": 30,
    "ADDRESS": 2, "BALANCE": 100, "ORIGIN": 2, "CALLER": 2, "CALLVALUE": 2,
    "CALLDATALOAD": 3, "CALLDATASIZE": 2, "CALLDATACOPY": 3,
    "CODESIZE": 2, "CODECOPY": 3, "GASPRICE": 2, "EXTCODESIZE": 100,
    "EXTCODECOPY": 100, "RETURNDATASIZE": 2, "RETURNDATACOPY": 3,
    "EXTCODEHASH": 100,
    "BLOCKHASH": 20, "COINBASE": 2, "TIMESTAMP": 2, "NUMBER": 2,
    "DIFFICULTY": 2, "GASLIMIT": 2, "CHAINID": 2, "SELFBALANCE": 5,
    "POP": 2, "MLOAD": 3, "MSTORE": 3, "MSTORE8": 3, "SLOAD": 100,
    "SSTORE": 20000, "JUMP": 8, "JUMPI": 10, "PC": 2, "MSIZE": 2,
    "GAS": 2, "JUMPDEST": 1, "PUSH1": 3, "PUSH2": 3, "PUSH3": 3,
    "PUSH4": 3, "PUSH5": 3, "PUSH6": 3, "PUSH7": 3, "PUSH8": 3,
    "PUSH9": 3, "PUSH10": 3, "PUSH11": 3, "PUSH12": 3, "PUSH13": 3,
    "PUSH14": 3, "PUSH15": 3, "PUSH16": 3, "PUSH17": 3, "PUSH18": 3,
    "PUSH19": 3, "PUSH20": 3, "PUSH21": 3, "PUSH22": 3, "PUSH23": 3,
    "PUSH24": 3, "PUSH25": 3, "PUSH26": 3, "PUSH27": 3, "PUSH28": 3,
    "PUSH29": 3, "PUSH30": 3, "PUSH31": 3, "PUSH32": 3,
    "DUP1": 3, "DUP2": 3, "DUP3": 3, "DUP4": 3, "DUP5": 3, "DUP6": 3,
    "DUP7": 3, "DUP8": 3, "DUP9": 3, "DUP10": 3, "DUP11": 3, "DUP12": 3,
    "DUP13": 3, "DUP14": 3, "DUP15": 3, "DUP16": 3,
    "SWAP1": 3, "SWAP2": 3, "SWAP3": 3, "SWAP4": 3, "SWAP5": 3,
    "SWAP6": 3, "SWAP7": 3, "SWAP8": 3, "SWAP9": 3, "SWAP10": 3,
    "SWAP11": 3, "SWAP12": 3, "SWAP13": 3, "SWAP14": 3, "SWAP15": 3,
    "SWAP16": 3,
    "LOG0": 375, "LOG1": 750, "LOG2": 1125, "LOG3": 1500, "LOG4": 1875,
    "CREATE": 32000, "CALL": 100, "CALLCODE": 100, "RETURN": 0,
    "DELEGATECALL": 100, "STATICCALL": 100, "CREATE2": 32000,
    "REVERT": 0, "INVALID": 0, "SELFDESTRUCT": 5000,
}

_OPCODE_RE = re.compile(r"([A-Z]+)(\d*)")

def _opcode_cost(opcode: str) -> int:
    m = _OPCODE_RE.match(opcode)
    if not m:
        return 0
    base = m.group(1)
    if base == "PUSH":
        return 3
    if base == "DUP":
        return 3
    if base == "SWAP":
        return 3
    if base == "LOG":
        n = int(m.group(2) or "0")
        return 375 + 375 * n
    return _GAS_SCHEDULE.get(base, 0)


def _disassemble(bytecode_hex: str) -> list:
    bytecode = bytecode_hex
    if bytecode.startswith("0x"):
        bytecode = bytecode[2:]
    ops = []
    i = 0
    while i < len(bytecode):
        op_byte = bytecode[i:i+2]
        if not op_byte:
            break
        val = int(op_byte, 16)
        i += 2
        if 0x60 <= val <= 0x7f:
            push_bytes = val - 0x5f
            data = bytecode[i:i+push_bytes*2]
            i += push_bytes * 2
            ops.append({"op": f"PUSH{push_bytes}", "data": data})
        elif val == 0x00:
            ops.append({"op": "STOP"})
        elif val == 0x01:
            ops.append({"op": "ADD"})
        elif val == 0x02:
            ops.append({"op": "MUL"})
        elif val == 0x03:
            ops.append({"op": "SUB"})
        elif val == 0x04:
            ops.append({"op": "DIV"})
        elif val == 0x20:
            ops.append({"op": "KECCAK256"})
        elif val == 0x30:
            ops.append({"op": "ADDRESS"})
        elif val == 0x31:
            ops.append({"op": "BALANCE"})
        elif val == 0x32:
            ops.append({"op": "ORIGIN"})
        elif val == 0x33:
            ops.append({"op": "CALLER"})
        elif val == 0x34:
            ops.append({"op": "CALLVALUE"})
        elif val == 0x35:
            ops.append({"op": "CALLDATALOAD"})
        elif val == 0x36:
            ops.append({"op": "CALLDATASIZE"})
        elif val == 0x37:
            ops.append({"op": "CALLDATACOPY"})
        elif val == 0x38:
            ops.append({"op": "CODESIZE"})
        elif val == 0x39:
            ops.append({"op": "CODECOPY"})
        elif val == 0x3a:
            ops.append({"op": "GASPRICE"})
        elif val == 0x3b:
            ops.append({"op": "EXTCODESIZE"})
        elif val == 0x40:
            ops.append({"op": "BLOCKHASH"})
        elif val == 0x41:
            ops.append({"op": "COINBASE"})
        elif val == 0x42:
            ops.append({"op": "TIMESTAMP"})
        elif val == 0x43:
            ops.append({"op": "NUMBER"})
        elif val == 0x44:
            ops.append({"op": "DIFFICULTY"})
        elif val == 0x45:
            ops.append({"op": "GASLIMIT"})
        elif val == 0x46:
            ops.append({"op": "CHAINID"})
        elif val == 0x47:
            ops.append({"op": "SELFBALANCE"})
        elif val == 0x50:
            ops.append({"op": "POP"})
        elif val == 0x51:
            ops.append({"op": "MLOAD"})
        elif val == 0x52:
            ops.append({"op": "MSTORE"})
        elif val == 0x53:
            ops.append({"op": "MSTORE8"})
        elif val == 0x54:
            ops.append({"op": "SLOAD"})
        elif val == 0x55:
            ops.append({"op": "SSTORE"})
        elif val == 0x56:
            ops.append({"op": "JUMP"})
        elif val == 0x57:
            ops.append({"op": "JUMPI"})
        elif val == 0x58:
            ops.append({"op": "PC"})
        elif val == 0x59:
            ops.append({"op": "MSIZE"})
        elif val == 0x5a:
            ops.append({"op": "GAS"})
        elif val == 0x5b:
            ops.append({"op": "JUMPDEST"})
        elif val == 0xa0:
            ops.append({"op": "LOG0"})
        elif val == 0xa1:
            ops.append({"op": "LOG1"})
        elif val == 0xa2:
            ops.append({"op": "LOG2"})
        elif val == 0xa3:
            ops.append({"op": "LOG3"})
        elif val == 0xa4:
            ops.append({"op": "LOG4"})
        elif val == 0xf0:
            ops.append({"op": "CREATE"})
        elif val == 0xf1:
            ops.append({"op": "CALL"})
        elif val == 0xf2:
            ops.append({"op": "CALLCODE"})
        elif val == 0xf3:
            ops.append({"op": "RETURN"})
        elif val == 0xf4:
            ops.append({"op": "DELEGATECALL"})
        elif val == 0xfa:
            ops.append({"op": "STATICCALL"})
        elif val == 0xf5:
            ops.append({"op": "CREATE2"})
        elif val == 0xfd:
            ops.append({"op": "REVERT"})
        elif val == 0xfe:
            ops.append({"op": "INVALID"})
        elif val == 0xff:
            ops.append({"op": "SELFDESTRUCT"})
        else:
            ops.append({"op": f"UNKNOWN_{hex(val)}"})
    return ops


_has_forge = shutil.which("forge") is not None


def _has_solc() -> bool:
    try:
        r = subprocess.run(["solc", "--version"], capture_output=True, text=True, timeout=10)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _compile_via_solcx(code: str) -> Optional[dict]:
    """Compile using py-solc-x (solcx) Python API instead of solc CLI."""
    try:
        import solcx
    except ImportError:
        return None
    try:
        # Detect pragma version from source code
        m = re.search(r"pragma solidity\s+([^;]+)", code)
        target = str(m.group(1)).replace("^", "").replace("~", "").split()[0].split("<")[0].split(">")[0].strip() if m else ""
        if not target:
            target = "0.8.25"
        ver = solcx.get_installed_solc_versions()
        if not ver:
            solcx.install_solc(target)
            ver = solcx.get_installed_solc_versions()
        if target not in [str(v) for v in ver]:
            solcx.install_solc(target)
        solcx.set_solc_version(target)
    except Exception as e:
        logger.debug(f"solcx setup: {e}")
        return None
    try:
        result = solcx.compile_source(code, output_values=["bin"])
    except Exception as e:
        logger.debug(f"solcx compile failed: {e}")
        return None
    contracts = {}
    for name, data in result.items():
        bin_hex = data.get("bin", "")
        if not bin_hex:
            continue
        ops = _disassemble(bin_hex)
        total = sum(_opcode_cost(o["op"]) for o in ops)
        contracts[name.split(":")[-1]] = {"bytecode_len": len(bin_hex) // 2, "opcodes": len(ops), "estimated_gas": total}
    return contracts if contracts else None


def compile_and_disassemble(code: str) -> Optional[dict]:
    contracts = _compile_via_solcx(code)
    if contracts:
        return contracts
    if not _has_solc():
        return None
    with tempfile.TemporaryDirectory(prefix="gas_") as tmp:
        src = os.path.join(tmp, "C.sol")
        with open(src, "w", encoding="utf-8") as f:
            f.write(code)
        try:
            r = subprocess.run(
                ["solc", "--bin", "--optimize", "--optimize-runs", "200", src],
                capture_output=True, text=True, timeout=60,
            )
        except subprocess.TimeoutExpired:
            logger.warning("solc compilation timed out")
            return None
        if r.returncode != 0:
            logger.warning(f"solc compilation failed: {r.stderr[:300]}")
            return None
    contracts = {}
    current = None
    for line in r.stdout.split("\n"):
        if line.startswith("======= ") and line.endswith(" ======="):
            current = line.split(" ")[1].split(":")[-1]
        elif current and line.strip() and not line.startswith("Binary"):
            bc = line.strip()
            ops = _disassemble(bc)
            total = sum(_opcode_cost(o["op"]) for o in ops)
            contracts[current] = {"bytecode_len": len(bc) // 2, "opcodes": len(ops), "estimated_gas": total}
            current = None
    return contracts if contracts else None


def _run_forge_gas_report_from_source(code: str) -> Optional[str]:
    if not _has_forge:
        return None
    with tempfile.TemporaryDirectory(prefix="forge_gas_") as tmp:
        os.makedirs(os.path.join(tmp, "src"), exist_ok=True)
        src = os.path.join(tmp, "src", "C.sol")
        with open(src, "w", encoding="utf-8") as f:
            f.write(code)
        foundry_toml = os.path.join(tmp, "foundry.toml")
        with open(foundry_toml, "w", encoding="utf-8") as f:
            f.write("[profile.default]\nsolc_version = \"0.8.26\"\n")
        try:
            r = subprocess.run(
                ["forge", "build", "--root", tmp, "--gas-report"],
                capture_output=True, text=True, timeout=120,
            )
        except subprocess.TimeoutExpired:
            logger.warning("forge build timed out")
            return None
        if r.returncode != 0:
            logger.debug(f"forge build failed: {r.stderr[:300]}")
            return None
        if r.stdout.strip():
            return r.stdout[:3000]
    return None


def run_forge_gas_report(project_path: str) -> str:
    if shutil.which("forge") is None:
        return ""
    try:
        r = subprocess.run(
            ["forge", "test", "--gas-report", "--json"],
            capture_output=True, text=True, timeout=120,
            cwd=project_path,
        )
    except subprocess.TimeoutExpired:
        logger.warning("forge test --gas-report timed out")
        return ""
    if r.returncode != 0:
        logger.debug(f"forge test failed: {r.stderr[:300]}")
        return ""
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        return r.stdout[:5000]
    if isinstance(data, dict):
        lines = ["### Forge Gas Report\n"]
        for contract, methods in data.items():
            lines.append(f"**{contract}**")
            if isinstance(methods, dict):
                for method, info in methods.items():
                    gas = info.get("gasUsed", "?")
                    lines.append(f"  {method}: {gas}")
            lines.append("")
        return "\n".join(lines)
    return ""


def estimate_gas(code: str, project_path: Optional[str] = None) -> str:
    parts = ["## Gas Profiling (Compilation-based)\n"]

    deployment = compile_and_disassemble(code)
    if deployment:
        parts.append("### Deployment Cost Estimate (solc)")
        parts.append(f"| Contract | Bytecode (bytes) | Opcodes | Est. Gas |")
        parts.append(f"|----------|-----------------|---------|----------|")
        for name, info in deployment.items():
            parts.append(f"| {name} | {info['bytecode_len']} | {info['opcodes']} | ~{info['estimated_gas']:,} |")
        parts.append("")
    else:
        parts.append("solc not available — install with: `pip install solc-select && solc-select install 0.8.26`")

    forge_report = _run_forge_gas_report_from_source(code)
    if forge_report:
        parts.append("### Foundry Gas Report (from source)")
        parts.append(f"```\n{forge_report}\n```")
    else:
        parts.append("Forge (foundry) not available — install from https://book.getfoundry.sh/")
        parts.append("or use `cargo install --git https://github.com/foundry-rs/foundry --bins foundry-cli`")

    if project_path and _has_forge:
        is_foundry = os.path.isfile(os.path.join(project_path, "foundry.toml"))
        if not is_foundry:
            parent = os.path.dirname(project_path)
            if parent and os.path.isdir(os.path.join(parent, ".git")):
                is_foundry = True
        if is_foundry:
            report = run_forge_gas_report(project_path)
            if report:
                parts.append("### Foundry Gas Report (forge test --gas-report)")
                parts.append(f"```\n{report}\n```")

    return "\n".join(parts)
