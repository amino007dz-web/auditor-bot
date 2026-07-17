import os, re, json, logging, tempfile
from typing import Optional, List, Dict
from analyzers.base import Finding

logger = logging.getLogger(__name__)

BYTECODE_PATTERNS = {
    "selfdestruct": re.compile(r"selfdestruct|suicide", re.I),
    "delegatecall": re.compile(r"delegatecall|delegate_call", re.I),
    "call_value": re.compile(r"call\.value|callvalue", re.I),
    "timestamp": re.compile(r"timestamp|TIMESTAMP", re.I),
    "tx_origin": re.compile(r"tx\.origin|txorigin|ORIGIN", re.I),
    "assembly": re.compile(r"assembly\s*\{", re.I),
    "unchecked_send": re.compile(r"call\.send|\.send\(", re.I),
}

Opcodes = {
    "SELFDESTRUCT": "0xFF",
    "DELEGATECALL": "0xF4",
    "CALL": "0xF1",
    "CALLCODE": "0xF2",
    "TIMESTAMP": "0x42",
    "NUMBER": "0x43",
    "GASLIMIT": "0x45",
    "BLOCKHASH": "0x40",
    "ORIGIN": "0x32",
    "ADDRESS": "0x30",
    "SLOAD": "0x54",
    "SSTORE": "0x55",
    "SELFBALANCE": "0x47",
}


def _parse_hex(bytecode: str) -> bytes:
    bc = bytecode.strip()
    if bc.startswith("0x"):
        bc = bc[2:]
    try:
        return bytes.fromhex(bc)
    except Exception:
        return b""


def _analyze_opcodes(raw: bytes) -> List[Dict]:
    findings = []
    for name, op in Opcodes.items():
        code = bytes.fromhex(op[2:]) if op.startswith("0x") else op.encode()
        if code in raw:
            findings.append({"opcode": name, "code": op})
    return findings


def _regex_scan(text: str) -> List[Dict]:
    findings = []
    for name, pattern in BYTECODE_PATTERNS.items():
        if pattern.search(text):
            findings.append({"pattern": name, "match": pattern.search(text).group()})
    return findings


def decompile_bytecode(bytecode: str) -> Optional[str]:
    try:
        import subprocess
        with tempfile.NamedTemporaryFile(suffix=".hex", delete=False, mode="w") as f:
            f.write(bytecode)
            f.flush()
            proc = subprocess.run(["panoramix", f.name], capture_output=True, text=True, timeout=30)
            os.unlink(f.name)
            if proc.returncode == 0:
                return proc.stdout[:3000]
    except FileNotFoundError:
        pass
    except Exception as e:
        logger.debug(f"Decompiler error: {e}")
    return None


def analyze_bytecode(bytecode: str, address: str = "") -> List[Finding]:
    findings = []
    raw = _parse_hex(bytecode)
    op_findings = _analyze_opcodes(raw) if raw else []
    text_findings = _regex_scan(bytecode)

    for op in op_findings:
        sev = "Critical" if op["opcode"] in ("SELFDESTRUCT", "DELEGATECALL") else "High"
        findings.append(Finding(
            agent_name=f"Opcode: {op['opcode']}",
            severity=sev,
            category="Bytecode Analysis",
            file=address or "unknown",
            function_name="",
            description=f"Bytecode contains {op['opcode']} ({op['code']})",
            fix=f"Remove {op['opcode']} from bytecode if not needed",
        ))

    for tf in text_findings:
        sev = "Critical" if tf["pattern"] in ("selfdestruct",) else "High"
        findings.append(Finding(
            agent_name=f"Pattern: {tf['pattern']}",
            severity=sev,
            category="Bytecode Pattern",
            file=address or "unknown",
            function_name="",
            description=f"Bytecode matches {tf['pattern']}: {tf['match']}",
            fix=f"Avoid {tf['pattern']} pattern",
        ))

    if not findings:
        findings.append(Finding(
            agent_name="No Critical Opcodes",
            severity="Info",
            category="Bytecode Analysis",
            file=address or "unknown",
            function_name="",
            description="No dangerous opcodes detected in bytecode",
            fix="",
        ))

    return findings


def analyze_contract_from_explorer(address: str) -> List[Finding]:
    try:
        import requests
        apikey = os.environ.get("ETHERSCAN_API_KEY", "")
        if not apikey:
            return []
        resp = requests.get("https://api.etherscan.io/api", params={
            "module": "contract", "action": "getsourcecode",
            "address": address, "apikey": apikey,
        }, timeout=15)
        data = resp.json()
        if data.get("status") != "1":
            return []
        src = data["result"][0]
        bytecode = src.get("Bytecode", "")
        if bytecode and bytecode != "0x":
            return analyze_bytecode(bytecode, address)
    except Exception as e:
        logger.warning(f"Explorer analysis failed: {e}")
    return []
