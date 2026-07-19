"""
Fetch source code of smart contracts from chain explorers (Etherscan, Basescan, etc.)
"""
import json
import logging
import os
import re
import time
from typing import Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

# Supports 10 major chains — add any new chain here
CHAIN_CONFIG: Dict[str, Dict] = {
    "ethereum":  {"api_url": "https://api.etherscan.io/api",          "explorer": "Etherscan"},
    "bsc":       {"api_url": "https://api.bscscan.com/api",           "explorer": "BscScan"},
    "polygon":   {"api_url": "https://api.polygonscan.com/api",       "explorer": "PolygonScan"},
    "arbitrum":  {"api_url": "https://api.arbiscan.io/api",           "explorer": "ArbiScan"},
    "optimism":  {"api_url": "https://api-optimistic.etherscan.io/api","explorer": "OptimisticScan"},
    "avalanche": {"api_url": "https://api.snowtrace.io/api",          "explorer": "SnowTrace"},
    "base":      {"api_url": "https://api.basescan.org/api",          "explorer": "BaseScan"},
    "celo":      {"api_url": "https://api.celoscan.io/api",           "explorer": "CeloScan"},
    "gnosis":    {"api_url": "https://api.gnosisscan.io/api",         "explorer": "GnosisScan"},
    "scroll":    {"api_url": "https://api.scrollscan.com/api",        "explorer": "ScrollScan"},
}

ETHERSCAN_API_KEY: str = os.getenv("ETHERSCAN_API_KEY", "YourApiKeyToken")


def _fetch_abi_source(api_url: str, address: str, apikey: str) -> Optional[Dict]:
    """Fetch source code + ABI from explorer API."""
    params = {
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": apikey,
    }
    try:
        r = requests.get(api_url, params=params, timeout=30)
        data = r.json()
        if data.get("status") != "1":
            logger.warning(f"API returned: {data.get('message', 'unknown')}")
            return None
        result = data.get("result", [{}])[0]
        return result
    except requests.Timeout:
        logger.warning(f"Timeout fetching {address}")
        return None
    except Exception as e:
        logger.warning(f"Failed to fetch {address}: {e}")
        return None


def load_from_explorer(address: str, chain: str = "ethereum",
                       api_key: str = "") -> Optional[Dict]:
    """Fetch contract from explorer. Returns {name, code, compiler, ...} or None."""
    chain = chain.lower()
    cfg = CHAIN_CONFIG.get(chain)
    if not cfg:
        logger.error(f"Unsupported chain: {chain}. Choose from: {', '.join(CHAIN_CONFIG.keys())}")
        return None

    if not re.match(r'^0x[a-fA-F0-9]{40}$', address):
        logger.error(f"Invalid address: {address}")
        return None

    apikey = api_key or ETHERSCAN_API_KEY
    result = _fetch_abi_source(cfg["api_url"], address, apikey)
    if not result:
        return None

    source_code = result.get("SourceCode", "")
    if not source_code or not source_code.strip():
        logger.warning(f"Contract {address} is not verified on {cfg['explorer']}")
        return None
    # Etherscan sometimes wraps code in {{...}} for multi-file contracts
    if source_code.startswith("{{") and source_code.endswith("}}"):
        try:
            parsed = json.loads(source_code[1:-1])
            sources = parsed.get("sources", {})
            combined = ""
            for fpath, fdata in sources.items():
                content = fdata.get("content", "")
                combined += f"\n\n// File: {fpath}\n{content}"
            source_code = combined.strip()
        except (json.JSONDecodeError, AttributeError):
            source_code = source_code.strip("{}").strip()

    contract_name = result.get("ContractName", "Unknown")
    compiler = result.get("CompilerVersion", "")
    abi_raw = result.get("ABI", "")
    try:
        abi = json.loads(abi_raw) if isinstance(abi_raw, str) else abi_raw
    except (json.JSONDecodeError, TypeError):
        abi = []

    return {
        "name": contract_name,
        "code": source_code,
        "compiler": compiler,
        "abi": abi,
        "chain": chain,
        "address": address,
        "explorer": cfg["explorer"],
    }


def list_supported_chains() -> str:
    return ", ".join(f"{k} ({v['explorer']})" for k, v in CHAIN_CONFIG.items())
