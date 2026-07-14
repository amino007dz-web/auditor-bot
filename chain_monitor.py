"""Chain Monitor - monitor on-chain contracts with notifications on update.
Supports Proxy Upgrade detection by comparing bytecode hash."""
import os
import json
import time
import hashlib
import logging
import threading
from typing import Optional, Callable

logger = logging.getLogger(__name__)

MONITOR_FILE = os.path.join(os.path.dirname(__file__), "monitor_state.json")


class MonitoredContract:
    def __init__(self, address: str, chain: str = "ethereum", interval: int = 3600,
                 api_key: str = "", label: str = ""):
        self.address = address
        self.chain = chain
        self.interval = interval
        self.api_key = api_key
        self.label = label or address[:10]
        self.last_hash = ""
        self.last_seen = 0

    def to_dict(self) -> dict:
        return {
            "address": self.address, "chain": self.chain,
            "interval": self.interval, "api_key": self.api_key,
            "label": self.label, "last_hash": self.last_hash,
            "last_seen": self.last_seen,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "MonitoredContract":
        mc = cls(d["address"], d.get("chain", "ethereum"),
                  d.get("interval", 3600), d.get("api_key", ""),
                  d.get("label", ""))
        mc.last_hash = d.get("last_hash", "")
        mc.last_seen = d.get("last_seen", 0)
        return mc


class ChainMonitor:
    """Monitor contracts on chain — checks for code changes."""

    def __init__(self, state_file: str = MONITOR_FILE):
        self.state_file = state_file
        self.contracts: list[MonitoredContract] = []
        self._load()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._on_change: Optional[Callable] = None

    def _load(self):
        if os.path.isfile(self.state_file):
            try:
                with open(self.state_file, encoding="utf-8") as f:
                    data = json.load(f)
                self.contracts = [MonitoredContract.from_dict(d) for d in data]
            except Exception as e:
                logger.warning(f"Failed to load monitor state: {e}")

    def _save(self):
        with open(self.state_file, "w", encoding="utf-8") as f:
            json.dump([c.to_dict() for c in self.contracts], f, indent=2)

    def add(self, address: str, chain: str = "ethereum", interval: int = 3600,
            api_key: str = "", label: str = ""):
        mc = MonitoredContract(address, chain, interval, api_key, label)
        self.contracts.append(mc)
        self._save()
        logger.info(f"Monitoring {address} on {chain}")

    def remove(self, address: str):
        self.contracts = [c for c in self.contracts if c.address != address]
        self._save()

    def list(self) -> list:
        return [c.to_dict() for c in self.contracts]

    def on_change(self, callback: Callable):
        """Set a callback function for when a contract changes."""
        self._on_change = callback

    def check(self):
        """Check all contracts for changes."""
        from chain_loader import load_from_explorer

        for mc in self.contracts:
            if time.time() - mc.last_seen < mc.interval:
                continue
            try:
                data = load_from_explorer(mc.address, mc.chain, mc.api_key)
                if not data:
                    continue
                new_hash = hashlib.sha256(data["code"].encode()).hexdigest()
                if mc.last_hash and mc.last_hash != new_hash:
                    logger.warning(f"⚠️ Contract changed: {mc.label} ({mc.address})")
                    if self._on_change:
                        self._on_change(mc, data["code"])
                mc.last_hash = new_hash
                mc.last_seen = time.time()
            except Exception as e:
                logger.warning(f"Check failed for {mc.address}: {e}")
        self._save()

    def fetch_bytecode_hash(self, contract: MonitoredContract) -> Optional[str]:
        import requests
        explorer = {"ethereum": "api.etherscan.io", "bsc": "api.bscscan.com",
                    "polygon": "api.polygonscan.com", "arbitrum": "api.arbiscan.io"}
        domain = explorer.get(contract.chain, "api.etherscan.io")
        url = f"https://{domain}/api?module=proxy&action=eth_getCode&address={contract.address}&apikey={contract.api_key}"
        try:
            resp = requests.get(url, timeout=15)
            data = resp.json()
            bytecode = data.get("result", "")
            if not bytecode or bytecode == "0x":
                return None
            return hashlib.sha256(bytecode.encode()).hexdigest()[:16]
        except Exception as e:
            logger.debug(f"Bytecode fetch failed for {contract.address}: {e}")
            return None

    def check_for_upgrade(self, contract: MonitoredContract) -> Optional[str]:
        current_hash = self.fetch_bytecode_hash(contract)
        if current_hash is None:
            return None
        if contract.last_hash and contract.last_hash != current_hash:
            old_hash = contract.last_hash
            contract.last_hash = current_hash
            contract.last_seen = time.time()
            self._save()
            return (f"⚠️ *Proxy Upgrade Detected*\n"
                    f"Contract: `{contract.address}` ({contract.label})\n"
                    f"Bytecode hash: `{old_hash[:8]} → {current_hash[:8]}`\n"
                    f"Chain: {contract.chain}\nTriggering re-audit...")
        if not contract.last_hash:
            contract.last_hash = current_hash
        contract.last_seen = time.time()
        return None

    def start(self, interval: int = 60):
        """Start periodic monitoring in background."""
        if self._running:
            return
        self._running = True

        def loop():
            while self._running:
                self.check()
                time.sleep(interval)

        self._thread = threading.Thread(target=loop, daemon=True)
        self._thread.start()
        logger.info("Chain monitor started")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)


_MONITOR = ChainMonitor()


def get_monitor() -> ChainMonitor:
    return _MONITOR
