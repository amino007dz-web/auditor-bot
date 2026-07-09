"""Chain Monitor - monitor on-chain contracts with notifications on update."""
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
                with open(self.state_file) as f:
                    data = json.load(f)
                self.contracts = [MonitoredContract.from_dict(d) for d in data]
            except Exception as e:
                logger.warning(f"Failed to load monitor state: {e}")

    def _save(self):
        with open(self.state_file, "w") as f:
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
