"""Plugin system — allows custom Python detectors to be loaded dynamically."""

import importlib
import inspect
import logging
import os
import sys
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

ALLOW_DYNAMIC_PLUGINS = os.environ.get("ALLOW_DYNAMIC_PLUGINS", "false").lower() == "true"
PLUGIN_DIR = os.environ.get("PLUGIN_DIR", os.path.join(os.path.dirname(__file__), "..", "plugins"))
PLUGIN_ALLOWLIST = [".py"]

if not os.path.isdir(PLUGIN_DIR):
    os.makedirs(PLUGIN_DIR, exist_ok=True)
if PLUGIN_DIR not in sys.path:
    sys.path.insert(0, PLUGIN_DIR)


@dataclass
class DetectorResult:
    name: str
    severity: str
    description: str
    lines: Optional[List[int]] = None
    confidence: float = 0.8


class BaseDetector:
    """Base class for all custom detectors. Subclass and implement `detect(code: str) -> List[DetectorResult]`."""
    name: str = "base_detector"
    description: str = ""
    version: str = "1.0.0"

    def detect(self, code: str) -> List[DetectorResult]:
        raise NotImplementedError

    def info(self) -> dict:
        return {"name": self.name, "description": self.description, "version": self.version}


class PluginManager:
    """Loads and manages custom detector plugins from the plugins/ directory."""

    def __init__(self):
        self._detectors: Dict[str, BaseDetector] = {}
        self._loaded = False

    def load_plugins(self):
        if self._loaded:
            return
        self._loaded = True
        if not ALLOW_DYNAMIC_PLUGINS:
            logger.info("Dynamic plugins are disabled in production. Set ALLOW_DYNAMIC_PLUGINS=true to enable.")
            return
        if not os.path.isdir(PLUGIN_DIR):
            return
        for fname in sorted(os.listdir(PLUGIN_DIR)):
            fpath = os.path.join(PLUGIN_DIR, fname)
            if not os.path.isfile(fpath):
                continue
            if not any(fname.endswith(e) for e in PLUGIN_ALLOWLIST) or fname.startswith("_"):
                continue
            mod_name = fname[:-3]
            try:
                mod = importlib.import_module(mod_name)
                    for name, obj in inspect.getmembers(mod, inspect.isclass):
                        if issubclass(obj, BaseDetector) and obj is not BaseDetector:
                            instance = obj()
                            self._detectors[instance.name] = instance
                            logger.info(f"Loaded plugin detector: {instance.name} v{instance.version}")
                except Exception as e:
                    logger.warning(f"Failed to load plugin {mod_name}: {e}")

    def get_detectors(self) -> Dict[str, BaseDetector]:
        self.load_plugins()
        return dict(self._detectors)

    def run_all(self, code: str) -> List[DetectorResult]:
        results = []
        for name, detector in self.get_detectors().items():
            try:
                res = detector.detect(code)
                if res:
                    results.extend(res)
            except Exception as e:
                logger.warning(f"Plugin {name} failed: {e}")
        return results

    def list_plugins(self) -> List[dict]:
        return [d.info() for d in self.get_detectors().values()]


_plugin_manager = PluginManager()


def run_plugins(code: str) -> List[DetectorResult]:
    return _plugin_manager.run_all(code)


def list_plugins() -> List[dict]:
    return _plugin_manager.list_plugins()
