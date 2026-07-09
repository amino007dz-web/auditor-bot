from .base import Finding, Agent, LanguageAnalyzer, detect_language
from .solidity_analyzer import SolidityAnalyzer
from .chialisp_analyzer import ChialispAnalyzer
from .move_analyzer import MoveAnalyzer
from .vyper_analyzer import VyperAnalyzer

ANALYZERS = {
    "solidity": SolidityAnalyzer(),
    "chialisp": ChialispAnalyzer(),
    "move": MoveAnalyzer(),
    "vyper": VyperAnalyzer(),
}

def get_analyzer(lang: str) -> LanguageAnalyzer:
    return ANALYZERS.get(lang)

def list_languages() -> list:
    return list(ANALYZERS.keys())
