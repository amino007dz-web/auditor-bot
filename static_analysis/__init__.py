"""
Static analysis package for smart contract auditing.

Provides opcode tracing, storage layout analysis, inheritance hierarchy
analysis, AST-based analysis, and combined reporting for Solidity contracts.
"""

__version__ = "1.0.0"

__all__ = [
    "analyze_opcodes",
    "OPCODE_PATTERNS",
    "analyze_storage_single",
    "analyze_inheritance",
    "generate_combined_report",
    "generate_combined_report_interactive",
    "analyze_storage_with_ast",
    "analyze_inheritance_with_ast",
    "generate_combined_ast_report",
    "AST_AVAILABLE",
]

from .opcode_tracer import analyze_opcodes, OPCODE_PATTERNS
from .storage_analyzer import analyze_storage_single, _extract_contracts_from_code
from .inheritance_analyzer import analyze_inheritance
from .combined_report import generate_combined_report, generate_combined_report_interactive
from .ast_analyzer import (
    analyze_storage_with_ast, analyze_inheritance_with_ast,
    generate_combined_ast_report, HAS_SOLCAST as AST_AVAILABLE,
)
