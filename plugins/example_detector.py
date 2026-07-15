"""Example custom detector plugin."""

import re
from analyzers.plugin_system import BaseDetector, DetectorResult


class UncheckedExternalCallDetector(BaseDetector):
    name = "unchecked_external_calls"
    description = "Detects low-level calls without return value checks"
    version = "1.0.0"

    def detect(self, code: str) -> list:
        results = []
        pattern = re.compile(r"\.call\{[^}]*\}\([^)]*\)\s*;")
        for i, line in enumerate(code.split("\n"), 1):
            if pattern.search(line) and "require" not in line and "if" not in line:
                results.append(DetectorResult(
                    name=self.name,
                    severity="Medium",
                    description="Unchecked external call without return value validation",
                    lines=[i],
                    confidence=0.85,
                ))
        return results
