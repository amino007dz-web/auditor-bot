import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from agents import truncate_code, cache_stats


class TestTruncateCode:
    def test_short_code_no_truncation(self):
        code = "contract A { uint x; }"
        result = truncate_code(code, "deepseek-chat")
        assert result == code

    def test_long_code_truncation(self):
        code = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract A {\n" + "    uint x;\n" * 100000 + "\n}"
        result = truncate_code(code, "deepseek-chat")
        assert len(result) < len(code)

    def test_empty_code(self):
        assert truncate_code("", "deepseek-chat") == ""


class TestCacheStats:
    def test_cache_stats_format(self):
        stats = cache_stats()
        assert "enabled" in stats
        assert isinstance(stats.get("entries", 0), int)
