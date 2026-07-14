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
        assert "contract A" in result

    def test_empty_code(self):
        assert truncate_code("", "deepseek-chat") == ""

    def _long_contract_with(self, keyword: str) -> str:
        return (
            "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
            "contract Vulnerable {\n"
            "    mapping(address => uint) public balances;\n"
            "    uint[] public data;\n"
            "    address public immutable owner;\n"
            "    constructor() { owner = msg.sender; }\n"
            + keyword + "\n"
            + "".join(f"    uint private dummy_{i};\n" for i in range(5000))
            + "    function get() external view returns (uint) { return 1; }\n"
            + "}".rstrip()
        )

    def test_delegatecall_preserved_after_truncation(self):
        kw = "    function execute(address target) external { (bool ok,) = target.delegatecall{value: 0}(abi.encodeWithSignature(\"f()\")); require(ok); }"
        code = self._long_contract_with(kw)
        result = truncate_code(code)
        assert "delegatecall" in result
        assert "function body truncated" in result

    def test_selfdestruct_preserved_after_truncation(self):
        kw = "    function kill() external { selfdestruct(payable(owner)); }"
        code = self._long_contract_with(kw)
        result = truncate_code(code)
        assert "selfdestruct" in result
        assert "function body truncated" in result

    def test_tx_origin_preserved_after_truncation(self):
        kw = "    function setOwner(address _o) external { require(tx.origin == msg.sender); owner = _o; }"
        code = self._long_contract_with(kw)
        result = truncate_code(code)
        assert "tx.origin" in result
        assert "function body truncated" in result

    def test_token_transfer_preserved_after_truncation(self):
        kw = "    function withdraw(address token, uint amt) external { IERC20(token).transfer(msg.sender, amt); }"
        code = self._long_contract_with(kw)
        result = truncate_code(code)
        assert ".transfer(" in result
        assert "function body truncated" in result


class TestCacheStats:
    def test_cache_stats_format(self):
        stats = cache_stats()
        assert "enabled" in stats
        assert isinstance(stats.get("entries", 0), int)
