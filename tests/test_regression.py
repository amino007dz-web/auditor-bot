"""Regression tests — verify auditor catches known vulnerabilities from Damn Vulnerable DeFi v4."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from unittest.mock import patch

from agents.pre_scan import run_pre_scan
from bug_detector import get_summary

# ---------------------------------------------------------------------------
# Real contracts from Damn Vulnerable DeFi v4
# Source: https://github.com/theredguild/damn-vulnerable-defi/tree/v4.0.0
# ---------------------------------------------------------------------------

DVDF_CONTRACTS = {
    "unstoppable_vault": """// SPDX-License-Identifier: MIT
pragma solidity =0.8.25;
import {ReentrancyGuard} from "solady/utils/ReentrancyGuard.sol";
import {FixedPointMathLib} from "solmate/utils/FixedPointMathLib.sol";
import {Owned} from "solmate/auth/Owned.sol";
import {SafeTransferLib, ERC4626, ERC20} from "solmate/tokens/ERC4626.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {IERC3156FlashBorrower, IERC3156FlashLender} from "@openzeppelin/contracts/interfaces/IERC3156.sol";
contract UnstoppableVault is IERC3156FlashLender, ReentrancyGuard, Owned, ERC4626, Pausable {
    using SafeTransferLib for ERC20;
    using FixedPointMathLib for uint256;
    uint256 public constant FEE_FACTOR = 0.05 ether;
    uint64 public constant GRACE_PERIOD = 30 days;
    uint64 public immutable end = uint64(block.timestamp) + GRACE_PERIOD;
    address public feeRecipient;
    error InvalidAmount(uint256 amount);
    error InvalidBalance();
    error CallbackFailed();
    error UnsupportedCurrency();
    event FeeRecipientUpdated(address indexed newFeeRecipient);
    constructor(ERC20 _token, address _owner, address _feeRecipient)
        ERC4626(_token, "Too Damn Valuable Token", "tDVT")
        Owned(_owner)
    {
        feeRecipient = _feeRecipient;
        emit FeeRecipientUpdated(_feeRecipient);
    }
    function maxFlashLoan(address _token) public view nonReadReentrant returns (uint256) {
        if (address(asset) != _token) return 0;
        return totalAssets();
    }
    function flashFee(address _token, uint256 _amount) public view returns (uint256 fee) {
        if (address(asset) != _token) revert UnsupportedCurrency();
        if (block.timestamp < end && _amount < maxFlashLoan(_token)) return 0;
        else return _amount.mulWadUp(FEE_FACTOR);
    }
    function totalAssets() public view override nonReadReentrant returns (uint256) {
        return asset.balanceOf(address(this));
    }
    function flashLoan(IERC3156FlashBorrower receiver, address _token, uint256 amount, bytes calldata data)
        external returns (bool)
    {
        if (amount == 0) revert InvalidAmount(0);
        if (address(asset) != _token) revert UnsupportedCurrency();
        uint256 balanceBefore = totalAssets();
        if (convertToShares(totalSupply) != balanceBefore) revert InvalidBalance();
        ERC20(_token).safeTransfer(address(receiver), amount);
        uint256 fee = flashFee(_token, amount);
        if (receiver.onFlashLoan(msg.sender, address(asset), amount, fee, data)
                != keccak256("IERC3156FlashBorrower.onFlashLoan")) {
            revert CallbackFailed();
        }
        ERC20(_token).safeTransferFrom(address(receiver), address(this), amount + fee);
        ERC20(_token).safeTransfer(feeRecipient, fee);
        return true;
    }
    function beforeWithdraw(uint256 assets, uint256 shares) internal override nonReentrant {}
    function afterDeposit(uint256 assets, uint256 shares) internal override nonReentrant whenNotPaused {}
    function setFeeRecipient(address _feeRecipient) external onlyOwner {
        if (_feeRecipient != address(this)) {
            feeRecipient = _feeRecipient;
            emit FeeRecipientUpdated(_feeRecipient);
        }
    }
    function execute(address target, bytes memory data) external onlyOwner whenPaused {
        (bool success,) = target.delegatecall(data);
        require(success);
    }
    function setPause(bool flag) external onlyOwner {
        if (flag) _pause();
        else _unpause();
    }
}""",

    "naive_receiver_pool": """// SPDX-License-Identifier: MIT
pragma solidity =0.8.25;
import {IERC3156FlashLender} from "@openzeppelin/contracts/interfaces/IERC3156FlashLender.sol";
import {IERC3156FlashBorrower} from "@openzeppelin/contracts/interfaces/IERC3156FlashBorrower.sol";
import {Multicall} from "./Multicall.sol";
import {WETH} from "solmate/tokens/WETH.sol";
contract NaiveReceiverPool is Multicall, IERC3156FlashLender {
    uint256 private constant FIXED_FEE = 1e18;
    bytes32 private constant CALLBACK_SUCCESS = keccak256("ERC3156FlashBorrower.onFlashLoan");
    WETH public immutable weth;
    address public immutable trustedForwarder;
    address public immutable feeReceiver;
    mapping(address => uint256) public deposits;
    uint256 public totalDeposits;
    error RepayFailed();
    error UnsupportedCurrency();
    error CallbackFailed();
    constructor(address _trustedForwarder, address payable _weth, address _feeReceiver) payable {
        weth = WETH(_weth);
        trustedForwarder = _trustedForwarder;
        feeReceiver = _feeReceiver;
        _deposit(msg.value);
    }
    function maxFlashLoan(address token) external view returns (uint256) {
        if (token == address(weth)) return weth.balanceOf(address(this));
        return 0;
    }
    function flashFee(address token, uint256) external view returns (uint256) {
        if (token != address(weth)) revert UnsupportedCurrency();
        return FIXED_FEE;
    }
    function flashLoan(IERC3156FlashBorrower receiver, address token, uint256 amount, bytes calldata data)
        external returns (bool)
    {
        if (token != address(weth)) revert UnsupportedCurrency();
        weth.transfer(address(receiver), amount);
        totalDeposits -= amount;
        if (receiver.onFlashLoan(msg.sender, address(weth), amount, FIXED_FEE, data) != CALLBACK_SUCCESS) {
            revert CallbackFailed();
        }
        uint256 amountWithFee = amount + FIXED_FEE;
        weth.transferFrom(address(receiver), address(this), amountWithFee);
        totalDeposits += amountWithFee;
        deposits[feeReceiver] += FIXED_FEE;
        return true;
    }
    function withdraw(uint256 amount, address payable receiver) external {
        deposits[_msgSender()] -= amount;
        totalDeposits -= amount;
        weth.transfer(receiver, amount);
    }
    function deposit() external payable { _deposit(msg.value); }
    function _deposit(uint256 amount) private {
        weth.deposit{value: amount}();
        deposits[_msgSender()] += amount;
        totalDeposits += amount;
    }
    function _msgSender() internal view override returns (address) {
        if (msg.sender == trustedForwarder && msg.data.length >= 20) {
            return address(bytes20(msg.data[msg.data.length - 20:]));
        } else {
            return super._msgSender();
        }
    }
}""",

    "truster_pool": """// SPDX-License-Identifier: MIT
pragma solidity =0.8.25;
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {DamnValuableToken} from "../DamnValuableToken.sol";
contract TrusterLenderPool is ReentrancyGuard {
    using Address for address;
    DamnValuableToken public immutable token;
    error RepayFailed();
    constructor(DamnValuableToken _token) { token = _token; }
    function flashLoan(uint256 amount, address borrower, address target, bytes calldata data)
        external nonReentrant returns (bool)
    {
        uint256 balanceBefore = token.balanceOf(address(this));
        token.transfer(borrower, amount);
        target.functionCall(data);
        if (token.balanceOf(address(this)) < balanceBefore) revert RepayFailed();
        return true;
    }
}""",

    "side_entrance_pool": """// SPDX-License-Identifier: MIT
pragma solidity =0.8.25;
import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";
interface IFlashLoanEtherReceiver {
    function execute() external payable;
}
contract SideEntranceLenderPool {
    mapping(address => uint256) public balances;
    error RepayFailed();
    event Deposit(address indexed who, uint256 amount);
    event Withdraw(address indexed who, uint256 amount);
    function deposit() external payable {
        unchecked { balances[msg.sender] += msg.value; }
        emit Deposit(msg.sender, msg.value);
    }
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        delete balances[msg.sender];
        emit Withdraw(msg.sender, amount);
        SafeTransferLib.safeTransferETH(msg.sender, amount);
    }
    function flashLoan(uint256 amount) external {
        uint256 balanceBefore = address(this).balance;
        IFlashLoanEtherReceiver(msg.sender).execute{value: amount}();
        if (address(this).balance < balanceBefore) revert RepayFailed();
    }
}""",
}

MOCK_REPORT = """## Security Analysis Report
### Critical: Vulnerability detected
- Severity: Critical (CVSS 9.8)
- Description: A critical security issue was identified
- Fix: Apply standard security patterns
"""


class TestVulnerableContracts:
    """Pre-scan detectors catch known vulnerabilities in DVDF contracts."""

    @patch("agents.llm_client._call_ollama", return_value=MOCK_REPORT)
    def test_pre_scan_does_not_crash(self, _mock):
        code = DVDF_CONTRACTS["side_entrance_pool"]
        result = run_pre_scan(code)
        assert result is not None

    def test_bug_detector_returns_results(self):
        for name in DVDF_CONTRACTS:
            code = DVDF_CONTRACTS[name]
            summary = get_summary(code)
            assert isinstance(summary, list), f"get_summary failed for {name}"
            assert len(summary) > 0, f"No patterns found in {name}"

    def test_reentrancy_in_side_entrance(self):
        code = DVDF_CONTRACTS["side_entrance_pool"]
        summary = get_summary(code)
        names = [d.get("name", "") for d in summary]
        assert any("reentrancy" in n.lower() for n in names), (
            f"SideEntrance reentrancy not detected. Found: {names}"
        )

    def test_arbitrary_call_in_truster(self):
        code = DVDF_CONTRACTS["truster_pool"]
        summary = get_summary(code)
        names = [d.get("name", "") for d in summary]
        assert any("arbitrary" in n.lower() or "call" in n.lower() for n in names), (
            f"Truster arbitrary call not detected. Found: {names}"
        )

    def test_flash_loan_in_naive_receiver(self):
        code = DVDF_CONTRACTS["naive_receiver_pool"]
        summary = get_summary(code)
        names = [d.get("name", "") for d in summary]
        assert any("flash loan" in n.lower() for n in names)

    def test_erc4626_vault_in_unstoppable(self):
        code = DVDF_CONTRACTS["unstoppable_vault"]
        summary = get_summary(code)
        names = [d.get("name", "") for d in summary]
        assert any("erc4626" in n.lower() for n in names), (
            f"UnstoppableVault not flagged as ERC4626 bug. Found: {names}"
        )


class TestPatternLearner:
    """Static tests for pattern learner without LLM calls."""

    def test_extract_json_with_fences(self):
        from agents.pattern_learner import _extract_json
        text = '```json\n[{"name": "test"}]\n```'
        assert _extract_json(text) == '[{"name": "test"}]'

    def test_extract_json_bare(self):
        from agents.pattern_learner import _extract_json
        assert _extract_json('[{"a":1}]') == '[{"a":1}]'

    def test_extract_json_empty(self):
        from agents.pattern_learner import _extract_json
        assert _extract_json("") == ""
        assert _extract_json("no json here") == ""

    def test_load_save_learned(self):
        import tempfile, os, json
        from agents.pattern_learner import LEARNED_PATTERNS_PATH
        orig_path = LEARNED_PATTERNS_PATH
        test_path = os.path.join(tempfile.gettempdir(), "test_learned.json")
        import agents.pattern_learner as pl
        pl.LEARNED_PATTERNS_PATH = test_path
        try:
            # save
            pl._save_learned([{"name": "TestBug", "description": "desc", "severity": "High", "patterns": ["test"]}])
            # load
            loaded = pl._load_learned()
            assert len(loaded) == 1
            assert loaded[0]["name"] == "TestBug"
            # patterns_text
            txt = pl.patterns_text()
            assert "TestBug" in txt
            # get_learned_bug_classes
            classes = pl.get_learned_bug_classes()
            assert "learned_0" in classes
        finally:
            pl.LEARNED_PATTERNS_PATH = orig_path
            if os.path.isfile(test_path):
                os.remove(test_path)


class TestASTDetector:
    """Level 2 AST semantic analysis tests with self-contained contracts."""

    CEI_CONTRACT = '''pragma solidity ^0.8.0;
contract C {
    mapping(address => uint) public balances;
    function withdraw(uint amt) external {
        (bool ok,) = msg.sender.call{value: amt}("");
        balances[msg.sender] -= amt;
    }
}'''

    FLASH_LOAN_CONTRACT = '''pragma solidity ^0.8.0;
interface IFlashBorrower { function onFlashLoan(address,uint,uint) external returns (bytes32); }
contract Pool {
    function flashLoan(address receiver, uint amount) external {
        (bool ok,) = receiver.call{value: amount}("");
        require(IFlashBorrower(receiver).onFlashLoan(msg.sender, amount, 0) == keccak256("OK"));
    }
}'''

    ARB_CALL_CONTRACT = '''pragma solidity ^0.8.0;
contract Router {
    function execute(address target, bytes calldata data) external {
        (bool ok,) = target.call(data);
        require(ok);
    }
}'''

    def test_cei_violation(self):
        from agents.ast_detector import analyze_ast
        result = analyze_ast(self.CEI_CONTRACT)
        assert result and "CEI Violation" in result

    def test_unprotected_flash_loan(self):
        from agents.ast_detector import analyze_ast
        result = analyze_ast(self.FLASH_LOAN_CONTRACT)
        assert result and "Unprotected Flash Loan Receiver" in result

    def test_arbitrary_call_ast(self):
        from agents.ast_detector import analyze_ast
        result = analyze_ast(self.ARB_CALL_CONTRACT)
        assert result and "Arbitrary External Call" in result

    def test_safe_contract_no_ast_findings(self):
        from agents.ast_detector import analyze_ast
        code = '''pragma solidity ^0.8.0;
contract Safe {
    uint public x;
    function set(uint _x) external { x = _x; }
    function get() external view returns (uint) { return x; }
}'''
        assert analyze_ast(code) == ""

    def test_ast_detector_not_crash_on_invalid(self):
        from agents.ast_detector import analyze_ast
        assert analyze_ast("not solidity code") == ""
        assert analyze_ast("") == ""


class TestEdgeCases:
    """Edge case tests."""

    def test_empty_code(self):
        assert get_summary("") == []

    def test_no_contract(self):
        assert isinstance(get_summary("// just a comment"), list)

    def test_simple_storage_no_false_positive(self):
        code = "contract Store { uint public x; function set(uint _x) public { x = _x; } }"
        summary = get_summary(code)
        critical = [d for d in summary if d.get("severity_hint", "") == "Critical"]
        assert len(critical) == 0
