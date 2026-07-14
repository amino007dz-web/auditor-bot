// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ============================================================
// Vulnerability: Flash Loan Attack (DeFi 2022)
// ============================================================
interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

contract FlashLoanPool {
    IERC20 public token;
    uint256 public protocolFee = 100; // 1%

    constructor(address _token) {
        token = IERC20(_token);
    }

    function flashLoan(uint256 amount, address borrower, address target) external {
        uint256 balanceBefore = token.balanceOf(address(this));
        require(token.transfer(borrower, amount), "Transfer failed");

        (bool success, ) = target.call(abi.encodeWithSignature("execute()"));
        require(success, "Callback failed");

        uint256 balanceAfter = token.balanceOf(address(this));
        uint256 fee = (amount * protocolFee) / 10000;
        require(balanceAfter >= balanceBefore + fee, "Flash loan not repaid");
    }

    // Vulnerability: No reentrancy guard, attacker can manipulate pools
}