// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ============================================================
// Vulnerability: Oracle Manipulation (DeFi 2022)
// ============================================================
interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transferFrom(address, address, uint256) external returns (bool);
}

contract LendingPool {
    IERC20 public token;
    uint256 public collateralRatio = 150; // 150%

    function getCollateral(address user) public view returns (uint256) {
        // Vulnerability: uses spot price from single AMM pool
        uint256 price = getSpotPrice();
        return token.balanceOf(user) * price / 1e18;
    }

    function getSpotPrice() public view returns (uint256) {
        // Vulnerability: TWAP not used, flash loan can manipulate
        return 1000e18; // Simplified: actual implementation vulnerable
    }

    function liquidate(address user) external {
        uint256 collateral = getCollateral(user);
        require(collateral < 100e18, "Safe");
        token.transferFrom(user, msg.sender, 100e18);
    }

    // Exploit: flash loan manipulates spot price -> user gets liquidated unfairly
}