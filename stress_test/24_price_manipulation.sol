// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ============================================================
// Vulnerability: Price Manipulation via Flash Loan (DeFi 2022)
// Famous in: Alpha Finance hack $37M, Cream Finance $130M
// ============================================================
interface IUniswapV2Pair {
    function getReserves() external view returns (uint112, uint112, uint32);
    function swap(uint256, uint256, address, bytes calldata) external;
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

contract PriceManipulationVuln {
    IUniswapV2Pair public pair;
    IERC20 public token;

    function getPrice() public view returns (uint256) {
        // Vulnerability: uses spot price from single Uniswap pair
        (uint112 reserve0, uint112 reserve1, ) = pair.getReserves();
        return (reserve1 * 1e18) / reserve0;
    }

    function borrow(uint256 amount) external {
        // Vulnerability: uses oracle without TWAP
        uint256 price = getPrice();
        uint256 collateralValue = IERC20(token).balanceOf(msg.sender);
        require(collateralValue >= amount * price / 1e18, "Low collateral");

        // Exploit: flash loan manipulates pair reserves,
        // getPrice() returns manipulated value -> borrow unfair amount
        IERC20(token).transfer(msg.sender, amount);
    }
}