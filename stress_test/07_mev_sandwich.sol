// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ============================================================
// Vulnerability: Sandwich Attack (MEV / DeFi Hack 2023)
// ============================================================
interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
}

contract SimpleAMM {
    IERC20 public token0;
    IERC20 public token1;
    uint256 public reserve0;
    uint256 public reserve1;

    constructor(address _t0, address _t1) {
        token0 = IERC20(_t0);
        token1 = IERC20(_t1);
    }

    function swap(uint256 amountIn, address tokenIn) external returns (uint256 amountOut) {
        require(tokenIn == address(token0) || tokenIn == address(token1), "Invalid token");

        // Vulnerability: no slippage control or deadline
        if (tokenIn == address(token0)) {
            amountOut = (amountIn * reserve1) / (reserve0 + amountIn);
            reserve0 += amountIn;
            reserve1 -= amountOut;
        } else {
            amountOut = (amountIn * reserve0) / (reserve1 + amountIn);
            reserve1 += amountIn;
            reserve0 -= amountOut;
        }
        require(amountOut > 0, "Insufficient output");
        token1.transferFrom(msg.sender, address(this), amountIn);
        token0.transfer(msg.sender, amountOut);
    }

    function skim() external {
        // Vulnerability: where sandwich attack happens
    }

    function getReserves() external view returns (uint256, uint256) {
        return (reserve0, reserve1);
    }
}