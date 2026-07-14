// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ============================================================
// Vulnerability: Front-running (MEV Race)
// ============================================================
contract FrontRunVulnerable {
    address public owner;
    uint256 public salePrice;
    bool public sold;

    constructor() {
        owner = msg.sender;
    }

    function setPrice(uint256 _price) external {
        require(msg.sender == owner, "Not owner");
        salePrice = _price;
    }

    function buy() external payable {
        // Vulnerability: tx visible in mempool — front-runnable
        require(!sold, "Already sold");
        require(msg.value >= salePrice, "Low price");
        sold = true;
        payable(owner).transfer(msg.value);
        // Exploit: miner sees buy() tx in mempool, inserts own buy() first
    }

    function claimRefund() external {
        // Vulnerability: signature replay without nonce
        // (simplified — any user could forge)
    }
}