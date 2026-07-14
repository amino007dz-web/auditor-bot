// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ============================================================
// Vulnerability: Integer Overflow (Pre-Solidity 0.8) 
// ============================================================
contract OverflowBank {
    mapping(address => uint256) public balances;

    function deposit(uint256 amount) external {
        // Vulnerability: overflow can wrap totalBalance
        balances[msg.sender] += amount;
    }

    function transfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "No funds");
        balances[msg.sender] -= amount;
        // Vulnerability: underflow — max uint if amount > balance
        balances[to] += amount;
    }

    function withdrawAll() external {
        // Vulnerability: can drain if we overflow the addition
        uint256 amount = balances[msg.sender];
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Failed");
        balances[msg.sender] = 0;
    }
}