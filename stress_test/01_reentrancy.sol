// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ============================================================
// Vulnerability: Reentrancy (Ethernaut Lv10 / DeFi 2023)
// ============================================================
contract ReentrancyVictim {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 _amount) external {
        require(balances[msg.sender] >= _amount, "Insufficient balance");
        (bool success, ) = msg.sender.call{value: _amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= _amount;
    }

    // Exploit: attacker contract calls withdraw() recursively via fallback
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}