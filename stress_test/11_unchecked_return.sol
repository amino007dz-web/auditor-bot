// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ============================================================
// Vulnerability: Unchecked Return Value (DeFi bridge hack)
// ============================================================
interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

contract Bridge {
    mapping(address => uint256) public deposited;
    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    function deposit(uint256 amount) external {
        require(token.transferFrom(msg.sender, address(this), amount), "TransferFrom failed");
        deposited[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external {
        require(deposited[msg.sender] >= amount, "Insufficient");

        // Vulnerability: unchecked return value!
        token.transfer(msg.sender, amount);

        deposited[msg.sender] -= amount;
    }

    // Exploit: use a token that returns false on failed transfer
    // but the return value is ignored — attacker gets free withdrawal
}