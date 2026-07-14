// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ============================================================
// Vulnerability: Public Mint / Unchecked Access (Token)
// ============================================================
contract VulnerableERC20 {
    string public name = "VulnToken";
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowances;
    uint256 public totalSupply;

    // Vulnerability: no onlyOwner modifier — anyone can mint
    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balances[to] += amount;
    }

    // Vulnerability: no burn protection
    function burn(address from, uint256 amount) external {
        totalSupply -= amount;
        balances[from] -= amount;
    }

    // Vulnerability: approve front-running (race condition)
    function approve(address spender, uint256 amount) external returns (bool) {
        allowances[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(allowances[from][msg.sender] >= amount, "No allowance");
        allowances[from][msg.sender] -= amount;
        balances[from] -= amount;
        balances[to] += amount;
        return true;
    }
}