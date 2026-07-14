// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ============================================================
// Vulnerability: Missing Access Control (OnlyOwner pattern)
// ============================================================
contract NoAccessControl {
    mapping(address => uint256) public balances;
    uint256 public totalFees;

    // Vulnerability: no onlyOwner — anyone can set fees
    function setFees(uint256 _fee) external {
        totalFees = _fee;
    }

    // Vulnerability: anyone can pause the contract
    bool public paused;
    function setPaused(bool _paused) external {
        paused = _paused;
    }

    // Vulnerability: anyone can upgrade (no auth)
    address public logic;
    function upgradeTo(address _newLogic) external {
        logic = _newLogic;
    }

    modifier whenNotPaused() {
        require(!paused, "Paused");
        _;
    }
}