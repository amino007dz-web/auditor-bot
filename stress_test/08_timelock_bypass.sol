// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ============================================================
// Vulnerability: Access Control — Timelock Bypass (Compound fork)
// ============================================================
contract TimelockController {
    address public admin;
    uint256 public delay = 3 days;
    mapping(bytes32 => bool) public queued;
    uint256 public queueNonce;

    constructor() {
        admin = msg.sender;
    }

    function queue(address target, uint256 value, bytes calldata data) external returns (bytes32) {
        // Vulnerability: no access control — anyone can queue
        bytes32 txHash = keccak256(abi.encode(target, value, data, queueNonce++));
        queued[txHash] = true;
        return txHash;
    }

    function execute(address target, uint256 value, bytes calldata data) external returns (bytes memory) {
        // Vulnerability: anyone can execute without queuing and delay!
        (bool success, bytes memory result) = target.call{value: value}(data);
        require(success, "Call failed");
        return result;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    // Exploit: attacker calls execute() immediately with arbitrary calldata
}