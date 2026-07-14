// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ============================================================
// Vulnerability: Delegatecall Mutable Address (Parity 2017)
// ============================================================
contract Lib {
    address public owner;
    function setOwner(address _owner) public {
        owner = _owner;
    }
}

contract ProxyWallet {
    address public owner;
    address public implementation;
    bool public initialized;

    function init(address _impl) external {
        require(!initialized, "Already initialized");
        owner = msg.sender;
        implementation = _impl;
        initialized = true;
    }

    fallback() external payable {
        // Vulnerability: delegatecall to mutable implementation
        (bool success, ) = implementation.delegatecall(msg.data);
        require(success, "Delegatecall failed");
    }

    // Vulnerability: no upgrade protection, anyone can change implementation
}