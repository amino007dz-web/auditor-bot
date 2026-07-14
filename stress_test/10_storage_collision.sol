// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ============================================================
// Vulnerability: Storage Collision (Proxy Pattern — USDT issue)
// ============================================================
contract LogicV1 {
    uint256 public value;
    bool public initialized;

    function set(uint256 _value) external {
        value = _value;
    }
}

contract LogicV2 {
    address public owner; // Collides with V1._value slot!
    uint256 public value;
    bool public initialized;

    function initialize(address _owner) external {
        require(!initialized, "Init");
        owner = _owner;
        initialized = true;
    }

    function set(uint256 _value) external {
        value = _value;
    }
}

contract Proxy {
    address public implementation;
    mapping(bytes4 => address) public delegates;

    fallback() payable external {
        // Vulnerability: delegates don't line up with storage
        address impl = delegates[msg.sig];
        require(impl != address(0), "No delegate");
        (bool success, ) = impl.delegatecall(msg.data);
        require(success, "Delegatecall failed");
    }
}