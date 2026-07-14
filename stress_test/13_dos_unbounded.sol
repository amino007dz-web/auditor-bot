// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ============================================================
// Vulnerability: Denial of Service (Gas griefing — Unbounded loop)
// ============================================================
contract UnboundedLoop {
    address[] public users;

    function addUser(address user) external {
        users.push(user);
    }

    // Vulnerability: this loops over ALL users — O(n) gas cost grows
    function processAll() external {
        for (uint256 i = 0; i < users.length; i++) {
            // Some gas-heavy operation per user
            uint256 result = uint256(keccak256(abi.encodePacked(users[i], block.timestamp)));
            assembly { sstore(0, result) }
        }
        // After many users, this will hit block gas limit and fail
    }

    function distribute() external {
        for (uint256 i = 0; i < users.length; i++) {
            payable(users[i]).transfer(1e15);
        }
        // DoS: if one user reverts via malicious fallback, ALL transfers fail
    }
}