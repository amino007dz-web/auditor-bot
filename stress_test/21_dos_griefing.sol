// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ============================================================
// Vulnerability: Denial of Service via Revert (Gas griefing)
// Famous in: ENS auction, many NFT contracts
// ============================================================
contract DOSGriefing {
    address[] public participants;

    function join() external payable {
        require(msg.value == 0.1 ether, "Send 0.1 ETH");
        participants.push(msg.sender);
    }

    function distribute() external {
        // Vulnerability: single participant's revert blocks ALL payments
        for (uint256 i = 0; i < participants.length; i++) {
            payable(participants[i]).transfer(0.1 ether);
            // If participants[i] is a contract with a malicious receive()
            // that reverts, the entire distribution fails permanently
        }
    }

    function forceWithdraw(uint256 index) external {
        // Vulnerability: attacker can block specific user
        payable(participants[index]).transfer(0.1 ether);
    }
}