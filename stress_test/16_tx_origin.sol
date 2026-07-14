// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ============================================================
// Vulnerability: tx.origin Authentication (Phishing)
// Famous in: Ethernaut Lv4, many real-world hacks
// ============================================================
contract TxOriginVuln {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // Vulnerability: tx.origin is the original sender, not the direct caller
    function withdrawAll(address payable to) external {
        require(tx.origin == owner, "Not owner");
        to.transfer(address(this).balance);
    }

    // Exploit: user interacts with malicious contract which calls this
    // tx.origin = user, msg.sender = malicious contract -> bypass!
}