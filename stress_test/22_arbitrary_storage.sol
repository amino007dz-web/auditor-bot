// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ============================================================
// Vulnerability: Arbitrary Storage Write (Delegatecall exploit)
// Famous in: Parity wallet hack $300M, various proxy hacks
// ============================================================
contract StorageExploit {
    address public owner;
    mapping(bytes32 => uint256) public data;

    // Vulnerability: no bounds check — writes to any storage slot
    function writeStorage(bytes32 slot, uint256 value) external {
        assembly {
            sstore(slot, value)
        }
        // Exploit: sstore(0, attacker_address) overwrites owner
    }

    function withdraw() external payable {
        require(msg.sender == owner, "Not owner");
        payable(owner).transfer(address(this).balance);
    }
}