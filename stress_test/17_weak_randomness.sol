// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ============================================================
// Vulnerability: Weak Randomness (On-chain RNG)
// Famous in: Dice2Win, many gambling dApps hacks
// ============================================================
contract WeakRandom {
    uint256 public lastGuess;

    function guess(uint256 _number) external payable returns (bool) {
        require(msg.value == 0.1 ether, "Send 0.1 ETH");

        // Vulnerability: block.prevrandao (or difficulty) + timestamp are miner- manipulable
        uint256 random = uint256(keccak256(abi.encodePacked(
            block.timestamp, block.prevrandao, msg.sender
        ))) % 100;

        if (random == _number) {
            payable(msg.sender).transfer(1 ether);
            return true;
        }
        lastGuess = random;
        return false;
    }
}