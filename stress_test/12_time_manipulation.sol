// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ============================================================
// Vulnerability: Time Manipulation (RNG / DeFi hack)
// ============================================================
contract LotteryVuln {
    address public winner;
    uint256 public lastDraw;

    function draw() external {
        // Vulnerability: block.timestamp and block.difficulty are miner-manipulable
        uint256 pseudoRandom = uint256(keccak256(abi.encodePacked(
            block.timestamp, block.prevrandao, lastDraw
        )));
        if (pseudoRandom % 10 == 0) {
            winner = msg.sender;
            lastDraw = block.timestamp;
        }
    }

    function claim() external {
        require(msg.sender == winner, "Not winner");
        (bool success, ) = msg.sender.call{value: address(this).balance}("");
        require(success, "Fail");
        winner = address(0);
    }

    receive() external payable {}
}