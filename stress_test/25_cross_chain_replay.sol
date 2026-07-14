// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ============================================================
// Vulnerability: Cross-chain Replay Attack (Chain ID not checked)
// Famous in: Optimism bridge, many cross-chain bridges
// ============================================================
contract CrossChainBridge {
    mapping(bytes32 => bool) public processed;
    address public token;

    function deposit(uint256 amount, uint256 toChain) external {
        // Vulnerability: no source chain verification
        bytes32 txId = keccak256(abi.encodePacked(msg.sender, amount, toChain, block.number));
        processed[txId] = true;
    }

    function mint(bytes32 txId, address to, uint256 amount) external {
        // Vulnerability: no chainId in signature validation
        // Same signature can be replayed on Ethereum AND Polygon
        require(!processed[txId], "Already minted");
        processed[txId] = true;
        // Mint tokens to 'to' address
    }

    // Exploit: attacker calls deposit() on Ethereum, then replays
    // the same signature on Polygon to mint double
}