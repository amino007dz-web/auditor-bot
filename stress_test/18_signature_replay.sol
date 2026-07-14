// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ============================================================
// Vulnerability: Signature Replay (Cross-chain)
// Famous in: Optimism bridge hack, many DEX hacks
// ============================================================
contract SigReplay {
    mapping(bytes => bool) public usedSignatures;

    function claim(uint256 amount, bytes memory signature) external {
        // Vulnerability: no chainId, no nonce, no deadline
        bytes32 message = keccak256(abi.encodePacked(msg.sender, amount));
        address signer = recoverSigner(message, signature);

        // Vulnerability: signature can be replayed on any chain
        // Vulnerability: signature can be replayed multiple times (no nonce)
        require(!usedSignatures[signature], "Already used");
        usedSignatures[signature] = true;

        payable(msg.sender).transfer(amount);
    }

    function recoverSigner(bytes32 _hash, bytes memory _sig) internal pure returns (address) {
        bytes32 ethSignedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _hash));
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_sig);
        return ecrecover(ethSignedHash, v, r, s);
    }

    function splitSignature(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }
}