// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ============================================================
// Vulnerability: Constructor Naming Bug (Anyone becomes owner)
// Famous in: Rubixi hack (old contract name was "DynamicPyramid")
// ============================================================
// Vulnerability: constructor name MUST match contract name in Solidity <0.4.22
contract MissnamedConstructor {
    address public owner;

    // THIS IS NOT A CONSTRUCTOR — it's a regular public function!
    // Anyone can call it and become owner
    function MissnamedConstructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function withdraw() external onlyOwner {
        payable(owner).transfer(address(this).balance);
    }
}