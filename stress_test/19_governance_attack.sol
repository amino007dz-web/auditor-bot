// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ============================================================
// Vulnerability: Governance Attack (Flash Loan + Vote)
// Famous in: Compound proposal 2021, Beanstalk hack $182M
// ============================================================
interface IGovernance {
    function delegate(address delegatee) external;
}

contract GovToken {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract GovernanceVuln {
    GovToken public token;
    mapping(bytes32 => uint256) public proposalVotes;

    constructor(address _token) {
        token = GovToken(_token);
    }

    // Vulnerability: no snapshot, no voting delay
    function vote(bytes32 proposalId, bool support) external {
        uint256 weight = token.balanceOf(msg.sender);
        if (support) {
            proposalVotes[proposalId] += weight;
        }
        // Exploit: flash loan tokens, vote, repay — all in one tx
    }

    // Vulnerability: anyone can execute without quorum check
    function execute(bytes32 proposalId, address target, bytes calldata data) external {
        require(proposalVotes[proposalId] > 0, "No votes");
        (bool success, ) = target.call(data);
        require(success, "Execute failed");
    }

    // Vulnerability: no timelock between vote and execution
}