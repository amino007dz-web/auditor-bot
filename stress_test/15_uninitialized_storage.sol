// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ============================================================
// Vulnerability: Uninitialized Storage Variable (DeFi hack)
// ============================================================
contract UninitializedStorage {
    uint256 constant INTEREST_RATE = 5;

    // Vulnerability: struct stored at slot 0 (overlaps with _owner!)
    struct Loan {
        address borrower;
        uint256 amount;
    }

    mapping(uint256 => Loan) public loans;

    // This variable accidentally occupies slot 0!
    uint256 public _placeholder;

    struct User {
        bool isActive;
        address referrer;
    }

    // Vulnerability: Using struct without assignment confuses storage
    mapping(address => User) public users;

    function addUser(address referrer) external {
        User memory newUser;
        // Forgot to assign memory: isActive is false, referrer is wrong
        users[msg.sender] = newUser;
    }

    function takeLoan(uint256 amount) external returns (Loan) {
        Loan storage loan = loans[0];
        loan.borrower = msg.sender;
        loan.amount = amount;
        // Vulnerability: should be loans[nextId] but always overwrites slot 0!
        return loan;
    }
}