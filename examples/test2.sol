pragma solidity 0.8.0; 
contract WeakAuth { 
    address public owner; 
    function transfer(address payable to, uint amount) external { 
        require(tx.origin == owner); 
        to.transfer(amount); 
    } 
} 
