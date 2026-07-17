pragma solidity 0.8.0; 
contract VulnBank { 
    mapping(address = public balances; 
    function deposit() external payable { 
        balances[msg.sender] += msg.value; 
    } 
    function withdraw() external { 
        uint256 amount = balances[msg.sender]; 
        require(amount > 0); 
        (bool success, ) = msg.sender.call{value: amount}(""); 
        require(success); 
        balances[msg.sender] = 0; 
    } 
} 
