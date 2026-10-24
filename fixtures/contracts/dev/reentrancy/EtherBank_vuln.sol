// SPDX-License-Identifier: MIT
// Fixture (intentionally vulnerable, never deploy): classic DAO-style reentrancy.
pragma solidity ^0.8.20;

contract EtherBank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "empty");
        (bool ok, ) = msg.sender.call{value: amount}(""); // @expect: reentrancy
        require(ok, "send failed");
        balances[msg.sender] = 0;
    }
}
