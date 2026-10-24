// SPDX-License-Identifier: MIT
// Fixture: checks-effects-interactions ordering removes the reentrancy window.
pragma solidity ^0.8.20;

contract EtherBank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "empty");
        balances[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
    }
}
