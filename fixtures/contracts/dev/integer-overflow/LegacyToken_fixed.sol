// SPDX-License-Identifier: MIT
// Fixture: explicit pre-checks before each arithmetic update.
pragma solidity ^0.7.6;

contract LegacyToken {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    constructor(uint256 supply) {
        balanceOf[msg.sender] = supply;
        totalSupply = supply;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "balance");
        require(balanceOf[to] + amount >= balanceOf[to], "overflow");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
