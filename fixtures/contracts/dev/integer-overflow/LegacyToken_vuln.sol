// SPDX-License-Identifier: MIT
// Fixture (intentionally vulnerable): pre-0.8 token without overflow/underflow checks.
pragma solidity ^0.7.6;

contract LegacyToken {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    constructor(uint256 supply) {
        balanceOf[msg.sender] = supply;
        totalSupply = supply;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount; // @expect: integer-overflow
        balanceOf[to] += amount; // @expect: integer-overflow
        return true;
    }
}
