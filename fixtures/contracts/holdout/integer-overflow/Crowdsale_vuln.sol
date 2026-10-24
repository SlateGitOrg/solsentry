// SPDX-License-Identifier: MIT
// Holdout fixture (intentionally vulnerable): unchecked token arithmetic in a 0.7 sale.
pragma solidity ^0.7.6;

contract Crowdsale {
    address public owner;
    uint256 public rate;
    uint256 public totalSold;
    mapping(address => uint256) public purchased;

    constructor(uint256 tokensPerWei) {
        owner = msg.sender;
        rate = tokensPerWei;
    }

    function buy() external payable {
        uint256 tokens = msg.value * rate; // @expect: integer-overflow
        totalSold = totalSold + tokens; // @expect: integer-overflow
        purchased[msg.sender] = purchased[msg.sender] + tokens; // @expect: integer-overflow
    }

    function setRate(uint256 next) external {
        require(msg.sender == owner, "owner");
        rate = next;
    }
}
