// SPDX-License-Identifier: MIT
// Holdout fixture: explicit overflow checks after each operation.
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
        uint256 tokens = msg.value * rate;
        require(msg.value == 0 || tokens / msg.value == rate, "mul overflow");
        uint256 sold = totalSold + tokens;
        require(sold >= totalSold, "add overflow");
        totalSold = sold;
        uint256 mine = purchased[msg.sender] + tokens;
        require(mine >= tokens, "add overflow");
        purchased[msg.sender] = mine;
    }

    function setRate(uint256 next) external {
        require(msg.sender == owner, "owner");
        rate = next;
    }
}
