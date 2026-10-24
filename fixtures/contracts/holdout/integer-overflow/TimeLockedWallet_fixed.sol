// SPDX-License-Identifier: MIT
// Holdout fixture: SafeMath on the user-supplied increment.
pragma solidity ^0.7.6;

library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "add overflow");
        return c;
    }
}

contract TimeLockedWallet {
    using SafeMath for uint256;

    mapping(address => uint256) public balances;
    mapping(address => uint256) public lockTime;

    function deposit() external payable {
        balances[msg.sender] = balances[msg.sender].add(msg.value);
        lockTime[msg.sender] = block.timestamp + 1 weeks;
    }

    function increaseLockTime(uint256 secondsToIncrease) external {
        lockTime[msg.sender] = lockTime[msg.sender].add(secondsToIncrease);
    }

    function withdraw() external {
        require(balances[msg.sender] > 0, "empty");
        require(block.timestamp > lockTime[msg.sender], "locked");
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        msg.sender.transfer(amount);
    }
}
