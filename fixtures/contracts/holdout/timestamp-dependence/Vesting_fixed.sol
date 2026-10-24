// SPDX-License-Identifier: MIT
// Holdout fixture: the bonus window is a range.
pragma solidity ^0.8.20;

contract Vesting {
    uint256 public immutable start;
    uint256 public immutable cliff;
    uint256 public immutable duration;
    address public immutable beneficiary;
    uint256 public released;
    bool public bonusPaid;

    constructor(address who, uint256 cliffSeconds, uint256 durationSeconds) payable {
        beneficiary = who;
        start = block.timestamp;
        cliff = block.timestamp + cliffSeconds;
        duration = durationSeconds;
    }

    function release() external {
        require(block.timestamp >= cliff, "cliff");
        uint256 vested = address(this).balance + released;
        if (block.timestamp < start + duration) {
            vested = (vested * (block.timestamp - start)) / duration;
        }
        uint256 amount = vested - released;
        released += amount;
        payable(beneficiary).transfer(amount);
    }

    function claimBonus() external {
        require(!bonusPaid, "paid");
        if (block.timestamp >= start + duration) {
            bonusPaid = true;
        }
    }
}
