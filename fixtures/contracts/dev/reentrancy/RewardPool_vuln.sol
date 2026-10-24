// SPDX-License-Identifier: MIT
// Fixture (intentionally vulnerable): reentrancy through a high-level callback.
pragma solidity ^0.8.20;

interface IRewardReceiver {
    function onReward(uint256 amount) external;
}

contract RewardPool {
    mapping(address => uint256) public credits;
    uint256 public totalPaid;

    function credit(address user, uint256 amount) external {
        require(msg.sender == address(this), "internal");
        credits[user] += amount;
    }

    function claim() external {
        uint256 amount = credits[msg.sender];
        IRewardReceiver(msg.sender).onReward(amount); // @expect: reentrancy
        credits[msg.sender] = 0;
        totalPaid += amount;
    }

    function pending(address user) external view returns (uint256) {
        return credits[user];
    }
}
