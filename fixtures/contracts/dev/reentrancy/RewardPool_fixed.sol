// SPDX-License-Identifier: MIT
// Fixture: an inline mutex modifier (OpenZeppelin 4.x style) guards the callback.
pragma solidity ^0.8.20;

interface IRewardReceiver {
    function onReward(uint256 amount) external;
}

contract RewardPool {
    mapping(address => uint256) public credits;
    uint256 public totalPaid;
    uint256 private _status = 1;

    modifier nonReentrant() {
        require(_status != 2, "reentrant call");
        _status = 2;
        _;
        _status = 1;
    }

    function credit(address user, uint256 amount) external {
        require(msg.sender == address(this), "internal");
        credits[user] += amount;
    }

    function claim() external nonReentrant {
        uint256 amount = credits[msg.sender];
        IRewardReceiver(msg.sender).onReward(amount);
        credits[msg.sender] = 0;
        totalPaid += amount;
    }

    function pending(address user) external view returns (uint256) {
        return credits[user];
    }
}
