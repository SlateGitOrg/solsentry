// SPDX-License-Identifier: MIT
// Holdout fixture: Uniswap-V2-style `lock` modifier on every state-changing entry point.
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

contract Staking {
    IERC20 public immutable token;
    mapping(address => uint256) public stakes;
    uint256 public totalStaked;
    uint256 private unlocked = 1;

    modifier lock() {
        require(unlocked == 1, "LOCKED");
        unlocked = 0;
        _;
        unlocked = 1;
    }

    constructor(IERC20 stakingToken) {
        token = stakingToken;
    }

    function stake(uint256 amount) external lock {
        require(amount > 0, "zero");
        require(token.transferFrom(msg.sender, address(this), amount), "pull failed");
        stakes[msg.sender] += amount;
        totalStaked += amount;
    }

    function unstake(uint256 amount) external lock {
        require(stakes[msg.sender] >= amount, "too much");
        require(token.transfer(msg.sender, amount), "push failed");
        stakes[msg.sender] -= amount;
        totalStaked -= amount;
    }

    function stakeOf(address who) external view returns (uint256) {
        return stakes[who];
    }
}
