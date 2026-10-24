// SPDX-License-Identifier: MIT
// Holdout fixture (intentionally vulnerable): token callbacks (ERC-777 style hooks) can
// re-enter both entry points before the bookkeeping is updated.
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

    constructor(IERC20 stakingToken) {
        token = stakingToken;
    }

    function stake(uint256 amount) external {
        require(amount > 0, "zero");
        require(token.transferFrom(msg.sender, address(this), amount), "pull failed"); // @expect: reentrancy
        stakes[msg.sender] += amount;
        totalStaked += amount;
    }

    function unstake(uint256 amount) external {
        require(stakes[msg.sender] >= amount, "too much");
        require(token.transfer(msg.sender, amount), "push failed"); // @expect: reentrancy
        stakes[msg.sender] -= amount;
        totalStaked -= amount;
    }

    function stakeOf(address who) external view returns (uint256) {
        return stakes[who];
    }
}
