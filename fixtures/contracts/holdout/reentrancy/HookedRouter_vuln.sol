// SPDX-License-Identifier: MIT
// Holdout fixture (intentionally vulnerable): state updated in try/catch clauses after an
// untrusted hook ran.
pragma solidity ^0.8.20;

interface IHook {
    function beforeSwap(address user, uint256 amountIn) external returns (uint256 fee);
}

contract HookedRouter {
    mapping(address => uint256) public credit;
    uint256 public feesCollected;
    uint256 public hookFailures;

    function swap(address hook, uint256 amountIn) external {
        require(credit[msg.sender] >= amountIn, "credit");
        try IHook(hook).beforeSwap(msg.sender, amountIn) returns (uint256 fee) { // @expect: reentrancy
            feesCollected += fee;
            credit[msg.sender] -= amountIn;
        } catch {
            hookFailures += 1;
        }
    }

    function deposit() external payable {
        credit[msg.sender] += msg.value;
    }
}
