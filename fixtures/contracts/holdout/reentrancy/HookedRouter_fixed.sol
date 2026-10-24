// SPDX-License-Identifier: MIT
// Holdout fixture: debit first, then call the hook; failure bookkeeping uses a transient
// event instead of storage.
pragma solidity ^0.8.20;

interface IHook {
    function beforeSwap(address user, uint256 amountIn) external returns (uint256 fee);
}

contract HookedRouter {
    event HookFailed(address hook);
    event FeeQuoted(uint256 fee);

    mapping(address => uint256) public credit;

    function swap(address hook, uint256 amountIn) external {
        require(credit[msg.sender] >= amountIn, "credit");
        credit[msg.sender] -= amountIn;
        try IHook(hook).beforeSwap(msg.sender, amountIn) returns (uint256 fee) {
            emit FeeQuoted(fee);
        } catch {
            emit HookFailed(hook);
        }
    }

    function deposit() external payable {
        credit[msg.sender] += msg.value;
    }
}
