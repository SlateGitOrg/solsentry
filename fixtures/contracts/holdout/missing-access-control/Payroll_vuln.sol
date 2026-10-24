// SPDX-License-Identifier: MIT
// Holdout fixture (intentionally vulnerable): the withdraw-everything path is unguarded.
pragma solidity ^0.8.20;

contract Payroll {
    address public owner;
    mapping(address => uint256) public refunds;

    constructor() {
        owner = msg.sender;
    }

    receive() external payable {}

    function claimRefund() external {
        uint256 amount = refunds[msg.sender];
        refunds[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }

    function withdraw(address payable to) external {
        (bool ok, ) = to.call{value: address(this).balance}(""); // @expect: missing-access-control
        require(ok, "withdraw failed");
    }
}
