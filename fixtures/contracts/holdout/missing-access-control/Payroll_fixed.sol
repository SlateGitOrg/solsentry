// SPDX-License-Identifier: MIT
// Holdout fixture: owner-only sweep; per-user refunds stay open.
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
        require(msg.sender == owner, "owner");
        (bool ok, ) = to.call{value: address(this).balance}("");
        require(ok, "withdraw failed");
    }
}
