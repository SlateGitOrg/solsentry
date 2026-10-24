// SPDX-License-Identifier: MIT
// Holdout fixture: each payment is checked; a helper returns the send result to its caller.
pragma solidity ^0.8.20;

contract Airdrop {
    address public owner = msg.sender;

    receive() external payable {}

    function distribute(address[] calldata recipients, uint256[] calldata amounts) external {
        require(msg.sender == owner, "owner");
        require(recipients.length == amounts.length, "length");
        for (uint256 i = 0; i < recipients.length; i++) {
            (bool ok, ) = recipients[i].call{value: amounts[i]}("");
            require(ok, "payment failed");
        }
    }

    function trySend(address payable to, uint256 amount) external returns (bool) {
        require(msg.sender == owner, "owner");
        return to.send(amount);
    }
}
