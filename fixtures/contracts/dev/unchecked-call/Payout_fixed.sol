// SPDX-License-Identifier: MIT
// Fixture: send() wrapped in require.
pragma solidity ^0.8.20;

contract Payout {
    address public owner = msg.sender;

    function pay(address payable to, uint256 amount) external {
        require(msg.sender == owner, "owner");
        require(to.send(amount), "send failed");
    }
}
