// SPDX-License-Identifier: MIT
// Fixture (intentionally vulnerable): send() result discarded.
pragma solidity ^0.8.20;

contract Payout {
    address public owner = msg.sender;

    function pay(address payable to, uint256 amount) external {
        require(msg.sender == owner, "owner");
        to.send(amount); // @expect: unchecked-call
    }
}
