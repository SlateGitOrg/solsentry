// SPDX-License-Identifier: MIT
// Fixture: owner-only modifier.
pragma solidity ^0.8.20;

contract Killable {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "owner");
        _;
    }

    function kill() external onlyOwner {
        selfdestruct(payable(msg.sender));
    }
}
