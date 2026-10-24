// SPDX-License-Identifier: MIT
// Fixture (intentionally vulnerable): ownership can be taken by anyone.
pragma solidity ^0.8.20;

contract Ownable {
    address public owner;
    uint256 public limit;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "owner");
        _;
    }

    function setLimit(uint256 next) external onlyOwner {
        limit = next;
    }

    function transferOwnership(address next) external {
        owner = next; // @expect: missing-access-control
    }
}
