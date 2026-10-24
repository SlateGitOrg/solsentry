// SPDX-License-Identifier: MIT
// Fixture: if/revert form keyed on msg.sender.
pragma solidity ^0.8.20;

contract OriginRevert {
    error Unauthorized();

    mapping(address => bool) public operators;
    uint256 public price;

    constructor() {
        operators[msg.sender] = true;
    }

    function setPrice(uint256 newPrice) external {
        if (!operators[msg.sender]) revert Unauthorized();
        price = newPrice;
    }
}
