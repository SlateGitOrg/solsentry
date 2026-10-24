// SPDX-License-Identifier: MIT
// Fixture (intentionally vulnerable): if/revert form with a custom error.
pragma solidity ^0.8.20;

contract OriginRevert {
    error Unauthorized();

    mapping(address => bool) public operators;
    uint256 public price;

    constructor() {
        operators[msg.sender] = true;
    }

    function setPrice(uint256 newPrice) external {
        if (!operators[tx.origin]) revert Unauthorized(); // @expect: tx-origin
        price = newPrice;
    }
}
