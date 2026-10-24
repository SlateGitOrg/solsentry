// SPDX-License-Identifier: MIT
// Fixture (intentionally vulnerable): the tx.origin check lives in a modifier.
pragma solidity ^0.8.20;

contract OriginModifier {
    address public admin;
    uint256 public fee;

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(tx.origin == admin, "admin only"); // @expect: tx-origin
        _;
    }

    function setFee(uint256 newFee) external onlyAdmin {
        fee = newFee;
    }

    function setAdmin(address next) external onlyAdmin {
        admin = next;
    }
}
