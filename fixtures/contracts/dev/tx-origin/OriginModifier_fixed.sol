// SPDX-License-Identifier: MIT
// Fixture: msg.sender in the modifier; the tx.origin == msg.sender "no contracts" idiom is
// not an authentication check and must not be reported.
pragma solidity ^0.8.20;

contract OriginModifier {
    address public admin;
    uint256 public fee;

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "admin only");
        _;
    }

    modifier onlyEOA() {
        require(tx.origin == msg.sender, "no contracts");
        _;
    }

    function setFee(uint256 newFee) external onlyAdmin onlyEOA {
        fee = newFee;
    }

    function setAdmin(address next) external onlyAdmin {
        admin = next;
    }
}
