// SPDX-License-Identifier: MIT
// Fixture (intentionally vulnerable): anyone can destroy the contract.
pragma solidity ^0.8.20;

contract Killable {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function kill() external {
        selfdestruct(payable(msg.sender)); // @expect: unprotected-selfdestruct
    }
}
