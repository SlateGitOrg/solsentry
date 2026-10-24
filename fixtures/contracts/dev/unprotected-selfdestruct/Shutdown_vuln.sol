// SPDX-License-Identifier: MIT
// Fixture (intentionally vulnerable): the identity being checked is supplied by the caller.
pragma solidity ^0.8.20;

contract Shutdown {
    mapping(address => bool) public admins;

    constructor() {
        admins[msg.sender] = true;
    }

    function shutdown(address caller) external {
        require(admins[caller], "not admin");
        selfdestruct(payable(caller)); // @expect: unprotected-selfdestruct
    }
}
