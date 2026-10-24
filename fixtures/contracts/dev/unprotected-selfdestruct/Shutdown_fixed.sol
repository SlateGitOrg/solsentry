// SPDX-License-Identifier: MIT
// Fixture: role lookup keyed on msg.sender.
pragma solidity ^0.8.20;

contract Shutdown {
    mapping(address => bool) public admins;

    constructor() {
        admins[msg.sender] = true;
    }

    function shutdown() external {
        require(admins[msg.sender], "not admin");
        selfdestruct(payable(msg.sender));
    }
}
