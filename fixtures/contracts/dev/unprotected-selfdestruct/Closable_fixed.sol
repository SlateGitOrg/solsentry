// SPDX-License-Identifier: MIT
// Fixture: inline sender check.
pragma solidity ^0.8.20;

contract Closable {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function close(address payable beneficiary) external {
        require(msg.sender == owner, "owner");
        require(beneficiary != address(0), "zero");
        selfdestruct(beneficiary);
    }
}
