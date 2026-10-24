// SPDX-License-Identifier: MIT
// Fixture (intentionally vulnerable): a sanity check is not an authorization check.
pragma solidity ^0.8.20;

contract Closable {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function close(address payable beneficiary) external {
        require(beneficiary != address(0), "zero");
        selfdestruct(beneficiary); // @expect: unprotected-selfdestruct
    }
}
