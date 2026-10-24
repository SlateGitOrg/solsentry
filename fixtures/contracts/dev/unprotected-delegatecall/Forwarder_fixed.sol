// SPDX-License-Identifier: MIT
// Fixture: a proxy delegating to a stored implementation that only the admin can change.
pragma solidity ^0.8.20;

contract Forwarder {
    address public implementation;
    address public admin;

    constructor(address impl) {
        implementation = impl;
        admin = msg.sender;
    }

    function upgradeTo(address impl) external {
        require(msg.sender == admin, "admin");
        implementation = impl;
    }

    fallback() external payable {
        (bool ok, ) = implementation.delegatecall(msg.data);
        require(ok, "forward failed");
    }
}
