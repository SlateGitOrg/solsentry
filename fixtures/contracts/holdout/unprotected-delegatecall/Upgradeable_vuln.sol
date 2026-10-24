// SPDX-License-Identifier: MIT
// Holdout fixture (intentionally vulnerable): upgrade-and-call open to everyone.
pragma solidity ^0.8.20;

contract Upgradeable {
    address public implementation;
    address public admin;
    uint256 public version;

    constructor(address impl) {
        implementation = impl;
        admin = msg.sender;
    }

    function setVersion(uint256 next) external {
        require(msg.sender == admin, "admin");
        version = next;
    }

    function upgradeAndCall(address newImpl, bytes calldata data) external {
        implementation = newImpl; // @expect: missing-access-control
        (bool ok, ) = newImpl.delegatecall(data); // @expect: unprotected-delegatecall
        require(ok, "init failed");
    }
}
