// SPDX-License-Identifier: MIT
// Holdout fixture: the helper itself enforces ownership.
pragma solidity ^0.8.20;

contract Migrator {
    address public owner;
    address public successor;

    constructor() {
        owner = msg.sender;
    }

    function setSuccessor(address next) external {
        require(msg.sender == owner, "owner");
        successor = next;
    }

    function migrate() external {
        require(successor != address(0), "no successor");
        _destroy(payable(successor));
    }

    function _destroy(address payable to) internal {
        require(msg.sender == owner, "owner");
        selfdestruct(to);
    }
}
