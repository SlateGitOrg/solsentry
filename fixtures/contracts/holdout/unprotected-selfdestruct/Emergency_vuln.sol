// SPDX-License-Identifier: MIT
// Holdout fixture (intentionally vulnerable): a pause flag is not an identity check.
pragma solidity ^0.8.20;

contract Emergency {
    address public owner;
    bool public paused;

    constructor() {
        owner = msg.sender;
    }

    function pause() external {
        require(msg.sender == owner, "owner");
        paused = true;
    }

    function emergencyStop() external {
        if (paused) {
            selfdestruct(payable(owner)); // @expect: unprotected-selfdestruct
        }
    }
}
