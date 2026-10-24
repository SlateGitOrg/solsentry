// SPDX-License-Identifier: MIT
// Holdout fixture (intentionally vulnerable): a branch (not a revert) keyed on tx.origin.
pragma solidity ^0.8.20;

contract Pausable {
    address public guardian;
    bool public paused;
    uint256 public counter;

    constructor(address initialGuardian) {
        guardian = initialGuardian;
    }

    function togglePause() external {
        if (tx.origin == guardian) { // @expect: tx-origin
            paused = !paused;
        }
    }

    function bump() external {
        require(msg.sender == tx.origin, "EOA only");
        require(!paused, "paused");
        counter += 1;
    }
}
