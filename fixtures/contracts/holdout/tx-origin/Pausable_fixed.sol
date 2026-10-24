// SPDX-License-Identifier: MIT
// Holdout fixture: the guardian is authenticated via msg.sender.
pragma solidity ^0.8.20;

contract Pausable {
    address public guardian;
    bool public paused;
    uint256 public counter;

    constructor(address initialGuardian) {
        guardian = initialGuardian;
    }

    function togglePause() external {
        if (msg.sender == guardian) {
            paused = !paused;
        }
    }

    function bump() external {
        require(msg.sender == tx.origin, "EOA only");
        require(!paused, "paused");
        counter += 1;
    }
}
