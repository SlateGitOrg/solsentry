// SPDX-License-Identifier: MIT
// Holdout fixture: only the proposed owner may accept.
pragma solidity ^0.8.20;

contract TwoStepOwner {
    address public owner;
    address public pendingOwner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "owner");
        _;
    }

    function proposeOwner(address next) external onlyOwner {
        pendingOwner = next;
    }

    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "not pending owner");
        _transferOwnership(pendingOwner);
    }

    function _transferOwnership(address next) internal {
        owner = next;
        pendingOwner = address(0);
    }
}
