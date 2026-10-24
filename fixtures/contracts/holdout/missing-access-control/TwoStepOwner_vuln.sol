// SPDX-License-Identifier: MIT
// Holdout fixture (intentionally vulnerable): acceptOwnership forgets to check the caller.
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
        _transferOwnership(pendingOwner); // @expect: missing-access-control
    }

    function _transferOwnership(address next) internal {
        owner = next;
        pendingOwner = address(0);
    }
}
