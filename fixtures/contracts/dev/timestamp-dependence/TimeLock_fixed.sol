// SPDX-License-Identifier: MIT
// Fixture: a range comparison tolerates validator clock drift.
pragma solidity ^0.8.20;

contract TimeLock {
    uint256 public releaseTime;
    address public beneficiary;

    constructor(address who, uint256 when) {
        beneficiary = who;
        releaseTime = when;
    }

    function release() external {
        require(block.timestamp >= releaseTime, "too early");
        payable(beneficiary).transfer(address(this).balance);
    }
}
