// SPDX-License-Identifier: MIT
// Fixture (intentionally vulnerable): release only at one exact second.
pragma solidity ^0.8.20;

contract TimeLock {
    uint256 public releaseTime;
    address public beneficiary;

    constructor(address who, uint256 when) {
        beneficiary = who;
        releaseTime = when;
    }

    function release() external {
        require(block.timestamp == releaseTime, "not now"); // @expect: timestamp-dependence
        payable(beneficiary).transfer(address(this).balance);
    }
}
