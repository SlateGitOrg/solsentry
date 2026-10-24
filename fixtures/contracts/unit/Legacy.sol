// SPDX-License-Identifier: MIT
// Unit-test fixture for 0.7 semantics. Not part of the evaluation.
pragma solidity >=0.7.0 <0.8.0;

contract Legacy {
    uint256 public counter;
    mapping(address => uint256) public stamps;

    function bump(uint256 by) external {
        counter = counter + by;
        stamps[msg.sender] = block.timestamp;
    }

    function check(uint256 at) external view returns (bool) {
        return block.timestamp == at;
    }
}
