// SPDX-License-Identifier: MIT
// Fixture (intentionally vulnerable): BEC-style batch transfer multiplication overflow.
pragma solidity ^0.7.6;

contract BatchToken {
    mapping(address => uint256) public balances;

    constructor() {
        balances[msg.sender] = 1e24;
    }

    function batchTransfer(address[] calldata receivers, uint256 value) external {
        uint256 count = receivers.length;
        uint256 amount = count * value; // @expect: integer-overflow
        require(count > 0 && count <= 20, "count");
        require(value > 0 && balances[msg.sender] >= amount, "balance");
        balances[msg.sender] = balances[msg.sender] - amount;
        for (uint256 i = 0; i < count; i++) {
            balances[receivers[i]] = balances[receivers[i]] + value; // @expect: integer-overflow
        }
    }
}
