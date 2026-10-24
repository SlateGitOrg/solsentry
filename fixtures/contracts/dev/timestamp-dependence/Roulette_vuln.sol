// SPDX-License-Identifier: MIT
// Fixture (intentionally vulnerable): block.timestamp used as a random source.
pragma solidity ^0.8.20;

contract Roulette {
    address public lastWinner;
    uint256 public pastBlockTime;

    function spin() external payable {
        require(msg.value == 1 ether, "stake");
        require(block.timestamp != pastBlockTime, "one per block"); // @expect: timestamp-dependence
        pastBlockTime = block.timestamp;
        if (block.timestamp % 15 == 0) { // @expect: timestamp-dependence
            lastWinner = msg.sender;
        }
    }
}
