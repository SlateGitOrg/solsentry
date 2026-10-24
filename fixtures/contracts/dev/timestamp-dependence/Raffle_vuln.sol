// SPDX-License-Identifier: MIT
// Fixture (intentionally vulnerable): hashing the timestamp does not make it unpredictable.
pragma solidity ^0.8.20;

contract Raffle {
    address[] public players;
    address public winner;
    uint256 public endTime;

    constructor(uint256 duration) {
        endTime = block.timestamp + duration;
    }

    function enter() external payable {
        require(block.timestamp < endTime, "closed");
        players.push(msg.sender);
    }

    function draw() external {
        require(block.timestamp >= endTime, "open");
        uint256 seed = uint256(keccak256(abi.encodePacked(block.timestamp, players.length)));
        winner = players[seed % players.length]; // @expect: timestamp-dependence
    }
}
