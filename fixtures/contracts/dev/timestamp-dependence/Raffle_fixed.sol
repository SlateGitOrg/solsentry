// SPDX-License-Identifier: MIT
// Fixture: timestamps only bound the entry window and label tickets; the draw uses an
// externally supplied random word.
pragma solidity ^0.8.20;

contract Raffle {
    address[] public players;
    address public winner;
    address public coordinator;
    uint256 public endTime;
    mapping(bytes32 => address) public tickets;

    constructor(uint256 duration, address vrfCoordinator) {
        endTime = block.timestamp + duration;
        coordinator = vrfCoordinator;
    }

    function enter() external payable {
        require(block.timestamp < endTime, "closed");
        bytes32 ticket = keccak256(abi.encodePacked(msg.sender, block.timestamp));
        tickets[ticket] = msg.sender;
        players.push(msg.sender);
    }

    function fulfillRandomWord(uint256 word) external {
        require(msg.sender == coordinator, "coordinator");
        require(block.timestamp >= endTime, "open");
        winner = players[word % players.length];
    }
}
