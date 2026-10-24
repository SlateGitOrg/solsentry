// SPDX-License-Identifier: MIT
// Holdout fixture: commit-reveal; the outcome mixes the player's secret with a future
// blockhash instead of the clock.
pragma solidity ^0.8.20;

contract CoinFlip {
    struct Commit {
        bytes32 hash;
        uint256 blockNumber;
    }

    mapping(address => uint256) public wins;
    mapping(address => Commit) public commits;

    function commit(bytes32 hash) external {
        commits[msg.sender] = Commit(hash, block.number);
    }

    function reveal(bool guess, bytes32 secret) external {
        Commit memory c = commits[msg.sender];
        require(c.blockNumber != 0 && block.number > c.blockNumber, "too early");
        require(keccak256(abi.encodePacked(guess, secret)) == c.hash, "bad reveal");
        delete commits[msg.sender];
        uint256 r = uint256(keccak256(abi.encodePacked(secret, blockhash(c.blockNumber))));
        if ((r % 2 == 1) == guess) {
            wins[msg.sender] += 1;
        }
    }
}
