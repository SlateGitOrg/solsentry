// SPDX-License-Identifier: MIT
// Fixture: randomness supplied by a trusted oracle; block numbers rate-limit spins.
pragma solidity ^0.8.20;

contract Roulette {
    address public lastWinner;
    address public oracle;
    uint256 public lastSpinBlock;
    address public pendingPlayer;

    constructor(address randomnessOracle) {
        oracle = randomnessOracle;
    }

    function spin() external payable {
        require(msg.value == 1 ether, "stake");
        require(block.number > lastSpinBlock, "one per block");
        lastSpinBlock = block.number;
        pendingPlayer = msg.sender;
    }

    function fulfill(uint256 randomness) external {
        require(msg.sender == oracle, "oracle");
        if (randomness % 15 == 0) {
            lastWinner = pendingPlayer;
        }
    }
}
