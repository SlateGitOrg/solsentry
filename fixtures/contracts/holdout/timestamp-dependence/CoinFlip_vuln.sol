// SPDX-License-Identifier: MIT
// Holdout fixture (intentionally vulnerable): "randomness" from a helper hashing the clock.
pragma solidity ^0.8.20;

contract CoinFlip {
    mapping(address => uint256) public wins;

    function _random() internal view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, block.number, msg.sender)));
    }

    function flip(bool guess) external {
        uint256 r = _random();
        bool side = r % 2 == 1; // @expect: timestamp-dependence
        if (side == guess) {
            wins[msg.sender] += 1;
        }
    }
}
