// SPDX-License-Identifier: MIT
// Fixture (intentionally vulnerable): 0.8 code that opts out of checks in `unchecked`.
pragma solidity ^0.8.20;

contract UncheckedVault {
    mapping(address => uint256) public shares;
    uint256 public totalShares;

    function mintShares(address to, uint256 amount) external {
        require(msg.sender == address(0x1234), "minter");
        unchecked {
            shares[to] += amount; // @expect: integer-overflow
            totalShares += amount; // @expect: integer-overflow
        }
    }

    function sumShares(address[] calldata holders) external view returns (uint256 total) {
        for (uint256 i = 0; i < holders.length; ) {
            total += shares[holders[i]];
            unchecked {
                ++i;
            }
        }
    }
}
