// SPDX-License-Identifier: MIT
// Fixture: checked arithmetic for user amounts; `unchecked` only for the loop counter.
pragma solidity ^0.8.20;

contract UncheckedVault {
    mapping(address => uint256) public shares;
    uint256 public totalShares;

    function mintShares(address to, uint256 amount) external {
        require(msg.sender == address(0x1234), "minter");
        shares[to] += amount;
        totalShares += amount;
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
