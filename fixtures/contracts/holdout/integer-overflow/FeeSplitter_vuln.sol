// SPDX-License-Identifier: MIT
// Holdout fixture (intentionally vulnerable): gas-golfed fee math wraps for large amounts.
pragma solidity ^0.8.20;

contract FeeSplitter {
    uint256 public constant FEE_BPS = 30;
    mapping(address => uint256) public owed;

    function quote(uint256 amount) public pure returns (uint256 fee, uint256 net) {
        unchecked {
            fee = (amount * FEE_BPS) / 10_000; // @expect: integer-overflow
            net = amount - fee;
        }
    }

    function settle(address[] calldata payees, uint256 amount) external {
        (, uint256 net) = quote(amount);
        for (uint256 i; i < payees.length; ) {
            owed[payees[i]] += net;
            unchecked {
                ++i;
            }
        }
    }
}
