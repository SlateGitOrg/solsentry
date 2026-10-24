// SPDX-License-Identifier: MIT
// Holdout fixture: success and length are both validated.
pragma solidity ^0.8.20;

contract PriceReader {
    address public oracle;
    uint256 public lastPrice;

    constructor(address priceOracle) {
        oracle = priceOracle;
    }

    function refresh() external {
        (bool ok, bytes memory data) = oracle.staticcall(abi.encodeWithSignature("price()"));
        require(ok && data.length == 32, "oracle failed");
        lastPrice = abi.decode(data, (uint256));
    }
}
