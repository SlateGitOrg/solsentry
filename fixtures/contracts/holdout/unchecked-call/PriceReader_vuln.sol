// SPDX-License-Identifier: MIT
// Holdout fixture (intentionally vulnerable): staticcall failure decodes garbage/empty data.
pragma solidity ^0.8.20;

contract PriceReader {
    address public oracle;
    uint256 public lastPrice;

    constructor(address priceOracle) {
        oracle = priceOracle;
    }

    function refresh() external {
        (bool ok, bytes memory data) = oracle.staticcall(abi.encodeWithSignature("price()")); // @expect: unchecked-call
        lastPrice = abi.decode(data, (uint256));
    }
}
