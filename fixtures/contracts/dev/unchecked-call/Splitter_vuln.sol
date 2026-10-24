// SPDX-License-Identifier: MIT
// Fixture (intentionally vulnerable): the flag is copied around but no copy is ever checked.
pragma solidity ^0.8.20;

contract Splitter {
    address payable public a;
    address payable public b;
    bool public lastOk;

    constructor(address payable first, address payable second) {
        a = first;
        b = second;
    }

    function split() external {
        uint256 half = address(this).balance / 2;
        bool sentA = a.send(half); // @expect: unchecked-call
        lastOk = sentA;
        bool sentB = b.send(half);
        require(sentB, "b failed");
    }

    receive() external payable {}
}
