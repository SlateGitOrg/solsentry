// SPDX-License-Identifier: MIT
// Fixture: the flag reaches a require through a copy.
pragma solidity ^0.8.20;

contract Splitter {
    address payable public a;
    address payable public b;

    constructor(address payable first, address payable second) {
        a = first;
        b = second;
    }

    function split() external {
        uint256 half = address(this).balance / 2;
        bool sentA = a.send(half);
        bool both = sentA;
        bool sentB = b.send(half);
        both = both && sentB;
        require(both, "send failed");
    }

    receive() external payable {}
}
