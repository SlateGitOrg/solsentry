// SPDX-License-Identifier: MIT
// Fixture (intentionally vulnerable): anyone can sweep the whole balance to any address.
pragma solidity ^0.8.20;

contract Treasury {
    address private _owner;

    constructor() {
        _owner = msg.sender;
    }

    receive() external payable {}

    function owner() public view returns (address) {
        return _owner;
    }

    function sweep(address payable to) external {
        to.transfer(address(this).balance); // @expect: missing-access-control
    }
}
