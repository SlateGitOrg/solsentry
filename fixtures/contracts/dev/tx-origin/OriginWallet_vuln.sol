// SPDX-License-Identifier: MIT
// Fixture (intentionally vulnerable): tx.origin authentication lets a phishing contract
// spend the owner's funds when the owner calls it.
pragma solidity ^0.8.20;

contract OriginWallet {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    receive() external payable {}

    function transferTo(address payable to, uint256 amount) external {
        require(tx.origin == owner, "not owner"); // @expect: tx-origin
        to.transfer(amount);
    }
}
