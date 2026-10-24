// SPDX-License-Identifier: MIT
// Holdout fixture (intentionally vulnerable): failed payments in a loop go unnoticed.
pragma solidity ^0.8.20;

contract Airdrop {
    address public owner = msg.sender;

    receive() external payable {}

    function distribute(address[] calldata recipients, uint256[] calldata amounts) external {
        require(msg.sender == owner, "owner");
        require(recipients.length == amounts.length, "length");
        for (uint256 i = 0; i < recipients.length; i++) {
            recipients[i].call{value: amounts[i]}(""); // @expect: unchecked-call
        }
    }
}
