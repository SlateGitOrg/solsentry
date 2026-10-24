// SPDX-License-Identifier: MIT
// Holdout fixture: pull payments, as in the Solidity documentation's SimpleAuction.
pragma solidity ^0.8.20;

contract Auction {
    address public highestBidder;
    uint256 public highestBid;
    uint256 public immutable endTime;
    mapping(address => uint256) public pendingReturns;

    constructor(uint256 biddingTime) {
        endTime = block.timestamp + biddingTime;
    }

    function bid() external payable {
        require(block.timestamp < endTime, "ended");
        require(msg.value > highestBid, "too low");
        if (highestBid != 0) {
            pendingReturns[highestBidder] += highestBid;
        }
        highestBidder = msg.sender;
        highestBid = msg.value;
    }

    function withdraw() external returns (bool) {
        uint256 amount = pendingReturns[msg.sender];
        if (amount > 0) {
            pendingReturns[msg.sender] = 0;
            if (!payable(msg.sender).send(amount)) {
                pendingReturns[msg.sender] = amount;
                return false;
            }
        }
        return true;
    }
}
