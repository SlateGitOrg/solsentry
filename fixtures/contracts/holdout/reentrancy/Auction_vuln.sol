// SPDX-License-Identifier: MIT
// Holdout fixture (intentionally vulnerable): refunding the previous bidder with a raw call
// before recording the new highest bid.
pragma solidity ^0.8.20;

contract Auction {
    address payable public highestBidder;
    uint256 public highestBid;
    uint256 public immutable endTime;

    constructor(uint256 biddingTime) {
        endTime = block.timestamp + biddingTime;
    }

    function bid() external payable {
        require(block.timestamp < endTime, "ended");
        require(msg.value > highestBid, "too low");
        if (highestBid != 0) {
            (bool ok, ) = highestBidder.call{value: highestBid}(""); // @expect: reentrancy
            require(ok, "refund failed");
        }
        highestBidder = payable(msg.sender);
        highestBid = msg.value;
    }
}
