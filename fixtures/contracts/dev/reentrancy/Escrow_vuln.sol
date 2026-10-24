// SPDX-License-Identifier: MIT
// Fixture (intentionally vulnerable): the external call hides in an internal helper and the
// state update goes through a storage pointer.
pragma solidity ^0.8.20;

contract Escrow {
    struct Deal {
        address payable seller;
        uint256 amount;
        bool released;
    }

    mapping(uint256 => Deal) public deals;
    uint256 public nextId;

    function open(address payable seller) external payable returns (uint256 id) {
        id = nextId++;
        deals[id] = Deal(seller, msg.value, false);
    }

    function release(uint256 id) external {
        Deal storage deal = deals[id];
        require(!deal.released, "done");
        _pay(deal.seller, deal.amount); // @expect: reentrancy
        deal.released = true;
    }

    function _pay(address payable to, uint256 amount) internal {
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "pay failed");
    }
}
