// SPDX-License-Identifier: MIT
// Fixture: OpenZeppelin 5.x style guard implemented with internal before/after helpers.
pragma solidity ^0.8.20;

contract Escrow {
    struct Deal {
        address payable seller;
        uint256 amount;
        bool released;
    }

    error ReentrantCall();

    mapping(uint256 => Deal) public deals;
    uint256 public nextId;
    uint256 private _guard = 1;

    modifier nonReentrant() {
        _enter();
        _;
        _leave();
    }

    function _enter() private {
        if (_guard == 2) revert ReentrantCall();
        _guard = 2;
    }

    function _leave() private {
        _guard = 1;
    }

    function open(address payable seller) external payable returns (uint256 id) {
        id = nextId++;
        deals[id] = Deal(seller, msg.value, false);
    }

    function release(uint256 id) external nonReentrant {
        Deal storage deal = deals[id];
        require(!deal.released, "done");
        _pay(deal.seller, deal.amount);
        deal.released = true;
    }

    function _pay(address payable to, uint256 amount) internal {
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "pay failed");
    }
}
