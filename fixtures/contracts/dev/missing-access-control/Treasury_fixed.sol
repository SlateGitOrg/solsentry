// SPDX-License-Identifier: MIT
// Fixture: OpenZeppelin 5.x style `_checkOwner()` helper guards the sweep.
pragma solidity ^0.8.20;

contract Treasury {
    error OwnableUnauthorizedAccount(address account);

    address private _owner;

    constructor() {
        _owner = msg.sender;
    }

    receive() external payable {}

    modifier onlyOwner() {
        _checkOwner();
        _;
    }

    function owner() public view returns (address) {
        return _owner;
    }

    function _msgSender() internal view returns (address) {
        return msg.sender;
    }

    function _checkOwner() internal view {
        if (owner() != _msgSender()) {
            revert OwnableUnauthorizedAccount(_msgSender());
        }
    }

    function sweep(address payable to) external onlyOwner {
        to.transfer(address(this).balance);
    }
}
