// SPDX-License-Identifier: MIT
// Holdout fixture: the helper authenticates msg.sender.
pragma solidity ^0.8.20;

contract GuardedVault {
    address public owner;
    mapping(address => uint256) public allowanceOf;

    constructor() {
        owner = msg.sender;
    }

    function _isAuthorized() internal view returns (bool) {
        return msg.sender == owner;
    }

    modifier onlyOwner() {
        require(_isAuthorized(), "unauthorized");
        _;
    }

    function setAllowance(address spender, uint256 amount) external onlyOwner {
        allowanceOf[spender] = amount;
    }

    function noContracts() external view returns (bool) {
        return msg.sender == tx.origin;
    }
}
