// SPDX-License-Identifier: MIT
// Holdout fixture: role administration is owner-only.
pragma solidity ^0.8.20;

contract MinterRegistry {
    address public owner;
    mapping(address => bool) public minters;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "owner");
        _;
    }

    modifier onlyMinter() {
        require(minters[msg.sender], "not minter");
        _;
    }

    function addMinter(address account) external onlyOwner {
        minters[account] = true;
    }

    function mint(address to, uint256 amount) external onlyMinter {
        balanceOf[to] += amount;
        totalSupply += amount;
    }
}
