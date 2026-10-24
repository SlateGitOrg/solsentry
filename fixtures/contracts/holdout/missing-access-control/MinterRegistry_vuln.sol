// SPDX-License-Identifier: MIT
// Holdout fixture (intentionally vulnerable): anyone can grant themselves the minter role.
pragma solidity ^0.8.20;

contract MinterRegistry {
    address public owner;
    mapping(address => bool) public minters;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyMinter() {
        require(minters[msg.sender], "not minter");
        _;
    }

    function addMinter(address account) external {
        minters[account] = true; // @expect: missing-access-control
    }

    function mint(address to, uint256 amount) external onlyMinter {
        balanceOf[to] += amount;
        totalSupply += amount;
    }
}
