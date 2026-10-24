// SPDX-License-Identifier: MIT
// Fixture: one-shot initializer flag.
pragma solidity ^0.8.20;

contract Initializable {
    address public admin;
    uint256 public cap;
    bool private initialized;

    function initialize(address firstAdmin) external {
        require(!initialized, "already initialized");
        initialized = true;
        admin = firstAdmin;
    }

    function setCap(uint256 next) external {
        require(msg.sender == admin, "admin");
        cap = next;
    }
}
