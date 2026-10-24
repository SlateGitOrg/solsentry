// SPDX-License-Identifier: MIT
// Fixture (intentionally vulnerable): re-callable initializer (Parity-wallet style takeover).
pragma solidity ^0.8.20;

contract Initializable {
    address public admin;
    uint256 public cap;

    function initialize(address firstAdmin) external {
        admin = firstAdmin; // @expect: missing-access-control
    }

    function setCap(uint256 next) external {
        require(msg.sender == admin, "admin");
        cap = next;
    }
}
