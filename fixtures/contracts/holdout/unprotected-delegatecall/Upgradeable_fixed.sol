// SPDX-License-Identifier: MIT
// Holdout fixture: upgrades are admin-only. Facets on an admin-curated allow-list may be run
// by anyone (diamond-style); each facet enforces its own authorization, so restricting the
// *target* rather than the *caller* is a legitimate design here.
pragma solidity ^0.8.20;

contract Upgradeable {
    address public implementation;
    address public admin;
    uint256 public version;
    mapping(address => bool) public approvedFacet;

    constructor(address impl) {
        implementation = impl;
        admin = msg.sender;
    }

    function approveFacet(address facet) external {
        require(msg.sender == admin, "admin");
        approvedFacet[facet] = true;
    }

    function setVersion(uint256 next) external {
        require(msg.sender == admin, "admin");
        version = next;
    }

    function upgradeAndCall(address newImpl, bytes calldata data) external {
        require(msg.sender == admin, "admin");
        implementation = newImpl;
        (bool ok, ) = newImpl.delegatecall(data);
        require(ok, "init failed");
    }

    function runFacet(address facet, bytes calldata data) external {
        require(approvedFacet[facet], "unknown facet");
        (bool ok, ) = facet.delegatecall(data);
        require(ok, "facet failed");
    }
}
