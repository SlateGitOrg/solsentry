// SPDX-License-Identifier: MIT
// Holdout fixture: role check through an internal view helper.
pragma solidity ^0.8.20;

contract Emergency {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    mapping(bytes32 => mapping(address => bool)) private _roles;
    bool public paused;

    constructor() {
        _roles[ADMIN_ROLE][msg.sender] = true;
    }

    function hasRole(bytes32 role, address account) public view returns (bool) {
        return _roles[role][account];
    }

    function pause() external {
        require(hasRole(ADMIN_ROLE, msg.sender), "admin");
        paused = true;
    }

    function emergencyStop() external {
        require(hasRole(ADMIN_ROLE, msg.sender), "admin");
        if (paused) {
            selfdestruct(payable(msg.sender));
        }
    }
}
