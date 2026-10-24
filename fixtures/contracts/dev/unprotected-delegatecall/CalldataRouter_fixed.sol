// SPDX-License-Identifier: MIT
// Fixture: routes only to an allow-listed module chosen by the owner.
pragma solidity ^0.8.20;

contract CalldataRouter {
    address public owner = msg.sender;
    address public module;

    function setModule(address next) external {
        require(msg.sender == owner, "owner");
        module = next;
    }

    fallback() external payable {
        (bool ok, ) = module.delegatecall(msg.data);
        require(ok, "route failed");
    }
}
