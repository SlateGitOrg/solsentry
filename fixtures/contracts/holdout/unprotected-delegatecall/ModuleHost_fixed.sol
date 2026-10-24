// SPDX-License-Identifier: MIT
// Holdout fixture: only the owner can execute modules.
pragma solidity ^0.8.20;

contract ModuleHost {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    function execute(address module, bytes calldata payload) external payable returns (bytes memory) {
        require(msg.sender == owner, "owner");
        (bool ok, bytes memory ret) = module.delegatecall(payload);
        require(ok, "module failed");
        return ret;
    }
}
