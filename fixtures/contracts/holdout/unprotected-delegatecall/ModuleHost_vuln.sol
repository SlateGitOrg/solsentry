// SPDX-License-Identifier: MIT
// Holdout fixture (intentionally vulnerable): any module address may be executed in context.
pragma solidity ^0.8.20;

contract ModuleHost {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    function execute(address module, bytes calldata payload) external payable returns (bytes memory) {
        (bool ok, bytes memory ret) = module.delegatecall(payload); // @expect: unprotected-delegatecall
        require(ok, "module failed");
        return ret;
    }
}
