// SPDX-License-Identifier: MIT
// Fixture (intentionally vulnerable): arbitrary delegatecall target, result ignored.
pragma solidity ^0.8.20;

contract Executor {
    address public owner = msg.sender;

    function exec(address target, bytes calldata data) external {
        target.delegatecall(data); // @expect: unprotected-delegatecall, unchecked-call
    }
}
