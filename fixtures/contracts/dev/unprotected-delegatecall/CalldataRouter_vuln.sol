// SPDX-License-Identifier: MIT
// Fixture (intentionally vulnerable): the target address is sliced out of calldata.
pragma solidity ^0.8.20;

contract CalldataRouter {
    address public owner = msg.sender;

    fallback() external payable {
        address target = address(bytes20(msg.data[0:20]));
        (bool ok, ) = target.delegatecall(msg.data[20:]); // @expect: unprotected-delegatecall
        require(ok, "route failed");
    }
}
