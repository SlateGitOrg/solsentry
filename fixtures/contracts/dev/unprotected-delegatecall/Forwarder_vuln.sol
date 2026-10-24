// SPDX-License-Identifier: MIT
// Fixture (intentionally vulnerable): caller picks the implementation per call.
pragma solidity ^0.8.20;

contract Forwarder {
    uint256 public counter;

    function forward(address impl) public payable {
        (bool ok, ) = impl.delegatecall(msg.data[36:]); // @expect: unprotected-delegatecall
        require(ok, "forward failed");
    }
}
