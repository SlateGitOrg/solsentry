// SPDX-License-Identifier: MIT
// Fixture: the flag gates a revert.
pragma solidity ^0.8.20;

contract Relay {
    error CallFailed();
    event Relayed(address target, bool ok);

    address public owner = msg.sender;

    function relay(address target, bytes calldata data) external {
        require(msg.sender == owner, "owner");
        (bool ok, ) = target.call(data);
        if (!ok) revert CallFailed();
        emit Relayed(target, ok);
    }
}
