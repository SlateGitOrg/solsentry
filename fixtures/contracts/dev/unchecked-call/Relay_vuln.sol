// SPDX-License-Identifier: MIT
// Fixture (intentionally vulnerable): call() success flag captured but never checked.
pragma solidity ^0.8.20;

contract Relay {
    event Relayed(address target, bool ok);

    address public owner = msg.sender;

    function relay(address target, bytes calldata data) external {
        require(msg.sender == owner, "owner");
        (bool ok, ) = target.call(data); // @expect: unchecked-call
        emit Relayed(target, ok);
    }
}
