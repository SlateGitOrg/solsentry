// SPDX-License-Identifier: MIT
// Fixture: only the owner may choose the target; the result is checked.
pragma solidity ^0.8.20;

contract Executor {
    address public owner = msg.sender;

    modifier onlyOwner() {
        require(msg.sender == owner, "owner");
        _;
    }

    function exec(address target, bytes calldata data) external onlyOwner {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "exec failed");
    }
}
