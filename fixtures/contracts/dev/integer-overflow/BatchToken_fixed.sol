// SPDX-License-Identifier: MIT
// Fixture: SafeMath-style library; the library's own arithmetic is self-checked.
pragma solidity ^0.7.6;

library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "add overflow");
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a, "sub underflow");
        return a - b;
    }

    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }
        uint256 c = a * b;
        require(c / a == b, "mul overflow");
        return c;
    }
}

contract BatchToken {
    using SafeMath for uint256;

    mapping(address => uint256) public balances;

    constructor() {
        balances[msg.sender] = 1e24;
    }

    function batchTransfer(address[] calldata receivers, uint256 value) external {
        uint256 count = receivers.length;
        uint256 amount = count.mul(value);
        require(count > 0 && count <= 20, "count");
        require(value > 0 && balances[msg.sender] >= amount, "balance");
        balances[msg.sender] = balances[msg.sender].sub(amount);
        for (uint256 i = 0; i < count; i++) {
            balances[receivers[i]] = balances[receivers[i]].add(value);
        }
    }
}
