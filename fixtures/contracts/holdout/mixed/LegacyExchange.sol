// SPDX-License-Identifier: MIT
// Holdout fixture (mixed, partly vulnerable): a 0.7 exchange combining safe and unsafe code.
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
}

contract LegacyExchange {
    using SafeMath for uint256;

    struct Order {
        address maker;
        uint256 amount;
        uint256 filled;
        uint256 price;
    }

    address public admin;
    mapping(address => uint256) public ethBalance;
    mapping(uint256 => Order) public orders;
    uint256 public orderCount;

    constructor() {
        admin = msg.sender;
    }

    function depositEth() external payable {
        ethBalance[msg.sender] = ethBalance[msg.sender].add(msg.value);
    }

    function withdrawEth() external {
        uint256 amount = ethBalance[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}(""); // @expect: reentrancy
        require(ok, "withdraw failed");
        ethBalance[msg.sender] = 0;
    }

    function placeOrder(uint256 amount, uint256 price) external returns (uint256 id) {
        require(msg.sender == tx.origin, "EOA only");
        id = orderCount;
        orderCount = orderCount.add(1);
        orders[id] = Order(msg.sender, amount, 0, price);
    }

    function fill(uint256 id, uint256 quantity) external {
        Order storage order = orders[id];
        uint256 remaining = order.amount.sub(order.filled);
        require(quantity <= remaining, "too much");
        order.filled = order.filled.add(quantity);
        uint256 cost = quantity * order.price; // @expect: integer-overflow
        ethBalance[msg.sender] = ethBalance[msg.sender].sub(cost);
        ethBalance[order.maker] = ethBalance[order.maker].add(cost);
    }

    function refundMaker(uint256 id) external {
        require(msg.sender == admin, "admin");
        Order storage order = orders[id];
        payable(order.maker).send(order.price); // @expect: unchecked-call
    }
}
