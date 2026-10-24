// SPDX-License-Identifier: MIT
// Holdout fixture (mixed, partly vulnerable): a realistic vault with mostly-correct code,
// one business-logic access-control bug and a benign weekday rule.
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

abstract contract Ownable {
    error OwnableUnauthorizedAccount(address account);

    address private _owner;

    constructor() {
        _owner = msg.sender;
    }

    modifier onlyOwner() {
        _checkOwner();
        _;
    }

    function owner() public view returns (address) {
        return _owner;
    }

    function _checkOwner() internal view {
        if (owner() != msg.sender) {
            revert OwnableUnauthorizedAccount(msg.sender);
        }
    }

    function transferOwnership(address next) external onlyOwner {
        _owner = next;
    }
}

contract CommunityVault is Ownable {
    IERC20 public immutable asset;
    mapping(address => uint256) public shares;
    uint256 public totalShares;
    address public feeRecipient;
    uint256 public feeBps = 50;

    constructor(IERC20 vaultAsset, address recipient) {
        asset = vaultAsset;
        feeRecipient = recipient;
    }

    function deposit(uint256 amount) external {
        uint256 day = block.timestamp / 1 days;
        require((day + 4) % 7 < 5, "weekdays only");
        shares[msg.sender] += amount;
        totalShares += amount;
        require(asset.transferFrom(msg.sender, address(this), amount), "pull");
    }

    function withdraw(uint256 amount) external {
        require(shares[msg.sender] >= amount, "shares");
        uint256 fee = (amount * feeBps) / 10_000;
        shares[msg.sender] -= amount;
        totalShares -= amount;
        require(asset.transfer(feeRecipient, fee), "fee");
        require(asset.transfer(msg.sender, amount - fee), "push");
    }

    function setFeeRecipient(address recipient) external {
        feeRecipient = recipient; // @expect: missing-access-control
    }

    function setFee(uint256 bps) external onlyOwner {
        require(bps <= 500, "fee too high");
        feeBps = bps;
    }

    function rescue(IERC20 token, address to, uint256 amount) external onlyOwner {
        require(token != asset, "asset");
        require(token.transfer(to, amount), "rescue");
    }
}
