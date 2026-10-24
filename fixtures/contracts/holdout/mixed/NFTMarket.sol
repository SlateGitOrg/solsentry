// SPDX-License-Identifier: MIT
// Holdout fixture (mixed, partly vulnerable): marketplace with view-only royalty lookups and
// expiry checks (benign) plus a payout-before-delete reentrancy.
pragma solidity ^0.8.20;

interface IERC721 {
    function transferFrom(address from, address to, uint256 tokenId) external;
    function ownerOf(uint256 tokenId) external view returns (address);
}

interface IRoyalty {
    function royaltyInfo(uint256 tokenId, uint256 price) external view returns (address, uint256);
}

contract NFTMarket {
    struct Listing {
        address seller;
        uint256 price;
        uint256 expiry;
    }

    address public owner;
    uint256 public feeBps = 250;
    uint256 public collectedFees;
    mapping(address => mapping(uint256 => Listing)) public listings;
    mapping(address => uint256) public royaltiesOwed;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "owner");
        _;
    }

    function list(address nft, uint256 tokenId, uint256 price, uint256 ttl) external {
        require(IERC721(nft).ownerOf(tokenId) == msg.sender, "not owner");
        listings[nft][tokenId] = Listing(msg.sender, price, block.timestamp + ttl);
    }

    function cancel(address nft, uint256 tokenId) external {
        require(listings[nft][tokenId].seller == msg.sender, "not seller");
        delete listings[nft][tokenId];
    }

    function quoteRoyalty(address nft, uint256 tokenId) external {
        Listing storage listing = listings[nft][tokenId];
        (address receiver, uint256 amount) = IRoyalty(nft).royaltyInfo(tokenId, listing.price);
        royaltiesOwed[receiver] += amount;
    }

    function buy(address nft, uint256 tokenId) external payable {
        Listing memory listing = listings[nft][tokenId];
        require(listing.seller != address(0), "not listed");
        require(block.timestamp <= listing.expiry, "expired");
        require(msg.value == listing.price, "price");
        uint256 fee = (msg.value * feeBps) / 10_000;
        (bool ok, ) = listing.seller.call{value: msg.value - fee}(""); // @expect: reentrancy
        require(ok, "pay seller");
        collectedFees += fee;
        delete listings[nft][tokenId];
        IERC721(nft).transferFrom(listing.seller, msg.sender, tokenId);
    }

    function setFee(uint256 bps) external onlyOwner {
        feeBps = bps;
    }

    function withdrawFees(address payable to) external onlyOwner {
        uint256 amount = collectedFees;
        collectedFees = 0;
        to.transfer(amount);
    }
}
