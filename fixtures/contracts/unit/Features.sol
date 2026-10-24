// SPDX-License-Identifier: MIT
// Unit-test fixture exercising CFG and effect corner cases. Not part of the evaluation.
pragma solidity ^0.8.20;

interface IThing {
    function poke(uint256 x) external returns (uint256);
    function peek() external view returns (uint256);
}

contract Features {
    address public owner;
    uint256 public total;
    uint256[] public items;
    mapping(address => uint256) public balances;
    bool private entered;

    constructor() {
        owner = msg.sender;
    }

    modifier twice() {
        _;
        _;
    }

    modifier early(bool stop) {
        if (stop) {
            return;
        }
        _;
        total += 1;
    }

    modifier noReenter() {
        require(!entered, "reentered");
        entered = true;
        _;
        entered = false;
    }

    function loops(uint256 n) external returns (uint256 acc) {
        for (uint256 i = 0; i < n; i++) {
            if (i == 3) {
                continue;
            }
            if (i > 10) {
                break;
            }
            acc += i;
        }
        uint256 j = 0;
        while (j < n) {
            j++;
        }
        do {
            j--;
        } while (j > 0);
        for (;;) {
            break;
        }
    }

    function modified(bool stop) external twice early(stop) {
        items.push(total);
    }

    function guarded(IThing thing) external noReenter {
        thing.poke(1);
        total = 2;
    }

    function tryIt(IThing thing) external returns (uint256) {
        try thing.poke(2) returns (uint256 value) {
            return value;
        } catch Error(string memory) {
            return 1;
        } catch {
            return 0;
        }
    }

    function viewCall(IThing thing) external {
        uint256 v = thing.peek();
        total = v;
    }

    function asmDestroy() external {
        assembly {
            selfdestruct(caller())
        }
    }

    function asmWrite(uint256 x) external returns (uint256 y) {
        assembly {
            y := add(x, 1)
        }
    }

    function popAndDelete() external {
        require(msg.sender == owner, "owner");
        items.pop();
        delete total;
        (uint256 a, uint256 b) = (1, 2);
        (a, b) = (b, a);
        balances[msg.sender] = a + b;
    }

    function revertNow() external pure {
        revert("never");
    }

    function quietCall(address target) external {
        target.call(""); // solsentry-disable-line unchecked-call
        // solsentry-disable-next-line
        target.call("");
        target.call(""); // solsentry-disable-line reentrancy
    }

    function conditional(bool flag, address target) external returns (bool) {
        return flag ? true : payable(target).send(0);
    }
}
