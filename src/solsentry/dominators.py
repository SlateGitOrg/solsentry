"""Dominator and post-dominator trees (Cooper, Harvey & Kennedy, "A Simple, Fast Dominance
Algorithm", 2001).

The iterative algorithm processes nodes in reverse post-order and intersects predecessor
dominators by walking up the partially built tree. On reducible CFGs (all structured
Solidity code) it converges in two passes, i.e. O(N * depth); worst case O(N^2).
"""

from __future__ import annotations

from collections.abc import Callable

from solsentry.cfg import Cfg


class DominatorTree:
    """Immediate-dominator map over the nodes reachable from ``root``."""

    def __init__(
        self,
        root: int,
        successors: Callable[[int], list[int]],
        predecessors: Callable[[int], list[int]],
    ) -> None:
        self.root = root
        order = _reverse_postorder(root, successors)
        self.position = {node: index for index, node in enumerate(order)}
        idom: dict[int, int] = {root: root}
        changed = True
        while changed:
            changed = False
            for node in order[1:]:
                processed = [p for p in predecessors(node) if p in idom]
                if not processed:
                    continue
                new_idom = processed[0]
                for pred in processed[1:]:
                    new_idom = self._intersect(pred, new_idom, idom)
                if idom.get(node) != new_idom:
                    idom[node] = new_idom
                    changed = True
        self.idom = idom

    def _intersect(self, a: int, b: int, idom: dict[int, int]) -> int:
        position = self.position
        while a != b:
            while position[a] > position[b]:
                a = idom[a]
            while position[b] > position[a]:
                b = idom[b]
        return a

    def dominates(self, a: int, b: int) -> bool:
        """True if every path from the root to ``b`` passes through ``a`` (reflexive)."""
        if b not in self.idom or a not in self.idom:
            return False
        current = b
        while True:
            if current == a:
                return True
            parent = self.idom[current]
            if parent == current:
                return False
            current = parent

    def strictly_dominates(self, a: int, b: int) -> bool:
        return a != b and self.dominates(a, b)

    def dominators_of(self, node: int) -> list[int]:
        """``node`` and all its dominators, innermost first."""
        if node not in self.idom:
            return []
        chain = [node]
        while self.idom[chain[-1]] != chain[-1]:
            chain.append(self.idom[chain[-1]])
        return chain


def _reverse_postorder(root: int, successors: Callable[[int], list[int]]) -> list[int]:
    order: list[int] = []
    seen = {root}
    stack = [(root, iter(successors(root)))]
    while stack:
        node, children = stack[-1]
        for child in children:
            if child not in seen:
                seen.add(child)
                stack.append((child, iter(successors(child))))
                break
        else:
            stack.pop()
            order.append(node)
    order.reverse()
    return order


def dominator_tree(cfg: Cfg) -> DominatorTree:
    return DominatorTree(cfg.entry, cfg.successors, cfg.predecessors)


def postdominator_tree(cfg: Cfg) -> DominatorTree:
    """Post-dominators relative to normal termination (``EXIT``)."""
    return DominatorTree(cfg.exit, cfg.predecessors, cfg.successors)
