"""Reaching definitions and def-use chains.

A *definition* is a write to a variable at a CFG node (``Def(node, var)``). Strong writes
(``x = ..`` to a local) kill every other definition of the variable; weak writes (to a
mapping element, struct field or any storage variable) only add one. Parameters and named
return variables are defined at ``ENTRY``.

The transfer function is the classic ``OUT = GEN | (IN - KILL)`` over sets of definitions,
solved with the generic worklist solver: O(N * D) set operations for N nodes, D definitions.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING

from solsentry.dataflow import solve_forward

if TYPE_CHECKING:
    from solsentry.analysis import FunctionAnalysis
    from solsentry.cfg import CfgNode


@dataclass(frozen=True, slots=True, order=True)
class Def:
    node: int
    var: int


def _union(a: frozenset[Def], b: frozenset[Def]) -> frozenset[Def]:
    return a | b


class DefUse:
    def __init__(self, fa: FunctionAnalysis) -> None:
        self.fa = fa
        self._strong_vars: dict[int, set[int]] = {}
        self._gen: dict[int, frozenset[Def]] = {}
        for node in fa.cfg:
            writes = fa.effects[node.id].writes
            self._gen[node.id] = frozenset(Def(node.id, w.var) for w in writes)
            self._strong_vars[node.id] = {w.var for w in writes if w.strong}
        empty: frozenset[Def] = frozenset()
        result = solve_forward(fa.cfg, empty, empty, self._transfer, _union)
        self.reaching_in: dict[int, frozenset[Def]] = result.inputs
        self._uses: dict[Def, list[int]] = defaultdict(list)
        for node in fa.cfg:
            reads = fa.effects[node.id].reads
            for definition in self.reaching_in.get(node.id, frozenset()):
                if definition.var in reads:
                    self._uses[definition].append(node.id)

    def _transfer(self, node: CfgNode, facts: frozenset[Def]) -> frozenset[Def]:
        killed = self._strong_vars[node.id]
        survivors = frozenset(d for d in facts if d.var not in killed) if killed else facts
        return survivors | self._gen[node.id]

    def reaching(self, node_id: int, var: int) -> list[Def]:
        return sorted(d for d in self.reaching_in.get(node_id, frozenset()) if d.var == var)

    def uses(self, definition: Def) -> list[int]:
        return sorted(self._uses.get(definition, []))
