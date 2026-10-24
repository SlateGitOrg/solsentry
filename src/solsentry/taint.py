"""Flow-sensitive, intra-procedural taint analysis with inter-procedural return summaries.

A *label* names where a value may come from:

========== ==============================================================
PARAM      a function parameter (attacker-chosen for entry points)
SENDER     ``msg.sender``            ORIGIN      ``tx.origin``
VALUE      ``msg.value``             CALLDATA    ``msg.data`` / ``msg.sig``
TIMESTAMP  ``block.timestamp``/now   BLOCK       ``block.number``
EXTCALL    data returned by an external call
STATE      a storage variable        SELF_BALANCE ``address(this).balance``
ASM        written by inline assembly (opaque)
========== ==============================================================

The analysis is a *may* analysis: a label on a value means some path may carry data from that
source into it. Only explicit data flow is tracked (no implicit flow through branches), and
storage is tracked per variable root (``m[a]`` and ``m[b]`` share one fact).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import TYPE_CHECKING

from solsentry.cfg import NodeKind
from solsentry.dataflow import DataflowResult, solve_forward
from solsentry.expr import (
    CallKind,
    call_kind,
    internal_call_args,
    internal_target,
    is_self_balance,
    magic_label,
    unwrap_callee,
)
from solsentry.solast import Node, child_nodes

if TYPE_CHECKING:
    from solsentry.analysis import FunctionAnalysis
    from solsentry.cfg import CfgNode

Labels = frozenset[str]
Env = Mapping[int, Labels]

EMPTY: Labels = frozenset()
PARAM, SENDER, ORIGIN, VALUE, CALLDATA = (
    "PARAM",
    "SENDER",
    "ORIGIN",
    "VALUE",
    "CALLDATA",
)
TIMESTAMP, BLOCK, EXTCALL, STATE, SELF_BALANCE, ASM = (
    "TIMESTAMP",
    "BLOCK",
    "EXTCALL",
    "STATE",
    "SELF_BALANCE",
    "ASM",
)
#: Labels meaning "the caller (attacker) chooses this value".
ATTACKER = frozenset({PARAM, VALUE, CALLDATA, EXTCALL})
IDENTITY = frozenset({SENDER, ORIGIN})


def arg_label(index: int) -> str:
    return f"arg:{index}"


class ReturnSummary:
    """How a function's return value depends on its arguments."""

    __slots__ = ("deps", "labels")

    def __init__(self, deps: frozenset[int] = frozenset(), labels: Labels = EMPTY) -> None:
        self.deps = deps
        self.labels = labels

    def apply(self, arg_labels: Sequence[Labels]) -> Labels:
        result = set(self.labels)
        for index in self.deps:
            if index < len(arg_labels):
                result |= arg_labels[index]
        return frozenset(result)

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, ReturnSummary)
            and self.deps == other.deps
            and self.labels == other.labels
        )

    def __hash__(self) -> int:
        return hash((self.deps, self.labels))


SummaryLookup = Callable[[int], ReturnSummary]


def _join(a: Env, b: Env) -> Env:
    if not a:
        return b
    if not b:
        return a
    merged = dict(a)
    for key, value in b.items():
        previous = merged.get(key)
        merged[key] = value if previous is None else previous | value
    return merged


class TaintAnalysis:
    """Taint facts for every node of one function."""

    def __init__(
        self,
        fa: FunctionAnalysis,
        param_labels: Callable[[int], Labels],
        summaries: SummaryLookup,
    ) -> None:
        self.fa = fa
        self.summaries = summaries
        entry: dict[int, Labels] = {}
        for index, param in enumerate(fa.function.parameters):
            entry[int(param["id"])] = param_labels(index)
        self.result: DataflowResult[Env] = solve_forward(fa.cfg, entry, {}, self._transfer, _join)

    # -- transfer ---------------------------------------------------------------------------

    def _transfer(self, node: CfgNode, env: Env) -> Env:
        effects = self.fa.effects[node.id]
        if not effects.writes or node.kind is NodeKind.ENTRY:
            return env
        current = dict(env)
        for write in effects.writes:
            labels = set(write.extra_labels)
            for source in write.sources:
                labels |= self.labels_in(source, current)
            frozen = frozenset(labels)
            targets = [write.var]
            alias = self.fa.aliases.get(write.var)
            if alias is not None and not write.strong:
                targets.append(alias)
            for target in targets:
                strong = (
                    write.strong
                    and target == write.var
                    and not self.fa.program.is_state_var(target)
                )
                if strong or target not in current:
                    current[target] = frozen
                else:
                    current[target] = current[target] | frozen
        return current

    # -- queries ----------------------------------------------------------------------------

    def env_in(self, node_id: int) -> Env:
        return self.result.inputs.get(node_id, {})

    def labels(self, node_id: int, expr: Node) -> Labels:
        """Labels of ``expr`` evaluated in the state on entry to ``node_id``."""
        return self.labels_in(expr, self.env_in(node_id))

    def labels_in(self, expr: Node, env: Env) -> Labels:
        magic = magic_label(expr)
        if magic is not None:
            return frozenset({magic})
        if is_self_balance(expr):
            return frozenset({SELF_BALANCE})
        node_type = expr.get("nodeType")
        if node_type == "Identifier":
            ref = expr.get("referencedDeclaration")
            if not isinstance(ref, int):
                return EMPTY
            known = env.get(ref, EMPTY)
            if self.fa.program.is_state_var(ref):
                return known | {STATE}
            return known
        if node_type == "Literal":
            return EMPTY
        if node_type == "FunctionCall":
            return self._call_labels(expr, env)
        result: set[str] = set()
        for child in child_nodes(expr):
            child_type = str(child.get("nodeType", ""))
            if child_type.endswith(("TypeName", "Mapping")):
                continue
            result |= self.labels_in(child, env)
        return frozenset(result)

    def _call_labels(self, call: Node, env: Env) -> Labels:
        kind = call_kind(call)
        program = self.fa.program
        if kind is CallKind.INTERNAL:
            target = internal_target(call, program)
            args = [self.labels_in(arg, env) for arg in internal_call_args(call, program)]
            if target is None:
                return frozenset().union(*args) if args else EMPTY
            return self.summaries(target).apply(args)
        if kind in {
            CallKind.EXTERNAL,
            CallKind.LOW_CALL,
            CallKind.LOW_DELEGATECALL,
            CallKind.LOW_STATICCALL,
            CallKind.SEND,
            CallKind.CREATION,
        }:
            return frozenset({EXTCALL})
        if kind in {
            CallKind.REQUIRE,
            CallKind.ASSERT,
            CallKind.REVERT,
            CallKind.EVENT,
            CallKind.ERROR,
            CallKind.SELFDESTRUCT,
            CallKind.TRANSFER,
        }:
            return EMPTY
        result: set[str] = set()
        for arg in call.get("arguments") or []:
            result |= self.labels_in(arg, env)
        if kind is not CallKind.CONVERSION:
            callee = unwrap_callee(call)
            if callee.get("nodeType") == "MemberAccess":
                result |= self.labels_in(callee["expression"], env)
        return frozenset(result)
