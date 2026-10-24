"""Whole-program analysis driver: per-function facts plus inter-procedural summaries.

Pipeline (see docs/ARCHITECTURE.md for the full description):

1. build a CFG for every function with a body and compute per-node read/write effects;
2. resolve local storage pointers to the state variables they alias;
3. fixpoint over the internal call graph for *effect summaries* (state written/read,
   reentrancy-capable calls, ``selfdestruct``);
4. fixpoint for *return-taint summaries* (which arguments flow to the return value);
5. detector-mode taint per function (parameters labelled ``PARAM``);
6. fixpoint for *guard summaries* (does every normal exit pass a ``msg.sender`` identity
   check / acquire a reentrancy lock) -- needed so ``_checkOwner()``-style helpers count.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from functools import cached_property

from solsentry.cfg import Cfg, CfgNode, NodeKind, build_cfg
from solsentry.defuse import DefUse
from solsentry.dominators import DominatorTree, dominator_tree, postdominator_tree
from solsentry.errors import SolsentryError
from solsentry.expr import (
    CallKind,
    EffectCollector,
    Effects,
    Write,
    call_kind,
    internal_target,
    is_reentrant_call,
    lvalue_roots,
    type_string,
)
from solsentry.model import FunctionInfo, Program, literal_address
from solsentry.solast import Node, iter_nodes
from solsentry.taint import (
    ATTACKER,
    IDENTITY,
    PARAM,
    STATE,
    ReturnSummary,
    TaintAnalysis,
    arg_label,
)

log = logging.getLogger(__name__)

MAX_SUMMARY_ROUNDS = 25


@dataclass
class FunctionSummary:
    writes: frozenset[int] = frozenset()
    reads: frozenset[int] = frozenset()
    reentrant_call: bool = False
    selfdestruct: bool = False
    returns: ReturnSummary = field(default_factory=ReturnSummary)
    sender_guarded: bool = False
    guard_vars: frozenset[int] = frozenset()
    locks: frozenset[int] = frozenset()


@dataclass(frozen=True)
class Check:
    """A node whose condition gates execution.

    ``kind == "stmt"``: ``require``/``assert`` or an ``if`` with a reverting branch -- protects
    every node it strictly dominates. ``kind == "branch"``: an ordinary ``if``/loop condition --
    protects nodes dominated by one of ``roots`` (successors entered only from this check).
    ``kind == "call"``: an internal call whose callee is itself guarded.
    """

    node: int
    cond: Node | None
    kind: str
    roots: tuple[int, ...] = ()


@dataclass
class GuardInfo:
    identity: list[Check] = field(default_factory=list)
    initializer: list[Check] = field(default_factory=list)
    lock_acquires: dict[int, frozenset[int]] = field(default_factory=dict)
    guard_vars: frozenset[int] = frozenset()


class FunctionAnalysis:
    """CFG, effects and lazily computed flow facts for one function."""

    def __init__(self, owner: ProgramAnalysis, function: FunctionInfo) -> None:
        self.owner = owner
        self.program = owner.program
        self.function = function
        self.cfg: Cfg = build_cfg(self.program, function)
        collector = EffectCollector(self.program)
        self.asm_builtins: dict[int, set[str]] = {}
        self.effects: dict[int, Effects] = {
            n.id: self._node_effects(n, collector) for n in self.cfg
        }
        self.aliases: dict[int, int] = self._storage_aliases()
        self.guards = GuardInfo()

    # -- effects -----------------------------------------------------------------------------

    def _node_effects(self, node: CfgNode, collector: EffectCollector) -> Effects:
        effects = Effects()
        if node.kind is NodeKind.ENTRY:
            for decl in [*self.function.parameters, *self.function.returns]:
                effects.writes.append(Write(int(decl["id"]), True, (), decl))
        elif node.kind is NodeKind.BIND:
            for param, arg in node.bindings:
                if arg is not None:
                    collector.expression(arg, effects)
                site = node.stmt if node.stmt is not None else {}
                sources = (arg,) if arg is not None else ()
                effects.writes.append(Write(param, True, sources, site, node.bind_labels))
        elif node.kind is NodeKind.ASSEMBLY and node.stmt is not None:
            self._assembly_effects(node, node.stmt, effects)
        elif node.stmt is not None and node.stmt.get("nodeType") == "VariableDeclarationStatement":
            collector.declaration_statement(node.stmt, effects)
        else:
            for expr in node.exprs:
                collector.expression(expr, effects)
        return effects

    def _assembly_effects(self, node: CfgNode, stmt: Node, effects: Effects) -> None:
        by_src: dict[str, int] = {}
        for ref in stmt.get("externalReferences") or []:
            entries = (
                [ref] if "declaration" in ref else [v for v in ref.values() if isinstance(v, dict)]
            )
            for entry in entries:
                if isinstance(entry.get("declaration"), int) and isinstance(entry.get("src"), str):
                    by_src[entry["src"]] = entry["declaration"]
        for decl in by_src.values():
            if self.program.is_variable(decl):
                effects.reads.add(decl)
        builtins: set[str] = set()
        for yul in iter_nodes(stmt.get("AST") or {}):
            yul_type = yul.get("nodeType")
            if yul_type == "YulFunctionCall":
                builtins.add(str(yul.get("functionName", {}).get("name", "")))
            elif yul_type == "YulAssignment":
                for target in yul.get("variableNames") or []:
                    decl = by_src.get(str(target.get("src")))
                    if decl is not None and self.program.is_variable(decl):
                        effects.writes.append(Write(decl, False, (), stmt, frozenset({"ASM"})))
        self.asm_builtins[node.id] = builtins

    def _storage_aliases(self) -> dict[int, int]:
        aliases: dict[int, int] = {}
        program = self.program
        for _ in range(4):
            changed = False
            for effects in self.effects.values():
                for write in effects.writes:
                    decl = program.declaration(write.var)
                    if (
                        decl is None
                        or decl.get("stateVariable")
                        or decl.get("storageLocation") != "storage"
                        or not write.strong
                        or len(write.sources) != 1
                    ):
                        continue
                    for root, _ in lvalue_roots(write.sources[0]):
                        ref = root.get("referencedDeclaration")
                        if not isinstance(ref, int):
                            continue
                        target = ref if program.is_state_var(ref) else aliases.get(ref)
                        if target is not None and aliases.get(write.var) != target:
                            aliases[write.var] = target
                            changed = True
            if not changed:
                break
        return aliases

    def state_writes(self, node_id: int) -> set[int]:
        """State variables written directly at a node (through storage pointers too)."""
        result: set[int] = set()
        for write in self.effects[node_id].writes:
            if self.program.is_state_var(write.var):
                result.add(write.var)
            elif not write.strong and write.var in self.aliases:
                result.add(self.aliases[write.var])
        return result

    def state_reads(self, node_id: int) -> set[int]:
        result: set[int] = set()
        for var in self.effects[node_id].reads:
            if self.program.is_state_var(var):
                result.add(var)
            elif var in self.aliases:
                result.add(self.aliases[var])
        return result

    def internal_calls(self, node_id: int) -> list[tuple[Node, int]]:
        calls = []
        for call in self.effects[node_id].calls:
            if call_kind(call) is CallKind.INTERNAL:
                target = internal_target(call, self.program)
                if target is not None and target in self.owner.functions:
                    calls.append((call, target))
        return calls

    def callees(self) -> set[int]:
        return {target for node in self.cfg for _, target in self.internal_calls(node.id)}

    def node_is_reentrant_call(self, node_id: int) -> bool:
        """Node performs a reentrancy-capable call directly or through an internal callee."""
        if any(is_reentrant_call(call) for call in self.effects[node_id].calls):
            return True
        if self.asm_builtins.get(node_id, set()) & {"call", "delegatecall", "callcode"}:
            return True
        return any(self.owner.summary(t).reentrant_call for _, t in self.internal_calls(node_id))

    # -- lazily computed flow facts --------------------------------------------------------------

    @cached_property
    def dom(self) -> DominatorTree:
        return dominator_tree(self.cfg)

    @cached_property
    def postdom(self) -> DominatorTree:
        return postdominator_tree(self.cfg)

    @cached_property
    def defuse(self) -> DefUse:
        return DefUse(self)

    @cached_property
    def taint(self) -> TaintAnalysis:
        return TaintAnalysis(self, lambda _index: frozenset({PARAM}), self.owner.return_summary)

    @cached_property
    def exiting(self) -> set[int]:
        """Nodes from which normal termination (EXIT) is reachable."""
        return self.cfg.can_reach(self.cfg.exit)

    @cached_property
    def checks(self) -> list[Check]:
        """Every condition that gates execution (require/assert/if/loop conditions)."""
        found: list[Check] = []
        for node in self.cfg:
            if node.kind is NodeKind.STATEMENT and node.exprs:
                top = node.exprs[0]
                if (
                    node.stmt is not None
                    and node.stmt.get("nodeType") == "ExpressionStatement"
                    and top.get("nodeType") == "FunctionCall"
                    and call_kind(top) in {CallKind.REQUIRE, CallKind.ASSERT}
                    and top.get("arguments")
                ):
                    found.append(Check(node.id, top["arguments"][0], "stmt"))
            elif node.kind is NodeKind.CONDITION and node.exprs:
                targets = self.cfg.successors(node.id)
                reverting = [t for t in targets if t not in self.exiting]
                if reverting and len(reverting) < len(targets):
                    found.append(Check(node.id, node.exprs[0], "stmt"))
                else:
                    roots = tuple(t for t in targets if self.cfg.predecessors(t) == [node.id])
                    found.append(Check(node.id, node.exprs[0], "branch", roots))
        return found

    def covered_by(self, check: Check, node_id: int) -> bool:
        """Whether ``check`` gates every path from ENTRY to ``node_id``."""
        if check.kind in {"stmt", "call"}:
            return self.dom.strictly_dominates(check.node, node_id)
        return any(self.dom.dominates(root, node_id) for root in check.roots)

    def identity_protected(self, node_id: int) -> bool:
        return any(self.covered_by(check, node_id) for check in self.guards.identity)

    def initializer_protected(self, node_id: int) -> bool:
        return any(self.covered_by(check, node_id) for check in self.guards.initializer)

    def lock_protected(self, node_id: int) -> bool:
        return any(self.dom.strictly_dominates(acq, node_id) for acq in self.guards.lock_acquires)

    def lock_vars(self) -> set[int]:
        result: set[int] = set()
        for locks in self.guards.lock_acquires.values():
            result |= locks
        return result

    def location_node(self, node_id: int) -> Node | None:
        return self.cfg.node(node_id).anchor

    # -- guard computation (run inside the program-level fixpoint) ---------------------------

    def compute_guards(self) -> GuardInfo:
        info = GuardInfo()
        guard_vars: set[int] = set()
        collector = EffectCollector(self.program)
        for check in self.checks:
            if check.cond is None:
                continue
            if self.is_identity_check(check.node, check.cond):
                info.identity.append(check)
                cond_effects = Effects()
                collector.expression(check.cond, cond_effects)
                guard_vars |= {v for v in cond_effects.reads if self.program.is_state_var(v)}
                for call in cond_effects.calls:
                    target = (
                        internal_target(call, self.program)
                        if call_kind(call) is CallKind.INTERNAL
                        else None
                    )
                    if target is not None and target in self.owner.functions:
                        guard_vars |= self.owner.summary(target).reads
        for node in self.cfg:
            for _, target in self.internal_calls(node.id):
                summary = self.owner.summary(target)
                if summary.sender_guarded and node.kind is NodeKind.STATEMENT:
                    info.identity.append(Check(node.id, None, "call"))
                    guard_vars |= summary.guard_vars
        info.guard_vars = frozenset(guard_vars)
        info.initializer = self._initializer_checks()
        info.lock_acquires = self._lock_acquires()
        return info

    def is_identity_check(self, node_id: int, cond: Node) -> bool:
        """Does ``cond`` compare the caller's identity against trusted (storage/literal) data?"""
        node_type = cond.get("nodeType")
        if node_type == "UnaryOperation" and cond.get("operator") == "!":
            return self.is_identity_check(node_id, cond["subExpression"])
        if node_type == "TupleExpression":
            components = [c for c in cond.get("components") or [] if c is not None]
            return len(components) == 1 and self.is_identity_check(node_id, components[0])
        if node_type == "BinaryOperation":
            operator = cond.get("operator")
            left, right = cond["leftExpression"], cond["rightExpression"]
            if operator == "&&":
                return self.is_identity_check(node_id, left) or self.is_identity_check(
                    node_id, right
                )
            if operator == "||":
                return self.is_identity_check(node_id, left) and self.is_identity_check(
                    node_id, right
                )
            if operator in {"==", "!="}:
                taint = self.taint
                left_labels, right_labels = (
                    taint.labels(node_id, left),
                    taint.labels(node_id, right),
                )
                for ident, ident_labels, other, other_labels in (
                    (left, left_labels, right, right_labels),
                    (right, right_labels, left, left_labels),
                ):
                    del ident
                    if not ident_labels & IDENTITY:
                        continue
                    if STATE in other_labels or literal_address(other):
                        return True
                    if STATE in ident_labels and not other_labels & ATTACKER:
                        return True
                return False
            return False
        if type_string(cond) == "bool" and node_type in {
            "IndexAccess",
            "FunctionCall",
            "MemberAccess",
        }:
            labels = self.taint.labels(node_id, cond)
            return bool(labels & IDENTITY) and STATE in labels
        return False

    def _initializer_checks(self) -> list[Check]:
        strong_state_writes: dict[int, list[int]] = {}
        for node in self.cfg:
            for write in self.effects[node.id].writes:
                if write.strong and self.program.is_state_var(write.var):
                    strong_state_writes.setdefault(write.var, []).append(node.id)
        found = []
        for check in self.checks:
            if check.kind != "stmt" or check.cond is None:
                continue
            cond_effects = Effects()
            EffectCollector(self.program).expression(check.cond, cond_effects)
            for var in cond_effects.reads:
                state = self.program.state_vars.get(var)
                if state is None or not state.is_bool:
                    continue
                if any(
                    self.dom.strictly_dominates(check.node, w)
                    for w in strong_state_writes.get(var, [])
                ):
                    found.append(check)
                    break
        return found

    def _lock_acquires(self) -> dict[int, frozenset[int]]:
        acquires: dict[int, set[int]] = {}
        stmt_checks = [c for c in self.checks if c.kind == "stmt" and c.cond is not None]
        collector = EffectCollector(self.program)
        check_reads: dict[int, set[int]] = {}
        for check in stmt_checks:
            assert check.cond is not None
            cond_effects = Effects()
            collector.expression(check.cond, cond_effects)
            check_reads[check.node] = cond_effects.reads
        for node in self.cfg:
            for write in self.effects[node.id].writes:
                if not (write.strong and self.program.is_state_var(write.var)):
                    continue
                for check in stmt_checks:
                    if write.var in check_reads[check.node] and self.dom.strictly_dominates(
                        check.node, node.id
                    ):
                        acquires.setdefault(node.id, set()).add(write.var)
            for _, target in self.internal_calls(node.id):
                locks = self.owner.summary(target).locks
                if locks:
                    acquires.setdefault(node.id, set()).update(locks)
        return {node: frozenset(vars_) for node, vars_ in acquires.items()}


class ProgramAnalysis:
    """Runs the pipeline over every function of a :class:`Program`."""

    def __init__(self, program: Program) -> None:
        self.program = program
        self.functions: dict[int, FunctionAnalysis] = {}
        self.skipped: dict[str, str] = {}
        self.summaries: dict[int, FunctionSummary] = {}
        for function in program.analyzable_functions():
            try:
                self.functions[function.id] = FunctionAnalysis(self, function)
            except SolsentryError as exc:
                log.warning("skipping %s: %s", function.qualified_name, exc)
                self.skipped[function.qualified_name] = str(exc)
        for function_id in self.functions:
            self.summaries[function_id] = FunctionSummary()
        self._callees = {fid: fa.callees() for fid, fa in self.functions.items()}
        self._effect_summaries()
        self._return_summaries()
        self._guard_summaries()
        self.read_anywhere: frozenset[int] = frozenset(
            var
            for fa in self.functions.values()
            for node in fa.cfg
            for var in fa.state_reads(node.id)
        )

    def summary(self, function_id: int) -> FunctionSummary:
        return self.summaries.get(function_id) or FunctionSummary()

    def return_summary(self, function_id: int) -> ReturnSummary:
        return self.summary(function_id).returns

    def _effect_summaries(self) -> None:
        for fid, fa in self.functions.items():
            writes: set[int] = set()
            reads: set[int] = set()
            reentrant = selfdestruct = False
            for node in fa.cfg:
                writes |= fa.state_writes(node.id)
                reads |= fa.state_reads(node.id)
                calls = fa.effects[node.id].calls
                reentrant = reentrant or any(is_reentrant_call(c) for c in calls)
                selfdestruct = selfdestruct or any(
                    call_kind(c) is CallKind.SELFDESTRUCT for c in calls
                )
                builtins = fa.asm_builtins.get(node.id, set())
                reentrant = reentrant or bool(builtins & {"call", "delegatecall", "callcode"})
                selfdestruct = selfdestruct or "selfdestruct" in builtins
            summary = self.summaries[fid]
            summary.writes, summary.reads = frozenset(writes), frozenset(reads)
            summary.reentrant_call, summary.selfdestruct = reentrant, selfdestruct
        for _ in range(MAX_SUMMARY_ROUNDS):
            changed = False
            for fid, callees in self._callees.items():
                summary = self.summaries[fid]
                for callee in callees:
                    other = self.summaries[callee]
                    new_writes, new_reads = (
                        summary.writes | other.writes,
                        summary.reads | other.reads,
                    )
                    reentrant = summary.reentrant_call or other.reentrant_call
                    selfdestruct = summary.selfdestruct or other.selfdestruct
                    if (new_writes, new_reads, reentrant, selfdestruct) != (
                        summary.writes,
                        summary.reads,
                        summary.reentrant_call,
                        summary.selfdestruct,
                    ):
                        summary.writes, summary.reads = new_writes, new_reads
                        summary.reentrant_call, summary.selfdestruct = (
                            reentrant,
                            selfdestruct,
                        )
                        changed = True
            if not changed:
                return
        log.warning("effect summaries did not converge in %d rounds", MAX_SUMMARY_ROUNDS)

    def _return_summaries(self) -> None:
        for _ in range(MAX_SUMMARY_ROUNDS):
            changed = False
            for fid, fa in self.functions.items():
                taint = TaintAnalysis(fa, lambda i: frozenset({arg_label(i)}), self.return_summary)
                labels: set[str] = set()
                for node in fa.cfg:
                    if node.kind is NodeKind.RETURN and node.origin is fa.function:
                        for expr in node.exprs:
                            labels |= taint.labels(node.id, expr)
                exit_env = taint.env_in(fa.cfg.exit)
                for decl in fa.function.returns:
                    labels |= exit_env.get(int(decl["id"]), frozenset())
                deps = frozenset(int(label[4:]) for label in labels if label.startswith("arg:"))
                intrinsic = frozenset(label for label in labels if not label.startswith("arg:"))
                new = ReturnSummary(deps, intrinsic)
                if new != self.summaries[fid].returns:
                    self.summaries[fid].returns = new
                    changed = True
            if not changed:
                return
        log.warning("return summaries did not converge in %d rounds", MAX_SUMMARY_ROUNDS)

    def _guard_summaries(self) -> None:
        for _ in range(MAX_SUMMARY_ROUNDS):
            changed = False
            for fid, fa in self.functions.items():
                info = fa.compute_guards()
                fa.guards = info
                exit_id = fa.cfg.exit
                exit_reachable = exit_id in fa.dom.idom
                guarded = exit_reachable and any(fa.covered_by(c, exit_id) for c in info.identity)
                locks: set[int] = set()
                for acquire, lock_vars in info.lock_acquires.items():
                    if exit_reachable and fa.dom.strictly_dominates(acquire, exit_id):
                        locks |= lock_vars
                summary = self.summaries[fid]
                new = (guarded, info.guard_vars, frozenset(locks))
                if new != (summary.sender_guarded, summary.guard_vars, summary.locks):
                    summary.sender_guarded, summary.guard_vars, summary.locks = new
                    changed = True
            if not changed:
                return
        log.warning("guard summaries did not converge in %d rounds", MAX_SUMMARY_ROUNDS)

    def auth_vars(self) -> frozenset[int]:
        """State variables that some identity check reads (``owner``, ``admins`` ...)."""
        result: set[int] = set()
        for fa in self.functions.values():
            result |= fa.guards.guard_vars
        return frozenset(result)
