"""CFG construction, dominators, def-use and the dataflow solver on real fixture ASTs."""

from __future__ import annotations

import pytest

from solsentry.cfg import NodeKind, build_cfg
from solsentry.dataflow import solve_forward
from solsentry.defuse import Def
from solsentry.dominators import DominatorTree
from solsentry.errors import AstFormatError, SolsentryError
from tests.conftest import function_analysis, program


def _kinds(relative: str, qualified: str) -> list[NodeKind]:
    fa = function_analysis(relative, qualified)
    return [fa.cfg.node(n).kind for n in fa.cfg.reverse_postorder()]


def test_modifiers_are_inlined_with_placeholder_joins() -> None:
    fa = function_analysis("unit/Features", "Features.modified")
    binds = [n for n in fa.cfg if n.kind is NodeKind.BIND]
    # `twice` once, `early` once per placeholder of `twice`
    assert [b.note for b in binds] == ["modifier twice", "modifier early", "modifier early"]
    pushes = [n for n in fa.cfg if n.kind is NodeKind.STATEMENT and "push" in fa.cfg.describe(n)]
    assert len(pushes) == 2
    # `return` inside `early` resumes after the enclosing placeholder of `twice`
    returns = [n for n in fa.cfg if n.kind is NodeKind.RETURN]
    for ret in returns:
        (target,) = fa.cfg.successors(ret.id)
        assert fa.cfg.node(target).kind is NodeKind.JOIN
        assert "twice" in fa.cfg.node(target).note


def test_loops_break_continue_and_do_while() -> None:
    fa = function_analysis("unit/Features", "Features.loops")
    cfg = fa.cfg
    conditions = [n for n in cfg if n.kind is NodeKind.CONDITION]
    assert len(conditions) == 5  # for-cond, two ifs in the for body, while-cond, do-while cond
    # all five lie on a cycle; `for (;;) { break; }` has no condition but must still exit
    assert all(n.id in cfg.reachable_from(n.id) for n in conditions)
    assert cfg.exit in cfg.reachable_from(cfg.entry)
    for node in cfg:
        for succ in cfg.successors(node.id):
            assert node.id in cfg.predecessors(succ)


def test_require_and_revert_edges() -> None:
    fa = function_analysis("dev/reentrancy/EtherBank_vuln", "EtherBank.withdraw")
    revert_preds = fa.cfg.predecessors(fa.cfg.revert)
    assert len(revert_preds) == 2  # two require statements
    fa2 = function_analysis("unit/Features", "Features.revertNow")
    assert fa2.cfg.predecessors(fa2.cfg.exit) == []
    assert len(fa2.cfg.predecessors(fa2.cfg.revert)) == 1


def test_try_catch_binds_each_clause() -> None:
    fa = function_analysis("unit/Features", "Features.tryIt")
    (try_node,) = [n for n in fa.cfg if n.kind is NodeKind.TRY]
    labels = sorted(label for _, label in try_node.succs)
    assert labels == ["catch", "catch Error", "success"]
    success = next(t for t, label in try_node.succs if label == "success")
    assert fa.cfg.node(success).bindings  # `returns (uint256 value)` is bound to the call


def test_selfdestruct_halts() -> None:
    fa = function_analysis("dev/unprotected-selfdestruct/Killable_vuln", "Killable.kill")
    halts = [(s, label) for s, label in fa.cfg.node(fa.cfg.exit).preds if label == "halt"]
    assert len(halts) == 1


def test_text_and_dot_rendering() -> None:
    fa = function_analysis("dev/reentrancy/Escrow_fixed", "Escrow.release")
    text = fa.cfg.to_text()
    assert text.startswith("CFG Escrow.release")
    assert "modifier nonReentrant" in text and "L41 _pay(deal.seller, deal.amount)" in text
    dot = fa.cfg.to_dot()
    assert dot.startswith('digraph "Escrow.release"') and "->" in dot and dot.endswith("}")


def test_dominators_and_postdominators() -> None:
    fa = function_analysis("dev/reentrancy/EtherBank_vuln", "EtherBank.withdraw")
    cfg = fa.cfg
    for node in cfg:
        if node.id in fa.dom.idom:
            assert fa.dom.dominates(cfg.entry, node.id)
            assert fa.dom.dominates(node.id, node.id)
            assert not fa.dom.strictly_dominates(node.id, node.id)
    order = cfg.reverse_postorder()
    first_require = next(n for n in order if "require(amount" in cfg.describe(cfg.node(n)))
    write = next(n for n in order if "balances[msg.sender] = 0" in cfg.describe(cfg.node(n)))
    assert fa.dom.strictly_dominates(first_require, write)
    assert fa.postdom.dominates(write, first_require)
    assert fa.dom.dominators_of(write)[0] == write
    assert fa.dom.dominators_of(cfg.revert + 10_000) == []
    assert not fa.dom.dominates(write, cfg.revert + 10_000)


def test_dominator_tree_on_diamond() -> None:
    graph = {0: [1, 2], 1: [3], 2: [3], 3: []}
    preds: dict[int, list[int]] = {n: [] for n in graph}
    for source, targets in graph.items():
        for target in targets:
            preds[target].append(source)
    tree = DominatorTree(0, graph.__getitem__, preds.__getitem__)
    assert tree.idom == {0: 0, 1: 0, 2: 0, 3: 0}
    assert not tree.dominates(1, 3)


def test_def_use_chains_follow_copies() -> None:
    fa = function_analysis("dev/unchecked-call/Splitter_fixed", "Splitter.split")
    decl_nodes = {fa.cfg.describe(n).split(" ", 1)[1]: n.id for n in fa.cfg if n.stmt is not None}
    sent_a_node = decl_nodes["bool sentA = a.send(half)"]
    sent_a_var = next(w.var for w in fa.effects[sent_a_node].writes)
    uses = fa.defuse.uses(Def(sent_a_node, sent_a_var))
    assert uses == [decl_nodes["bool both = sentA"]]
    require_node = decl_nodes['require(both, "send failed")']
    both_var = next(w.var for w in fa.effects[decl_nodes["bool both = sentA"]].writes)
    reaching = fa.defuse.reaching(require_node, both_var)
    assert [d.node for d in reaching] == [decl_nodes["both = both && sentB"]]


def test_storage_pointer_aliases_resolve_to_state() -> None:
    fa = function_analysis("dev/reentrancy/Escrow_vuln", "Escrow.release")
    prog = fa.program
    deals = next(v.id for v in prog.state_vars.values() if v.name == "deals")
    assert deals in fa.aliases.values()
    written = set().union(*(fa.state_writes(n.id) for n in fa.cfg))
    assert deals in written


def test_build_cfg_rejects_bodyless_function() -> None:
    prog = program("unit/Features")
    poke = next(f for f in prog.functions.values() if f.name == "poke")
    with pytest.raises(AstFormatError):
        build_cfg(prog, poke)


def test_solver_detects_non_convergence() -> None:
    fa = function_analysis("unit/Features", "Features.loops")
    counter = iter(range(10**9))

    def transfer(_node: object, _fact: int) -> int:
        return next(counter)  # never stabilises

    with pytest.raises(SolsentryError, match="did not converge"):
        solve_forward(fa.cfg, 0, 0, transfer, max, max_iterations=500)
