"""Property-based tests: random structured Solidity bodies -> CFG/dataflow invariants.

Hypothesis generates nested statement trees (blocks, if/else, while, for, do-while,
break/continue inside loops, return, require, revert, assignments to locals) as solc-shaped AST
dicts. For every generated function we check graph well-formedness, dominator laws and
reaching-definition soundness.
"""

from __future__ import annotations

import itertools
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from solsentry.analysis import ProgramAnalysis
from solsentry.cfg import NodeKind
from solsentry.model import Program
from solsentry.solast import AstInput, SourceUnitInput
from solsentry.source import SourceFile

Node = dict[str, Any]
_ids = itertools.count(1000)
LOCAL_ID = 10
PARAM_ID = 11


def _nid() -> int:
    return next(_ids)


def _src() -> str:
    return "0:1:0"


def _lit() -> Node:
    return {
        "nodeType": "Literal",
        "id": _nid(),
        "src": _src(),
        "value": "1",
        "kind": "number",
        "typeDescriptions": {"typeIdentifier": "t_rational_1_by_1", "typeString": "int_const 1"},
    }


def _ident(ref: int) -> Node:
    return {
        "nodeType": "Identifier",
        "id": _nid(),
        "src": _src(),
        "name": f"v{ref}",
        "referencedDeclaration": ref,
        "typeDescriptions": {"typeIdentifier": "t_uint256", "typeString": "uint256"},
    }


def _cond() -> Node:
    return {
        "nodeType": "BinaryOperation",
        "id": _nid(),
        "src": _src(),
        "operator": "<",
        "leftExpression": _ident(LOCAL_ID),
        "rightExpression": _ident(PARAM_ID),
        "typeDescriptions": {"typeIdentifier": "t_bool", "typeString": "bool"},
    }


def _builtin_call(name: str, args: list[Node]) -> Node:
    return {
        "nodeType": "FunctionCall",
        "id": _nid(),
        "src": _src(),
        "kind": "functionCall",
        "arguments": args,
        "expression": {
            "nodeType": "Identifier",
            "id": _nid(),
            "src": _src(),
            "name": name,
            "referencedDeclaration": -18,
            "typeDescriptions": {"typeIdentifier": f"t_function_{name}_pure"},
        },
        "typeDescriptions": {"typeIdentifier": "t_tuple$__$", "typeString": "tuple()"},
    }


def _expr_stmt(expr: Node) -> Node:
    return {"nodeType": "ExpressionStatement", "id": _nid(), "src": _src(), "expression": expr}


def _assign() -> Node:
    return _expr_stmt(
        {
            "nodeType": "Assignment",
            "id": _nid(),
            "src": _src(),
            "operator": "=",
            "leftHandSide": _ident(LOCAL_ID),
            "rightHandSide": _ident(PARAM_ID),
            "typeDescriptions": {"typeIdentifier": "t_uint256", "typeString": "uint256"},
        }
    )


def _leaf(kind: str) -> Node:
    if kind == "assign":
        return _assign()
    if kind == "require":
        return _expr_stmt(_builtin_call("require", [_cond()]))
    if kind == "revert":
        return _expr_stmt(_builtin_call("revert", []))
    if kind == "return":
        return {"nodeType": "Return", "id": _nid(), "src": _src(), "expression": None}
    if kind == "break":
        return {"nodeType": "Break", "id": _nid(), "src": _src()}
    return {"nodeType": "Continue", "id": _nid(), "src": _src()}


def _statements(depth: int, in_loop: bool) -> st.SearchStrategy[Node]:
    kinds = ["assign", "assign", "require", "revert", "return"] + (
        ["break", "continue"] if in_loop else []
    )
    leaf = st.sampled_from(kinds).map(_leaf)
    if depth <= 0:
        return leaf

    def block(stmts: list[Node]) -> Node:
        return {"nodeType": "Block", "id": _nid(), "src": _src(), "statements": stmts}

    inner = st.lists(_statements(depth - 1, in_loop), max_size=3).map(block)
    loop_body = st.lists(_statements(depth - 1, True), max_size=3).map(block)
    if_stmt = st.tuples(inner, st.one_of(st.none(), inner)).map(
        lambda t: {
            "nodeType": "IfStatement",
            "id": _nid(),
            "src": _src(),
            "condition": _cond(),
            "trueBody": t[0],
            "falseBody": t[1],
        }
    )
    while_stmt = loop_body.map(
        lambda b: {
            "nodeType": "WhileStatement",
            "id": _nid(),
            "src": _src(),
            "condition": _cond(),
            "body": b,
        }
    )
    do_stmt = loop_body.map(
        lambda b: {
            "nodeType": "DoWhileStatement",
            "id": _nid(),
            "src": _src(),
            "condition": _cond(),
            "body": b,
        }
    )
    for_stmt = st.tuples(loop_body, st.booleans()).map(
        lambda t: {
            "nodeType": "ForStatement",
            "id": _nid(),
            "src": _src(),
            "body": t[0],
            "initializationExpression": None,
            "loopExpression": _assign(),
            "condition": _cond() if t[1] else None,
        }
    )
    return st.one_of(leaf, if_stmt, while_stmt, do_stmt, for_stmt)


def _program(body: list[Node]) -> ProgramAnalysis:
    local = {
        "nodeType": "VariableDeclaration",
        "id": LOCAL_ID,
        "src": _src(),
        "name": "v10",
        "stateVariable": False,
        "storageLocation": "default",
        "typeDescriptions": {"typeIdentifier": "t_uint256", "typeString": "uint256"},
    }
    param = dict(local, id=PARAM_ID, name="v11")
    decl = {
        "nodeType": "VariableDeclarationStatement",
        "id": _nid(),
        "src": _src(),
        "declarations": [local],
        "initialValue": _lit(),
        "assignments": [LOCAL_ID],
    }
    function = {
        "nodeType": "FunctionDefinition",
        "id": 3,
        "src": _src(),
        "name": "f",
        "kind": "function",
        "visibility": "external",
        "stateMutability": "nonpayable",
        "modifiers": [],
        "parameters": {"parameters": [param]},
        "returnParameters": {"parameters": []},
        "body": {"nodeType": "Block", "id": 4, "src": _src(), "statements": [decl, *body]},
    }
    contract = {
        "nodeType": "ContractDefinition",
        "id": 2,
        "src": _src(),
        "name": "C",
        "contractKind": "contract",
        "linearizedBaseContracts": [2],
        "nodes": [function],
    }
    unit = {"nodeType": "SourceUnit", "id": 1, "src": _src(), "nodes": [contract]}
    source = SourceFile("gen.sol", "x")
    return ProgramAnalysis(
        Program(AstInput("gen", [SourceUnitInput(0, "gen.sol", source, unit)], "0.8.26"))
    )


@settings(max_examples=150, deadline=None)
@given(st.lists(_statements(3, in_loop=False), max_size=5))
def test_cfg_and_dataflow_invariants(body: list[Node]) -> None:
    pa = _program(body)
    (fa,) = pa.functions.values()
    cfg = fa.cfg
    reachable = cfg.reachable_from(cfg.entry, include_start=True)
    # 1. after pruning, every node except EXIT/REVERT is reachable from ENTRY
    assert set(cfg.nodes) - {cfg.exit, cfg.revert} <= reachable
    # 2. edge lists are mutually consistent; EXIT and REVERT have no successors
    for node in cfg:
        for succ in cfg.successors(node.id):
            assert node.id in cfg.predecessors(succ)
        for pred in cfg.predecessors(node.id):
            assert node.id in cfg.successors(pred)
    assert cfg.successors(cfg.exit) == [] and cfg.successors(cfg.revert) == []
    # 3. dominator laws: ENTRY dominates all reachable nodes; idom strictly dominates
    for node_id in reachable:
        assert fa.dom.dominates(cfg.entry, node_id)
        if node_id != cfg.entry:
            assert fa.dom.strictly_dominates(fa.dom.idom[node_id], node_id)
    # 4. post-dominators: EXIT post-dominates every node that can reach it
    for node_id in fa.exiting:
        assert fa.postdom.dominates(cfg.exit, node_id)
    # 5. reaching definitions are sound: a def reaching n is at a node that reaches n
    for node in cfg:
        for definition in fa.defuse.reaching_in.get(node.id, frozenset()):
            assert definition.node == node.id or node.id in cfg.reachable_from(definition.node)
    # 6. taint: the local only ever holds the parameter or a literal
    for node in cfg:
        labels = fa.taint.env_in(node.id).get(LOCAL_ID, frozenset())
        assert labels <= {"PARAM"}
    # 7. guards: no identity checks exist in generated code
    assert fa.guards.identity == []
    assert all(n.kind is not NodeKind.BIND for n in cfg)
