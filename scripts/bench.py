"""Throughput and scaling benchmark (run with ``make bench``).

Part 1 analyses every committed fixture bundle ``--repeat`` times (all detectors) and reports
the median wall time. Part 2 builds synthetic functions of N statements (straight-line code,
if/else diamonds and nested loops, written directly as solc-shaped AST dicts) and times the
full pipeline -- CFG, dominators, def-use, taint, summaries, all detectors -- to show how the
cost grows with function size.
"""

from __future__ import annotations

import argparse
import itertools
import platform
import statistics
import time
from pathlib import Path
from typing import Any

from solsentry.engine import analyze_input
from solsentry.solast import AstInput, SourceUnitInput, load_path
from solsentry.source import SourceFile

ROOT = Path(__file__).resolve().parent.parent
AST = ROOT / "fixtures" / "ast"

Node = dict[str, Any]
_ids = itertools.count(100)
UINT = {"typeIdentifier": "t_uint256", "typeString": "uint256"}
LOCAL, PARAM = 10, 11


def _ident(ref: int) -> Node:
    return {
        "nodeType": "Identifier",
        "id": next(_ids),
        "src": "0:1:0",
        "name": f"v{ref}",
        "referencedDeclaration": ref,
        "typeDescriptions": UINT,
    }


def _assign() -> Node:
    expr = {
        "nodeType": "Assignment",
        "id": next(_ids),
        "src": "0:1:0",
        "operator": "+=",
        "leftHandSide": _ident(LOCAL),
        "rightHandSide": _ident(PARAM),
        "typeDescriptions": UINT,
    }
    return {"nodeType": "ExpressionStatement", "id": next(_ids), "src": "0:1:0", "expression": expr}


def _cond() -> Node:
    return {
        "nodeType": "BinaryOperation",
        "id": next(_ids),
        "src": "0:1:0",
        "operator": "<",
        "leftExpression": _ident(LOCAL),
        "rightExpression": _ident(PARAM),
        "typeDescriptions": {"typeIdentifier": "t_bool", "typeString": "bool"},
    }


def _block(stmts: list[Node]) -> Node:
    return {"nodeType": "Block", "id": next(_ids), "src": "0:1:0", "statements": stmts}


def _shape(n: int) -> list[Node]:
    """~n statements: thirds of straight-line code, if/else diamonds and loops."""
    stmts: list[Node] = []
    while len(stmts) < n:
        stmts.append(_assign())
        stmts.append(
            {
                "nodeType": "IfStatement",
                "id": next(_ids),
                "src": "0:1:0",
                "condition": _cond(),
                "trueBody": _block([_assign()]),
                "falseBody": _block([_assign()]),
            }
        )
        stmts.append(
            {
                "nodeType": "WhileStatement",
                "id": next(_ids),
                "src": "0:1:0",
                "condition": _cond(),
                "body": _block([_assign(), _assign()]),
            }
        )
    return stmts[:n]


def synthetic_input(n: int) -> AstInput:
    local = {
        "nodeType": "VariableDeclaration",
        "id": LOCAL,
        "src": "0:1:0",
        "name": "v10",
        "stateVariable": False,
        "storageLocation": "default",
        "typeDescriptions": UINT,
    }
    param = dict(local, id=PARAM, name="v11")
    function = {
        "nodeType": "FunctionDefinition",
        "id": 3,
        "src": "0:1:0",
        "name": "f",
        "kind": "function",
        "visibility": "external",
        "stateMutability": "nonpayable",
        "modifiers": [],
        "parameters": {"parameters": [param]},
        "returnParameters": {"parameters": [local]},
        "body": _block(_shape(n)),
    }
    contract = {
        "nodeType": "ContractDefinition",
        "id": 2,
        "src": "0:1:0",
        "name": "Synthetic",
        "contractKind": "contract",
        "linearizedBaseContracts": [2],
        "nodes": [function],
    }
    unit = {"nodeType": "SourceUnit", "id": 1, "src": "0:1:0", "nodes": [contract]}
    return AstInput(
        "synthetic",
        [SourceUnitInput(0, "synthetic.sol", SourceFile("synthetic.sol", ""), unit)],
        "0.7.6",
    )


def timed(fn: Any, repeat: int) -> float:
    samples = []
    for _ in range(repeat):
        start = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - start)
    return statistics.median(samples)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()
    print(
        f"python {platform.python_version()} on {platform.machine()} {platform.system()}; "
        f"median of {args.repeat} runs"
    )

    inputs = [load_path(p) for p in sorted(AST.rglob("*.json"))]
    lines = sum(u.source.line_count for i in inputs for u in i.units)
    results = [analyze_input(i) for i in inputs]
    functions = sum(r.functions_analyzed for r in results)
    nodes = sum(r.cfg_nodes for r in results)
    seconds = timed(lambda: [analyze_input(i) for i in inputs], args.repeat)
    print(
        f"\nfixtures: {len(inputs)} files, {lines} source lines, {functions} functions, "
        f"{nodes} CFG nodes"
    )
    print(
        f"  all detectors: {seconds * 1000:.0f} ms total, "
        f"{seconds / len(inputs) * 1000:.1f} ms/file, {lines / seconds:,.0f} source lines/s"
    )

    print("\nsynthetic single function (CFG + dataflow + all detectors):")
    print("  statements   cfg nodes   ms      ms per 1k nodes")
    for n in (250, 500, 1000, 2000, 4000):
        ast_input = synthetic_input(n)
        result = analyze_input(ast_input)
        seconds = timed(lambda ai=ast_input: analyze_input(ai), args.repeat)
        per_k = seconds * 1000 / result.cfg_nodes * 1000
        print(f"  {n:>10}   {result.cfg_nodes:>9}   {seconds * 1000:>6.0f}  {per_k:>8.1f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
