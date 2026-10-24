"""Integer overflow/underflow in unchecked arithmetic (SWC-101).

Applies to code compiled with solc < 0.8 (wrapping arithmetic everywhere) and to
``unchecked { ... }`` blocks in 0.8+.
"""

from __future__ import annotations

from collections.abc import Iterator

from solsentry.analysis import Check, FunctionAnalysis
from solsentry.cfg import CfgNode, NodeKind
from solsentry.detectors.base import Detector, DetectorInfo
from solsentry.expr import expr_key, is_literal, iter_subexpressions, type_string
from solsentry.findings import Confidence, Finding, Severity
from solsentry.solast import Node
from solsentry.taint import ATTACKER

_BINARY = {"+", "-", "*", "**"}
_COMPOUND = {"+=", "-=", "*="}
_COMPARISONS = {"<", "<=", ">", ">=", "==", "!="}


def _is_integer(expr: Node) -> bool:
    return type_string(expr).startswith(("uint", "int"))


def _comparisons(cond: Node) -> Iterator[Node]:
    for sub in iter_subexpressions(cond):
        if sub.get("nodeType") == "BinaryOperation" and sub.get("operator") in _COMPARISONS:
            yield sub


def _keys(expr: Node) -> set[str]:
    return {expr_key(sub) for sub in iter_subexpressions(expr)}


class IntegerOverflowDetector(Detector):
    info = DetectorInfo(
        id="integer-overflow",
        title="Unchecked integer arithmetic on attacker-influenced value",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description=(
            "+, -, *, ** (and +=, -=, *=, ++, --) in wrapping arithmetic -- any solc < 0.8 "
            "code or an unchecked block -- where an operand is tainted by a parameter, "
            "msg.value, calldata or an external call result, and no comparison relating the "
            "operands dominates the operation (pre-check) or relates the result to an "
            "operand on every path after it (SafeMath-style post-check)."
        ),
        soundness=(
            "Checks are matched syntactically on access paths (balances[msg.sender] is the "
            "same key everywhere); value-range reasoning is not performed, so a dominating "
            "bound such as `require(x < 100)` does not discharge `x * y`. Operands that are "
            "not attacker-influenced (e.g. loop counters, storage-only arithmetic) are never "
            "reported, which misses overflows driven by accumulated storage."
        ),
        cwe="CWE-190",
        swc="SWC-101",
        remediation=(
            "Use solc >= 0.8 checked arithmetic or SafeMath; keep user amounts out of unchecked."
        ),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for fa in self.functions():
            check_nodes = {check.node for check in fa.checks}
            for node in fa.cfg:
                if node.kind in {NodeKind.ENTRY, NodeKind.EXIT, NodeKind.REVERT, NodeKind.BIND}:
                    continue
                if node.id in check_nodes:
                    continue  # arithmetic inside a check is the check itself
                for op, operands in self._operations(node):
                    if self.program.checked_arithmetic(op) and not node.unchecked:
                        continue
                    finding = self._inspect(fa, node, op, operands)
                    if finding is not None:
                        findings.append(finding)
        return findings

    def _operations(self, node: CfgNode) -> Iterator[tuple[Node, list[Node]]]:
        for expr in node.exprs:
            for sub in iter_subexpressions(expr):
                node_type, operator = sub.get("nodeType"), sub.get("operator")
                if node_type == "BinaryOperation" and operator in _BINARY and _is_integer(sub):
                    yield sub, [sub["leftExpression"], sub["rightExpression"]]
                elif node_type == "Assignment" and operator in _COMPOUND and _is_integer(sub):
                    yield sub, [sub["leftHandSide"], sub["rightHandSide"]]
                elif (
                    node_type == "UnaryOperation" and operator in {"++", "--"} and _is_integer(sub)
                ):
                    yield sub, [sub["subExpression"]]

    def _inspect(
        self, fa: FunctionAnalysis, node: CfgNode, op: Node, operands: list[Node]
    ) -> Finding | None:
        if all(is_literal(o) for o in operands):
            return None
        labels = frozenset().union(*(fa.taint.labels(node.id, o) for o in operands))
        tainted = labels & ATTACKER
        if not tainted:
            return None
        keys = {expr_key(o) for o in operands if not is_literal(o)}
        result_key = self._result_key(node, op)
        for check in fa.checks:
            if check.cond is None or check.node == node.id:
                continue
            if fa.covered_by(check, node.id) and self._pre_check(check, keys):
                return None
            if (
                result_key is not None
                and fa.postdom.dominates(check.node, node.id)
                and self._post_check(check, result_key, keys)
            ):
                return None
        operator = op.get("operator")
        kind = "underflow" if operator in {"-", "-=", "--"} else "overflow"
        return self.make(
            fa,
            op,
            f"`{self.text(op)}` can {kind}: wrapping arithmetic on "
            f"{', '.join(sorted(tainted)).lower()}-influenced operand with no bounds check",
        )

    @staticmethod
    def _pre_check(check: Check, keys: set[str]) -> bool:
        assert check.cond is not None
        return any(keys <= _keys(comparison) for comparison in _comparisons(check.cond))

    @staticmethod
    def _post_check(check: Check, result_key: str, keys: set[str]) -> bool:
        assert check.cond is not None
        for comparison in _comparisons(check.cond):
            found = _keys(comparison)
            if result_key in found and found & keys:
                return True
        return False

    def _result_key(self, node: CfgNode, op: Node) -> str | None:
        """Key of the variable the operation's result is stored in, if directly assigned."""
        stmt = node.stmt
        if stmt is not None and stmt.get("nodeType") == "VariableDeclarationStatement":
            declarations = [d for d in stmt.get("declarations") or [] if d is not None]
            if len(declarations) == 1 and stmt.get("initialValue") is op:
                return f"v{declarations[0]['id']}"
        parent = self.program.index.parent_of(op)
        if (
            parent is not None
            and parent.get("nodeType") == "Assignment"
            and parent.get("operator") == "="
            and parent.get("rightHandSide") is op
        ):
            return expr_key(parent["leftHandSide"])
        return None
