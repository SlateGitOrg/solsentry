"""``tx.origin`` used for authorization (SWC-115)."""

from __future__ import annotations

from collections.abc import Iterator

from solsentry.analysis import FunctionAnalysis
from solsentry.detectors.base import Detector, DetectorInfo
from solsentry.expr import magic_label
from solsentry.findings import Confidence, Finding, Severity
from solsentry.solast import Node
from solsentry.taint import ORIGIN, SENDER


def _strip(expr: Node) -> Node:
    while True:
        if expr.get("nodeType") == "UnaryOperation" and expr.get("operator") == "!":
            expr = expr["subExpression"]
        elif expr.get("nodeType") == "TupleExpression" and len(expr.get("components") or []) == 1:
            expr = expr["components"][0]
        else:
            return expr


def _is_anti_contract_idiom(expr: Node) -> bool:
    """``tx.origin == msg.sender`` (or ``!=``): rejects contract callers, authenticates nobody."""
    expr = _strip(expr)
    if expr.get("nodeType") != "BinaryOperation" or expr.get("operator") not in {"==", "!="}:
        return False
    sides = {magic_label(expr["leftExpression"]), magic_label(expr["rightExpression"])}
    return sides == {ORIGIN, SENDER}


class TxOriginDetector(Detector):
    info = DetectorInfo(
        id="tx-origin",
        title="Authorization through tx.origin",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        description=(
            "A branch or require condition depends on tx.origin. Any contract the "
            "authorised account interacts with can then act with its authority (phishing)."
        ),
        soundness=(
            "Flags every gating condition whose taint includes tx.origin, through locals, "
            "internal-call return values and inlined modifiers. The `tx.origin == "
            "msg.sender` idiom is excluded. Implicit flows (tx.origin only deciding a branch "
            "that later sets a flag) are not tracked."
        ),
        cwe="CWE-477",
        swc="SWC-115",
        remediation="Authenticate msg.sender instead of tx.origin.",
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for fa in self.functions():
            for check in fa.checks:
                if check.cond is None:
                    continue
                for leaf in self._leaves(fa, check.node, check.cond):
                    finding = self.make(
                        fa,
                        leaf,
                        f"condition `{self.text(leaf)}` authorizes on tx.origin; use msg.sender",
                    )
                    if finding is not None:
                        findings.append(finding)
        return findings

    def _leaves(self, fa: FunctionAnalysis, node_id: int, cond: Node) -> Iterator[Node]:
        stripped = _strip(cond)
        if stripped.get("nodeType") == "BinaryOperation" and stripped.get("operator") in {
            "&&",
            "||",
        }:
            yield from self._leaves(fa, node_id, stripped["leftExpression"])
            yield from self._leaves(fa, node_id, stripped["rightExpression"])
            return
        if ORIGIN in fa.taint.labels(node_id, cond) and not _is_anti_contract_idiom(cond):
            yield cond
