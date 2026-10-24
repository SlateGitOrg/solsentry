"""Low-level call whose success flag is never checked (SWC-104)."""

from __future__ import annotations

from solsentry.analysis import FunctionAnalysis
from solsentry.cfg import NodeKind
from solsentry.defuse import Def
from solsentry.detectors.base import Detector, DetectorInfo
from solsentry.expr import LOW_LEVEL_KINDS, CallKind, call_kind, iter_subexpressions, lvalue_roots
from solsentry.findings import Confidence, Finding, Severity
from solsentry.solast import Node

_LOOP_OR_BRANCH = {"IfStatement", "WhileStatement", "ForStatement", "DoWhileStatement"}
_PASS_THROUGH = {"BinaryOperation", "UnaryOperation", "TupleExpression", "FunctionCallOptions"}


def _reads_var(expr: Node, var: int) -> bool:
    return any(
        sub.get("nodeType") == "Identifier" and sub.get("referencedDeclaration") == var
        for sub in iter_subexpressions(expr)
    )


class UncheckedCallDetector(Detector):
    info = DetectorInfo(
        id="unchecked-call",
        title="Unchecked low-level call",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        description=(
            "call/delegatecall/staticcall/send return false instead of reverting. The "
            "boolean result is discarded, or no copy of it reaches a condition, require, "
            "return or another call."
        ),
        soundness=(
            "Follows the flag through def-use chains (copies, boolean combinations) inside "
            "the function. Passing the flag to any call or returning it counts as checked, "
            "which can hide a callee that ignores it."
        ),
        cwe="CWE-252",
        swc="SWC-104",
        remediation="Wrap the call in require(...) or revert when the flag is false.",
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for fa in self.functions():
            for node in fa.cfg:
                for call in fa.effects[node.id].calls:
                    if call_kind(call) not in LOW_LEVEL_KINDS:
                        continue
                    if self._checked(fa, node.id, call):
                        continue
                    kind = call_kind(call).value
                    finding = self.make(
                        fa,
                        call,
                        f"return value of {kind} `{self.text(call)}` is not checked",
                    )
                    if finding is not None:
                        findings.append(finding)
        return findings

    def _checked(self, fa: FunctionAnalysis, node_id: int, call: Node) -> bool:
        index = self.program.index
        child, parent = call, index.parent_of(call)
        while parent is not None:
            parent_type = parent.get("nodeType")
            if parent_type == "FunctionCall":
                if parent.get("expression") is child:
                    child, parent = parent, index.parent_of(parent)
                    continue
                return call_kind(parent) not in {CallKind.EVENT}
            if parent_type in _LOOP_OR_BRANCH:
                return parent.get("condition") is child
            if parent_type in {"Return", "Conditional"}:
                return True
            if parent_type == "Assignment" and parent.get("rightHandSide") is child:
                targets = [root for root, _ in lvalue_roots(parent["leftHandSide"])]
                return self._flows_to_check(fa, node_id, targets[:1])
            if parent_type == "VariableDeclarationStatement":
                declarations = parent.get("declarations") or []
                first = declarations[0] if declarations else None
                return first is not None and self._flows_to_check(fa, node_id, [first])
            if parent_type in _PASS_THROUGH:
                child, parent = parent, index.parent_of(parent)
                continue
            return False
        return False

    def _flows_to_check(self, fa: FunctionAnalysis, def_node: int, targets: list[Node]) -> bool:
        worklist: list[Def] = []
        for target in targets:
            var = target.get("referencedDeclaration", target.get("id"))
            if isinstance(var, int):
                worklist.append(Def(def_node, var))
        seen: set[Def] = set()
        while worklist:
            definition = worklist.pop()
            if definition in seen:
                continue
            seen.add(definition)
            for use in fa.defuse.uses(definition):
                node = fa.cfg.node(use)
                if node.kind in {NodeKind.CONDITION, NodeKind.RETURN}:
                    return True
                for call in fa.effects[use].calls:
                    kind = call_kind(call)
                    if kind is CallKind.EVENT:
                        continue
                    if any(_reads_var(arg, definition.var) for arg in call.get("arguments") or []):
                        return True
                for write in fa.effects[use].writes:
                    if any(_reads_var(src, definition.var) for src in write.sources):
                        worklist.append(Def(use, write.var))
        return False
