"""``block.timestamp`` used as randomness or compared for strict equality (SWC-116/SWC-120)."""

from __future__ import annotations

from solsentry.analysis import FunctionAnalysis
from solsentry.detectors.base import Detector, DetectorInfo
from solsentry.expr import iter_subexpressions
from solsentry.findings import Confidence, Finding, Severity
from solsentry.solast import Node
from solsentry.taint import TIMESTAMP


class TimestampDependenceDetector(Detector):
    info = DetectorInfo(
        id="timestamp-dependence",
        title="Dangerous block.timestamp dependence",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        description=(
            "A value derived from block.timestamp (directly, via locals, hashing or "
            "internal calls) is reduced with % -- i.e. used as randomness -- or compared with "
            "== / !=, which a validator can satisfy or dodge by choosing the timestamp."
        ),
        soundness=(
            "Range comparisons (`>=`, `<`) are deliberately not reported: deadlines and "
            "vesting schedules tolerate the few seconds of validator influence. Timestamp "
            "flowing into storage and compared in another transaction is not tracked."
        ),
        cwe="CWE-829",
        swc="SWC-116",
        remediation=(
            "Use a verifiable randomness source (commit-reveal, VRF) and range comparisons "
            "for time windows."
        ),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for fa in self.functions():
            for node in fa.cfg:
                hit = self._first_hit(fa, node.id, node.exprs)
                if hit is None:
                    continue
                expr_node, what, severity = hit
                finding = self.make(
                    fa,
                    expr_node,
                    f"block.timestamp-derived `{self.text(expr_node)}` {what}",
                    severity=severity,
                )
                if finding is not None:
                    findings.append(finding)
        return findings

    @staticmethod
    def _first_hit(
        fa: FunctionAnalysis, node_id: int, exprs: list[Node]
    ) -> tuple[Node, str, Severity] | None:
        """One finding per CFG node: randomness (%) wins over strict equality."""
        equality: tuple[Node, str, Severity] | None = None
        for expr in exprs:
            for sub in iter_subexpressions(expr):
                if sub.get("nodeType") != "BinaryOperation":
                    continue
                operator = sub.get("operator")
                left = fa.taint.labels(node_id, sub["leftExpression"])
                if operator == "%" and TIMESTAMP in left:
                    return sub, "is used as a source of randomness", Severity.MEDIUM
                if operator in {"==", "!="} and equality is None:
                    right = fa.taint.labels(node_id, sub["rightExpression"])
                    if TIMESTAMP in left | right:
                        equality = (sub, "is compared for strict equality", Severity.LOW)
        return equality
