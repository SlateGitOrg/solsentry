"""Reentrancy: a storage write that can execute after an external call (SWC-107)."""

from __future__ import annotations

from solsentry.analysis import FunctionAnalysis
from solsentry.detectors.base import Detector, DetectorInfo
from solsentry.expr import is_reentrant_call
from solsentry.findings import Confidence, Finding, Severity
from solsentry.solast import Node


class ReentrancyDetector(Detector):
    info = DetectorInfo(
        id="reentrancy",
        title="State written after external call",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description=(
            "A call that hands control to another contract (high-level external call, "
            "call/delegatecall) is followed on some CFG path by a write to a storage variable "
            "that is read elsewhere. A re-entrant callee observes the stale value."
        ),
        soundness=(
            "Intra-procedural paths plus internal-call summaries; cross-function and "
            "cross-contract reentrancy, read-only reentrancy and transfer()/send() "
            "(2300-gas stipend) are out of scope. Mutexes are recognised structurally."
        ),
        cwe="CWE-841",
        swc="SWC-107",
        remediation=(
            "Apply checks-effects-interactions (update state before the call) or a "
            "reentrancy guard such as OpenZeppelin's nonReentrant."
        ),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for fa in self.functions():
            if not fa.function.is_state_changing:
                continue
            findings.extend(self._function(fa))
        return findings

    def _call_anchor(self, fa: FunctionAnalysis, node_id: int) -> Node | None:
        for call in fa.effects[node_id].calls:
            if is_reentrant_call(call):
                return call
        for call, target in fa.internal_calls(node_id):
            if self.analysis.summary(target).reentrant_call:
                return call
        return fa.location_node(node_id)

    def _function(self, fa: FunctionAnalysis) -> list[Finding]:
        findings: list[Finding] = []
        excluded = fa.lock_vars()
        for node in fa.cfg:
            if not fa.node_is_reentrant_call(node.id) or fa.lock_protected(node.id):
                continue
            writes: dict[int, set[int]] = {}
            for later in fa.cfg.reachable_from(node.id) | {node.id}:
                written = set(fa.state_writes(later))
                if later != node.id:
                    for _, target in fa.internal_calls(later):
                        written |= self.analysis.summary(target).writes
                written = {
                    v
                    for v in written - excluded
                    if v in self.analysis.read_anywhere
                    and not self.program.state_vars[v].constant
                    and not self.program.state_vars[v].immutable
                }
                if written:
                    writes[later] = written
            if not writes:
                continue
            anchor = self._call_anchor(fa, node.id)
            if anchor is None:
                continue
            all_vars = set().union(*writes.values())
            related = []
            for later, var_ids in sorted(writes.items()):
                later_anchor = fa.location_node(later)
                if later_anchor is not None:
                    related.append(
                        (later_anchor, f"writes {self.var_names(var_ids)} after the call")
                    )
            verb = "is" if len(all_vars) == 1 else "are"
            message = (
                f"`{self.text(anchor)}` can re-enter {fa.function.qualified_name} before "
                f"{self.var_names(all_vars)} {verb} updated"
            )
            finding = self.make(fa, anchor, message, related)
            if finding is not None:
                findings.append(finding)
        return findings
