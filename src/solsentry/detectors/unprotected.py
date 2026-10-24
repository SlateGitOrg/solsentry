"""Unprotected ``selfdestruct`` (SWC-106) and caller-chosen ``delegatecall`` targets (SWC-112)."""

from __future__ import annotations

from solsentry.detectors.base import Detector, DetectorInfo
from solsentry.expr import CallKind, call_kind, call_receiver
from solsentry.findings import Confidence, Finding, Severity
from solsentry.taint import ATTACKER

_GUARD_NOTE = (
    "A node counts as protected when a msg.sender identity check (==/!= against storage or "
    "a literal address, a boolean role lookup keyed by msg.sender, or an internal helper "
    "whose every exit passes such a check) dominates it in the CFG, modifiers inlined."
)


class UnprotectedSelfdestructDetector(Detector):
    info = DetectorInfo(
        id="unprotected-selfdestruct",
        title="Unprotected selfdestruct",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description=(
            "An externally callable function reaches selfdestruct (directly, in inline "
            "assembly, or through an internal call) without a dominating msg.sender check."
        ),
        soundness=_GUARD_NOTE + " Guards are not checked for polarity or for bypassable "
        "storage (e.g. an owner that anyone can overwrite is caught by missing-access-control).",
        cwe="CWE-284",
        swc="SWC-106",
        remediation="Restrict the function to an owner/admin role, or remove selfdestruct.",
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for fa in self.functions(entrypoints_only=True):
            for node in fa.cfg:
                anchors = [
                    c for c in fa.effects[node.id].calls if call_kind(c) is CallKind.SELFDESTRUCT
                ]
                for call, target in fa.internal_calls(node.id):
                    summary = self.analysis.summary(target)
                    if summary.selfdestruct and not summary.sender_guarded:
                        anchors.append(call)
                if "selfdestruct" in fa.asm_builtins.get(node.id, set()) and node.stmt is not None:
                    anchors.append(node.stmt)
                if not anchors or fa.identity_protected(node.id):
                    continue
                for anchor in anchors:
                    finding = self.make(
                        fa,
                        anchor,
                        f"anyone can call {fa.function.qualified_name} and reach "
                        f"`{self.text(anchor)}`",
                    )
                    if finding is not None:
                        findings.append(finding)
        return findings


class UnprotectedDelegatecallDetector(Detector):
    info = DetectorInfo(
        id="unprotected-delegatecall",
        title="Delegatecall to caller-controlled target",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description=(
            "An externally callable function delegatecalls an address derived from its "
            "parameters, calldata or external-call results, without a dominating "
            "msg.sender check. The callee runs with this contract's storage and balance."
        ),
        soundness=_GUARD_NOTE + " Only Solidity-level delegatecall in the entry function "
        "itself is inspected; delegatecall inside assembly or helper functions, and "
        "storage-held targets that are writable by anyone, are not traced.",
        cwe="CWE-829",
        swc="SWC-112",
        remediation="Delegate only to trusted, admin-controlled implementations.",
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for fa in self.functions(entrypoints_only=True):
            for node in fa.cfg:
                for call in fa.effects[node.id].calls:
                    if call_kind(call) is not CallKind.LOW_DELEGATECALL:
                        continue
                    target = call_receiver(call)
                    if target is None:
                        continue
                    labels = fa.taint.labels(node.id, target)
                    if not labels & ATTACKER or fa.identity_protected(node.id):
                        continue
                    sources = ", ".join(sorted(labels & ATTACKER)).lower()
                    finding = self.make(
                        fa,
                        call,
                        f"delegatecall target `{self.text(target)}` is attacker-controlled "
                        f"({sources}) and the call is not access-restricted",
                    )
                    if finding is not None:
                        findings.append(finding)
        return findings
