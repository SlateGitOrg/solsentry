"""Missing access control on privileged state or on ether withdrawal (SWC-105/SWC-100)."""

from __future__ import annotations

from solsentry.analysis import FunctionAnalysis
from solsentry.detectors.base import Detector, DetectorInfo
from solsentry.expr import CallKind, call_kind, call_receiver, call_value
from solsentry.findings import Confidence, Finding, Severity
from solsentry.taint import CALLDATA, PARAM, SELF_BALANCE, SENDER

_VALUE_CALLS = {CallKind.TRANSFER, CallKind.SEND, CallKind.LOW_CALL}


class MissingAccessControlDetector(Detector):
    info = DetectorInfo(
        id="missing-access-control",
        title="Missing access control",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description=(
            "An externally callable, state-changing function (1) writes an *authorization "
            "variable* -- a storage variable that some msg.sender identity check in the "
            "program reads, such as `owner` or `admins` -- or (2) sends the contract's entire "
            "balance to a caller-chosen address, without a dominating msg.sender check or a "
            "one-shot initializer flag."
        ),
        soundness=(
            "Privilege is inferred, not specified: a variable becomes privileged only if "
            "the code itself guards it somewhere. Business-level privileges that are never "
            "guarded anywhere (e.g. a lone unprotected mint) are invisible to this rule; a "
            "single unrelated identity check can promote a variable to privileged."
        ),
        cwe="CWE-284",
        swc="SWC-105",
        remediation="Add the same access-control modifier used by the other privileged functions.",
    )

    def run(self) -> list[Finding]:
        auth = self.analysis.auth_vars()
        findings: list[Finding] = []
        for fa in self.functions(entrypoints_only=True):
            if not fa.function.is_state_changing:
                continue
            findings.extend(self._writes(fa, auth))
            findings.extend(self._drains(fa))
        return findings

    def _protected(self, fa: FunctionAnalysis, node_id: int) -> bool:
        return fa.identity_protected(node_id) or fa.initializer_protected(node_id)

    def _writes(self, fa: FunctionAnalysis, auth: frozenset[int]) -> list[Finding]:
        findings: list[Finding] = []
        for node in fa.cfg:
            written = fa.state_writes(node.id) & auth
            for _, target in fa.internal_calls(node.id):
                summary = self.analysis.summary(target)
                if not summary.sender_guarded:
                    written |= summary.writes & auth
            if not written or self._protected(fa, node.id):
                continue
            anchor = fa.location_node(node.id)
            if anchor is None:
                continue
            finding = self.make(
                fa,
                anchor,
                f"{fa.function.qualified_name} writes authorization state "
                f"{self.var_names(written)} without checking msg.sender",
            )
            if finding is not None:
                findings.append(finding)
        return findings

    def _drains(self, fa: FunctionAnalysis) -> list[Finding]:
        findings: list[Finding] = []
        for node in fa.cfg:
            for call in fa.effects[node.id].calls:
                if call_kind(call) not in _VALUE_CALLS:
                    continue
                value, recipient = call_value(call), call_receiver(call)
                if value is None or recipient is None:
                    continue
                if SELF_BALANCE not in fa.taint.labels(node.id, value):
                    continue
                if not fa.taint.labels(node.id, recipient) & {PARAM, SENDER, CALLDATA}:
                    continue
                if self._protected(fa, node.id):
                    continue
                finding = self.make(
                    fa,
                    call,
                    f"anyone can send the whole contract balance to `{self.text(recipient)}` "
                    f"via {fa.function.qualified_name}",
                )
                if finding is not None:
                    findings.append(finding)
        return findings
