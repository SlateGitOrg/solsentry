"""Detector plumbing: metadata, the base class and finding construction."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass
from typing import ClassVar

from solsentry.analysis import FunctionAnalysis, ProgramAnalysis
from solsentry.findings import Confidence, Finding, RelatedLocation, Severity
from solsentry.solast import Node


@dataclass(frozen=True)
class DetectorInfo:
    id: str
    title: str
    severity: Severity
    confidence: Confidence
    description: str
    soundness: str
    cwe: str
    swc: str
    remediation: str


class Detector(ABC):
    """A detector inspects a :class:`ProgramAnalysis` and reports :class:`Finding` objects."""

    info: ClassVar[DetectorInfo]

    def __init__(self, analysis: ProgramAnalysis) -> None:
        self.analysis = analysis
        self.program = analysis.program

    @abstractmethod
    def run(self) -> list[Finding]:
        """Return all findings of this detector for the analysed program."""

    def functions(self, entrypoints_only: bool = False) -> Iterable[FunctionAnalysis]:
        for fa in self.analysis.functions.values():
            if entrypoints_only and not fa.function.is_entrypoint:
                continue
            yield fa

    def make(
        self,
        fa: FunctionAnalysis,
        anchor: Node,
        message: str,
        related: Iterable[tuple[Node, str]] = (),
        severity: Severity | None = None,
        confidence: Confidence | None = None,
    ) -> Finding | None:
        index = self.program.index
        location = index.location(anchor)
        if location is None:
            return None
        related_locations = []
        for node, text in related:
            rel = index.location(node)
            if rel is not None:
                related_locations.append(RelatedLocation(rel, text))
        function = fa.function
        return Finding(
            detector=self.info.id,
            title=self.info.title,
            severity=severity or self.info.severity,
            confidence=confidence or self.info.confidence,
            message=message,
            location=location,
            contract=function.contract.name,
            function=function.name or function.kind,
            snippet=" ".join(index.text(anchor).split())[:200],
            related=tuple(related_locations),
        )

    def text(self, node: Node, limit: int = 60) -> str:
        snippet = " ".join(self.program.index.text(node).split())
        return snippet if len(snippet) <= limit else snippet[: limit - 3] + "..."

    def var_names(self, var_ids: Iterable[int]) -> str:
        names = sorted(
            self.program.state_vars[v].name for v in var_ids if v in self.program.state_vars
        )
        return ", ".join(f"`{n}`" for n in names)
