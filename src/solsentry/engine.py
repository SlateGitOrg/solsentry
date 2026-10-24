"""High-level entry point: load an AST input, run detectors, post-process findings.

Post-processing deduplicates findings that share detector and source range (a modifier
inlined into many functions yields one report) and honours inline suppressions::

    foo.call(data); // solsentry-disable-line unchecked-call
    // solsentry-disable-next-line reentrancy, unchecked-call

A suppression without detector ids silences every detector on that line.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from solsentry.analysis import ProgramAnalysis
from solsentry.detectors import select
from solsentry.errors import input_boundary
from solsentry.findings import Finding, Severity
from solsentry.model import Program
from solsentry.solast import AstInput, load_path

log = logging.getLogger(__name__)

_SUPPRESS_RE = re.compile(r"solsentry-disable-(next-)?line\b([^\n]*)")


@dataclass
class AnalysisResult:
    origin: str
    findings: list[Finding]
    functions_analyzed: int
    cfg_nodes: int
    skipped: dict[str, str] = field(default_factory=dict)
    suppressed: int = 0
    seconds: float = 0.0
    compiler: str | None = None


def _suppressions(ast_input: AstInput) -> dict[tuple[str, int], set[str] | None]:
    """(path, line) -> detector ids suppressed there (``None`` = all)."""
    table: dict[tuple[str, int], set[str] | None] = {}
    for unit in ast_input.units:
        for number, line in enumerate(unit.source.content.splitlines(), start=1):
            match = _SUPPRESS_RE.search(line)
            if match is None:
                continue
            target = number + 1 if match.group(1) else number
            ids = {i for i in re.split(r"[\s,]+", match.group(2).strip()) if i}
            table[(unit.path, target)] = ids or None
    return table


def _postprocess(findings: list[Finding], ast_input: AstInput) -> tuple[list[Finding], int]:
    seen: set[tuple[str, str, int, int]] = set()
    unique: list[Finding] = []
    for finding in sorted(findings, key=Finding.sort_key):
        key = (
            finding.detector,
            finding.location.path,
            finding.location.start,
            finding.location.length,
        )
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    table = _suppressions(ast_input)
    kept: list[Finding] = []
    for finding in unique:
        rule = table.get((finding.location.path, finding.location.line), set())
        if rule is None or finding.detector in rule:
            continue
        kept.append(finding)
    return kept, len(unique) - len(kept)


def analyze_input(
    ast_input: AstInput,
    detectors: list[str] | None = None,
    exclude: list[str] | None = None,
    min_severity: Severity = Severity.INFO,
) -> AnalysisResult:
    """Run the selected detectors over one parsed input.

    A malformed AST raises :class:`~solsentry.errors.AstFormatError`, never a bare
    ``KeyError``/``TypeError``/``RecursionError`` (see :func:`~solsentry.errors.input_boundary`).
    """
    started = time.perf_counter()
    selected = select(detectors, exclude)
    with input_boundary(ast_input.origin):
        program = Program(ast_input)
        analysis = ProgramAnalysis(program)
        raw: list[Finding] = []
        for detector_cls in selected:
            detector = detector_cls(analysis)
            produced = detector.run()
            log.debug("%s: %d raw finding(s)", detector_cls.info.id, len(produced))
            raw.extend(produced)
        findings, suppressed = _postprocess(raw, ast_input)
    findings = [f for f in findings if f.severity.rank >= min_severity.rank]
    return AnalysisResult(
        origin=ast_input.origin,
        findings=findings,
        functions_analyzed=len(analysis.functions),
        cfg_nodes=sum(len(fa.cfg) for fa in analysis.functions.values()),
        skipped=dict(analysis.skipped),
        suppressed=suppressed,
        seconds=time.perf_counter() - started,
        compiler=ast_input.compiler_version,
    )


def analyze_path(
    path: Path,
    detectors: list[str] | None = None,
    exclude: list[str] | None = None,
    min_severity: Severity = Severity.INFO,
    source_root: Path | None = None,
) -> AnalysisResult:
    """Load ``path`` (bundle, solc standard-JSON output or SourceUnit) and analyse it."""
    with input_boundary(str(path)):
        ast_input = load_path(path, source_root)
    return analyze_input(ast_input, detectors, exclude, min_severity)


def expand_inputs(paths: list[Path]) -> list[Path]:
    """Files as given; directories expand to their ``*.json`` files, sorted."""
    result: list[Path] = []
    for path in paths:
        if path.is_dir():
            result.extend(sorted(p for p in path.rglob("*.json") if p.is_file()))
        else:
            result.append(path)
    return result
