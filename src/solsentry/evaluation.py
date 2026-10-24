"""Precision/recall of the detectors against labelled fixtures.

Ground truth lives in the fixture sources as trailing comments on the line where a finding is
expected::

    (bool ok, ) = msg.sender.call{value: amount}(""); // @expect: reentrancy

Matching is by ``(file, detector, line)``. Several findings of one detector on one line count
once; any finding without a label is a false positive and any unmatched label a false negative.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from solsentry.detectors import detector_infos
from solsentry.engine import analyze_input, expand_inputs
from solsentry.solast import AstInput, load_path

_EXPECT_RE = re.compile(r"@expect:\s*([a-z0-9\-, ]+)")

Key = tuple[str, str, int]  # (origin/path, detector, line)


def labels_of(ast_input: AstInput) -> set[Key]:
    labels: set[Key] = set()
    for unit in ast_input.units:
        for number, line in enumerate(unit.source.content.splitlines(), start=1):
            match = _EXPECT_RE.search(line)
            if match is None:
                continue
            for detector in re.split(r"[\s,]+", match.group(1).strip()):
                if detector:
                    labels.add((unit.path, detector, number))
    return labels


@dataclass
class Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0


@dataclass
class EvalReport:
    name: str
    files: int = 0
    per_detector: dict[str, Counts] = field(default_factory=dict)
    false_positives: list[Key] = field(default_factory=list)
    false_negatives: list[Key] = field(default_factory=list)
    seconds: float = 0.0
    source_lines: int = 0

    @property
    def total(self) -> Counts:
        total = Counts()
        for counts in self.per_detector.values():
            total.tp += counts.tp
            total.fp += counts.fp
            total.fn += counts.fn
        return total

    def to_dict(self) -> dict[str, Any]:
        def row(c: Counts) -> dict[str, Any]:
            return {
                "tp": c.tp,
                "fp": c.fp,
                "fn": c.fn,
                "precision": round(c.precision, 4),
                "recall": round(c.recall, 4),
                "f1": round(c.f1, 4),
            }

        return {
            "name": self.name,
            "files": self.files,
            "source_lines": self.source_lines,
            "seconds": round(self.seconds, 4),
            "detectors": {k: row(v) for k, v in sorted(self.per_detector.items())},
            "total": row(self.total),
            "false_positives": [list(k) for k in self.false_positives],
            "false_negatives": [list(k) for k in self.false_negatives],
        }

    def to_markdown(self) -> str:
        lines = [
            f"### {self.name}: {self.files} files, {self.source_lines} source lines",
            "",
            "| detector | TP | FP | FN | precision | recall | F1 |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
        for detector, counts in sorted(self.per_detector.items()):
            lines.append(_md_row(detector, counts))
        lines.append(_md_row("**all**", self.total))
        if self.false_positives:
            lines += ["", "False positives:"] + [
                f"- `{p}:{ln}` {d}" for p, d, ln in self.false_positives
            ]
        if self.false_negatives:
            lines += ["", "False negatives:"] + [
                f"- `{p}:{ln}` {d}" for p, d, ln in self.false_negatives
            ]
        return "\n".join(lines)


def _md_row(name: str, c: Counts) -> str:
    return (
        f"| {name} | {c.tp} | {c.fp} | {c.fn} | {c.precision:.2f} | {c.recall:.2f} | {c.f1:.2f} |"
    )


def evaluate(paths: list[Path], name: str = "fixtures") -> EvalReport:
    """Analyse every input under ``paths`` and score findings against ``@expect`` labels."""
    report = EvalReport(name)
    for info in detector_infos():
        report.per_detector[info.id] = Counts()
    for path in expand_inputs(paths):
        ast_input = load_path(path)
        expected = labels_of(ast_input)
        result = analyze_input(ast_input)
        report.files += 1
        report.seconds += result.seconds
        report.source_lines += sum(u.source.line_count for u in ast_input.units)
        found = {(f.location.path, f.detector, f.location.line) for f in result.findings}
        for key in found & expected:
            report.per_detector.setdefault(key[1], Counts()).tp += 1
        for key in sorted(found - expected):
            report.per_detector.setdefault(key[1], Counts()).fp += 1
            report.false_positives.append(key)
        for key in sorted(expected - found):
            report.per_detector.setdefault(key[1], Counts()).fn += 1
            report.false_negatives.append(key)
    return report
