"""Detector behaviour: vulnerable/fixed pairs, targeted assertions and golden evaluation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from solsentry.detectors import REGISTRY, detector_infos, select
from solsentry.engine import analyze_input, analyze_path, expand_inputs
from solsentry.evaluation import Counts, evaluate, labels_of
from solsentry.findings import Severity
from tests.conftest import AST_DIR, ROOT, fixture_path, load

DEV_PAIRS = sorted(
    p.relative_to(AST_DIR).with_suffix("").as_posix().removesuffix("_vuln")
    for p in (AST_DIR / "dev").rglob("*_vuln.json")
)


def _findings(relative: str) -> list[tuple[str, int]]:
    result = analyze_input(load(relative))
    return [(f.detector, f.location.line) for f in result.findings]


@pytest.mark.parametrize("stem", DEV_PAIRS)
def test_dev_pair_vulnerable_matches_labels_and_fixed_is_clean(stem: str) -> None:
    vuln = f"{stem}_vuln"
    detector = stem.split("/")[1]
    expected = {(d, line) for _, d, line in labels_of(load(vuln))}
    assert any(d == detector for d, _ in expected), "every vulnerable fixture carries a label"
    assert set(_findings(vuln)) == expected
    assert _findings(f"{stem}_fixed") == []


def test_reentrancy_reports_related_writes() -> None:
    result = analyze_input(load("dev/reentrancy/RewardPool_vuln"))
    (finding,) = result.findings
    assert finding.detector == "reentrancy"
    assert [r.location.line for r in finding.related] == [21, 22]
    assert "`credits`, `totalPaid` are updated" in finding.message
    assert finding.severity is Severity.HIGH


def test_reentrancy_ignores_view_calls_and_locked_functions(features: object) -> None:
    del features
    detectors = {(f.detector, f.function) for f in analyze_input(load("unit/Features")).findings}
    assert ("reentrancy", "viewCall") not in detectors
    assert ("reentrancy", "guarded") not in detectors


def test_timestamp_severity_depends_on_use() -> None:
    result = analyze_input(load("dev/timestamp-dependence/Roulette_vuln"))
    by_line = {f.location.line: f.severity for f in result.findings}
    assert by_line == {11: Severity.LOW, 13: Severity.MEDIUM}


def test_legacy_now_and_wrapping_arithmetic() -> None:
    result = analyze_input(load("unit/Legacy"))
    assert {(f.detector, f.location.line) for f in result.findings} == {
        ("integer-overflow", 10),
        ("timestamp-dependence", 15),
    }


def test_inline_suppressions() -> None:
    result = analyze_input(load("unit/Features"))
    unchecked = [f.location.line for f in result.findings if f.detector == "unchecked-call"]
    assert unchecked == [116]
    assert result.suppressed == 2


def test_assembly_selfdestruct_is_reported() -> None:
    result = analyze_input(load("unit/Features"))
    assert ("unprotected-selfdestruct", "asmDestroy") in {
        (f.detector, f.function) for f in result.findings
    }


def test_conditional_and_returned_send_count_as_checked() -> None:
    result = analyze_input(load("unit/Features"))
    assert all(f.function != "conditional" for f in result.findings)


def test_modifier_findings_are_deduplicated() -> None:
    result = analyze_input(load("dev/tx-origin/OriginModifier_vuln"))
    assert [(f.detector, f.location.line) for f in result.findings] == [("tx-origin", 14)]


def test_detector_selection_and_min_severity() -> None:
    path = fixture_path("dev/timestamp-dependence/Roulette_vuln")
    only = analyze_path(path, detectors=["timestamp-dependence"], min_severity=Severity.MEDIUM)
    assert [f.location.line for f in only.findings] == [13]
    none = analyze_path(path, exclude=["timestamp-dependence"])
    assert none.findings == []
    with pytest.raises(ValueError, match="unknown detector"):
        select(["nope"])
    assert len(select(exclude=["reentrancy"])) == len(REGISTRY) - 1


def test_detector_metadata_complete() -> None:
    infos = detector_infos()
    assert len(infos) == 8
    for info in infos:
        assert info.cwe.startswith("CWE-") and info.swc.startswith("SWC-")
        assert info.description and info.soundness and info.remediation


def test_finding_serialisation_and_fingerprint() -> None:
    (finding,) = analyze_input(load("dev/reentrancy/EtherBank_vuln")).findings
    data = finding.to_dict()
    assert data["location"]["line"] == 15 and data["detector"] == "reentrancy"
    assert len(finding.fingerprint) == 32
    again = analyze_input(load("dev/reentrancy/EtherBank_vuln")).findings[0]
    assert again.fingerprint == finding.fingerprint
    assert Severity.parse("HIGH") is Severity.HIGH
    with pytest.raises(ValueError, match="unknown severity"):
        Severity.parse("critical")


def test_expand_inputs(tmp_path: Path) -> None:
    files = expand_inputs([AST_DIR / "dev" / "reentrancy", tmp_path / "x.json"])
    assert len(files) == 7 and files[-1] == tmp_path / "x.json"


def test_counts_edge_cases() -> None:
    empty = Counts()
    assert (empty.precision, empty.recall) == (1.0, 1.0)
    assert Counts(fp=1, fn=1).f1 == 0.0


@pytest.mark.parametrize("split", ["dev", "holdout"])
def test_evaluation_matches_golden(split: str) -> None:
    """Pins every TP/FP/FN; a detector change must update tests/golden deliberately."""
    report = evaluate([AST_DIR / split], split).to_dict()
    report.pop("seconds")
    golden = json.loads((ROOT / "tests" / "golden" / f"eval-{split}.json").read_text())
    assert report == golden


def test_markdown_report_lists_errors() -> None:
    report = evaluate([AST_DIR / "holdout" / "mixed"], "mixed")
    text = report.to_markdown()
    assert "| **all** |" in text and "False positives:" in text and "False negatives:" in text
