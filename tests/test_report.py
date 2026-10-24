"""Text, JSON and SARIF rendering."""

from __future__ import annotations

import json

import jsonschema

from solsentry.engine import AnalysisResult, analyze_input
from solsentry.report import render_json, render_sarif, render_text
from tests.conftest import ROOT, load

SCHEMA = json.loads((ROOT / "tests" / "sarif-subset.schema.json").read_text())


def _results(*relatives: str) -> list[AnalysisResult]:
    return [analyze_input(load(r)) for r in relatives]


def test_sarif_validates_and_carries_rules() -> None:
    document = json.loads(render_sarif(_results("dev/reentrancy/Escrow_vuln", "unit/Features")))
    jsonschema.validate(document, SCHEMA)
    run = document["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules][:2] == ["reentrancy", "tx-origin"]
    assert all("Soundness limits" in r["help"]["text"] for r in rules)
    reentrancy = next(r for r in run["results"] if r["ruleId"] == "reentrancy")
    assert rules[reentrancy["ruleIndex"]]["id"] == "reentrancy"
    assert reentrancy["level"] == "error"
    assert reentrancy["relatedLocations"][0]["physicalLocation"]["region"]["startLine"] == 25


def test_sarif_golden() -> None:
    """Byte-stable SARIF for one fixture (regenerate deliberately if the format changes)."""
    rendered = render_sarif(_results("dev/reentrancy/EtherBank_vuln"))
    golden = (ROOT / "tests" / "golden" / "EtherBank_vuln.sarif").read_text()
    assert rendered + "\n" == golden


def test_sarif_reports_skipped_functions() -> None:
    result = _results("dev/reentrancy/EtherBank_vuln")[0]
    result.skipped["X.f"] = "boom"
    document = json.loads(render_sarif([result]))
    notes = document["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    assert notes[0]["message"]["text"] == "skipped X.f: boom"


def test_json_output() -> None:
    document = json.loads(render_json(_results("dev/unchecked-call/Payout_vuln")))
    (entry,) = document["inputs"]
    assert entry["compiler"] == "0.8.26+commit.8a97fa7a"
    assert entry["findings"][0]["detector"] == "unchecked-call"
    assert entry["functionsAnalyzed"] == 1 and entry["cfgNodes"] > 3


def test_text_output_with_and_without_colour() -> None:
    results = _results("dev/reentrancy/EtherBank_vuln", "dev/reentrancy/EtherBank_fixed")
    results[1].skipped["X.f"] = "boom"
    plain = render_text(results)
    assert "dev/reentrancy/EtherBank_vuln.sol:15:23: HIGH [reentrancy]" in plain
    assert "- dev/reentrancy/EtherBank_vuln.sol:17:9: writes `balances` after the call" in plain
    assert "note: skipped X.f: boom" in plain
    assert plain.splitlines()[-1] == "1 finding(s) in 2 input(s), 4 function(s) analysed (1 high)"
    assert "\x1b[31mHIGH" in render_text(results, color=True)
    assert render_text([]).endswith("0 finding(s) in 0 input(s), 0 function(s) analysed")
