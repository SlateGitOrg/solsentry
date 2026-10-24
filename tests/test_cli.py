"""Command-line interface (exercised in-process through ``main``)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from solsentry.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main
from tests.conftest import AST_DIR, fixture_path

VULN = str(fixture_path("dev/reentrancy/EtherBank_vuln"))
FIXED = str(fixture_path("dev/reentrancy/EtherBank_fixed"))


def test_analyze_text(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["analyze", VULN]) == EXIT_OK
    out = capsys.readouterr().out
    assert "[reentrancy]" in out and "1 finding(s)" in out


def test_fail_on_threshold() -> None:
    assert main(["analyze", VULN, "--fail-on", "high", "-o", "/dev/null"]) == EXIT_FINDINGS
    assert main(["analyze", FIXED, "--fail-on", "low", "-o", "/dev/null"]) == EXIT_OK


def test_analyze_sarif_and_json_to_file(tmp_path: Path) -> None:
    sarif = tmp_path / "out" / "r.sarif"
    assert (
        main(["analyze", str(AST_DIR / "dev" / "reentrancy"), "-f", "sarif", "-o", str(sarif)]) == 0
    )
    document = json.loads(sarif.read_text())
    assert len(document["runs"][0]["results"]) == 3
    as_json = tmp_path / "r.json"
    assert main(["-v", "analyze", VULN, "-f", "json", "-o", str(as_json), "--color"]) == 0
    assert json.loads(as_json.read_text())["tool"]["name"] == "solsentry"


def test_detector_filters(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["analyze", VULN, "--exclude", "reentrancy"]) == EXIT_OK
    assert "0 finding(s)" in capsys.readouterr().out
    assert main(["analyze", VULN, "--detectors", "nope"]) == EXIT_ERROR
    assert "unknown detector" in capsys.readouterr().err


def test_detectors_listing(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["detectors"]) == EXIT_OK
    assert "unprotected-delegatecall" in capsys.readouterr().out
    assert main(["detectors", "-f", "json"]) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert {d["id"] for d in payload} >= {"reentrancy", "integer-overflow"}


def test_cfg_command(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["cfg", VULN, "EtherBank.withdraw"]) == EXIT_OK
    assert capsys.readouterr().out.startswith("CFG EtherBank.withdraw")
    assert main(["cfg", VULN, "EtherBank.withdraw", "--dot"]) == EXIT_OK
    assert "digraph" in capsys.readouterr().out
    assert main(["cfg", VULN, "EtherBank.nope"]) == EXIT_ERROR
    assert "available: EtherBank.deposit, EtherBank.withdraw" in capsys.readouterr().err


def test_eval_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    target = AST_DIR / "dev" / "tx-origin"
    assert main(["eval", str(target), "--name", "tx"]) == EXIT_OK
    assert "### tx: 6 files" in capsys.readouterr().out
    out = tmp_path / "e.json"
    assert main(["eval", str(target), "-f", "json", "-o", str(out)]) == EXIT_OK
    assert json.loads(out.read_text())["total"]["tp"] == 3


def test_input_errors(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["analyze", str(tmp_path / "missing.json")]) == EXIT_ERROR
    assert "cannot read" in capsys.readouterr().err
    assert main(["analyze", str(tmp_path)]) == EXIT_ERROR
    assert "no input files" in capsys.readouterr().err


def test_bad_severity_is_usage_error() -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["analyze", VULN, "--fail-on", "critical"])
    assert excinfo.value.code == 2
