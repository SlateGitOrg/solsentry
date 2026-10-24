"""Malformed and hostile AST input: exit code 2 with a one-line error, never a traceback.

docs/THREAT_MODEL.md promises that a malformed AST (for example one checked into a pull request)
cannot crash the analyzer. These tests hold it to that: a fixed regression for the reviewer's
example, deep nesting, a multi-file run with one bad file, the ``cfg`` and ``eval`` commands,
and a Hypothesis fuzz test that deletes or replaces random keys of committed fixture ASTs.
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import subprocess
import sys
import tempfile
from functools import cache
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from solsentry.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main
from solsentry.errors import AstFormatError, input_boundary
from tests.conftest import AST_DIR, fixture_path

VULN = fixture_path("dev/reentrancy/EtherBank_vuln")
FIXTURES = sorted(AST_DIR.rglob("*.json"))
REPLACEMENTS: list[Any] = [None, 0, -1, True, "x", [], {}, {"nodeType": "Bogus"}, [{}]]


def _nodes(document: Any) -> list[dict[str, Any]]:
    """Every AST node (dict with ``nodeType``) in pre-order."""
    found: list[dict[str, Any]] = []
    stack = [document]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            if "nodeType" in item:
                found.append(item)
            stack.extend(reversed(list(item.values())))
        elif isinstance(item, list):
            stack.extend(reversed(item))
    return found


@cache
def _fixture_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _load(path: Path) -> Any:
    return json.loads(_fixture_text(path))


def _first(document: Any, node_type: str) -> dict[str, Any]:
    return next(n for n in _nodes(document) if n["nodeType"] == node_type)


def _run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


def _write(directory: Path, name: str, document: Any) -> Path:
    path = directory / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _missing_expression(tmp_path: Path) -> Path:
    """The reviewer's example: delete ``expression`` from the first FunctionCall."""
    document = _load(VULN)
    del _first(document, "FunctionCall")["expression"]
    return _write(tmp_path, "EtherBank_broken.json", document)


def test_reviewer_example_exits_2_without_traceback(tmp_path: Path) -> None:
    broken = _missing_expression(tmp_path)
    code, out, err = _run(["analyze", str(broken), "--fail-on", "info"])
    assert code == EXIT_ERROR
    assert "malformed or unsupported AST (KeyError: 'expression')" in err
    assert "Traceback (most recent" not in err and "0 input(s)" in out


def test_reviewer_example_end_to_end_process(tmp_path: Path) -> None:
    """Through a real interpreter process: exit status 2 and no traceback on stderr."""
    broken = _missing_expression(tmp_path)
    proc = subprocess.run(
        [sys.executable, "-m", "solsentry.cli", "analyze", str(broken), "--fail-on", "info"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == EXIT_ERROR
    assert "Traceback (most recent" not in proc.stderr
    assert proc.stderr.startswith("solsentry: error:")


def test_deep_nesting_is_an_input_error(tmp_path: Path) -> None:
    """600 nested unary minus operators parse as JSON but exceed Python's recursion limit."""
    document = _load(VULN)
    statement = _first(document, "ExpressionStatement")
    inner = statement["expression"]
    for depth in range(600):
        inner = {
            "nodeType": "UnaryOperation",
            "id": 900_000 + depth,
            "src": inner["src"],
            "operator": "-",
            "prefix": True,
            "subExpression": inner,
            "typeDescriptions": inner.get("typeDescriptions", {}),
        }
    statement["expression"] = inner
    code, _, err = _run(["analyze", str(_write(tmp_path, "deep.json", document))])
    assert code == EXIT_ERROR
    assert "nesting too deep" in err and "Traceback (most recent" not in err


def test_one_bad_file_does_not_stop_a_multi_file_run(tmp_path: Path) -> None:
    broken = _missing_expression(tmp_path)
    good = _write(tmp_path, "good.json", _load(VULN))
    report = tmp_path / "report.json"
    code, _, err = _run(
        ["analyze", str(broken), str(good), "-f", "json", "-o", str(report), "--fail-on", "high"]
    )
    # The good file still has its reentrancy finding, but the failure wins: exit 2, not 1.
    assert code == EXIT_ERROR
    assert err.count("solsentry: error:") == 1 and "EtherBank_broken.json" in err
    results = json.loads(report.read_text())["inputs"]
    assert [r["origin"] for r in results] == [str(good)]
    assert any(f["detector"] == "reentrancy" for f in results[0]["findings"])


def test_cfg_and_eval_commands_report_malformed_input(tmp_path: Path) -> None:
    broken = _missing_expression(tmp_path)
    code, _, err = _run(["cfg", str(broken), "EtherBank.withdraw"])
    assert code == EXIT_ERROR and "malformed or unsupported AST" in err
    code, _, err = _run(["eval", str(broken)])
    assert code == EXIT_ERROR and "malformed or unsupported AST" in err


def test_wrong_top_level_types_are_input_errors(tmp_path: Path) -> None:
    document = _load(VULN)
    _first(document, "ContractDefinition")["nodes"] = 7
    code, _, err = _run(["analyze", str(_write(tmp_path, "nodes.json", document))])
    assert code == EXIT_ERROR and "TypeError" in err and "Traceback (most recent" not in err


def test_boundary_passes_deliberate_errors_through() -> None:
    marker = AstFormatError("deliberate")
    with pytest.raises(AstFormatError) as caught, input_boundary("x.json"):
        raise marker
    assert caught.value is marker
    with (
        pytest.raises(AstFormatError, match=r"^x\.json: .*\(ValueError\);"),
        input_boundary("x.json"),
    ):
        raise ValueError("")
    with pytest.raises(AstFormatError, match=r"\.\.\.\); rerun"), input_boundary("x.json"):
        raise KeyError("k" * 500)


def test_programming_errors_outside_the_input_class_still_surface() -> None:
    """Only the exceptions typical of bad input are converted; others are real bugs."""
    with pytest.raises(ZeroDivisionError), input_boundary("x.json"):
        _ = 1 // 0


def test_unmutated_fixtures_still_analyse_cleanly(tmp_path: Path) -> None:
    code, _, err = _run(["analyze", str(AST_DIR), "-o", str(tmp_path / "r.txt")])
    assert code == EXIT_OK and err == ""


@st.composite
def _mutation(draw: st.DrawFn) -> tuple[str, Any]:
    """A committed fixture with 1-3 keys of random AST nodes deleted or replaced."""
    path = draw(st.sampled_from(FIXTURES))
    document = copy.deepcopy(_load(path))
    nodes = _nodes(document)
    for _ in range(draw(st.integers(min_value=1, max_value=3))):
        node = nodes[draw(st.integers(min_value=0, max_value=len(nodes) - 1))]
        if not node:
            continue
        key = draw(st.sampled_from(sorted(node)))
        if draw(st.booleans()):
            del node[key]
        else:
            node[key] = draw(st.sampled_from(REPLACEMENTS))
    return path.name, document


@settings(
    max_examples=200,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)
@given(_mutation())
def test_fuzzed_ast_never_crashes(case: tuple[str, Any]) -> None:
    name, document = case
    with tempfile.TemporaryDirectory() as directory:
        path = _write(Path(directory), name, document)
        code, _, err = _run(["analyze", str(path), "--fail-on", "info"])
    assert code in (EXIT_OK, EXIT_FINDINGS, EXIT_ERROR)
    assert "Traceback (most recent" not in err
    if code == EXIT_ERROR:
        assert err.startswith("solsentry: error:")
