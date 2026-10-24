"""Source mapping and AST input loading."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from solsentry import solast
from solsentry.errors import AstFormatError, InputError
from solsentry.solast import (
    AstIndex,
    child_nodes,
    iter_nodes,
    load_path,
    make_bundle,
    parse_document,
)
from solsentry.source import SourceFile, SrcRange, parse_src
from tests.conftest import fixture_path, load


def test_parse_src_roundtrip() -> None:
    assert parse_src("12:34:5") == SrcRange(12, 34, 5)
    assert parse_src("-1:-1:-1") == SrcRange(-1, -1, -1)


@pytest.mark.parametrize("bad", ["", "1:2", "a:b:c", "1:2:3:4"])
def test_parse_src_rejects_garbage(bad: str) -> None:
    with pytest.raises(AstFormatError):
        parse_src(bad)


def test_positions_are_byte_based_and_one_indexed() -> None:
    source = SourceFile("x.sol", "ab\n// é\nxyz")
    assert source.position(0) == (1, 1)
    assert source.position(3) == (2, 1)
    # "é" is two bytes, so "xyz" starts at byte 9 on line 3
    assert source.position(9) == (3, 1)
    assert source.text(SrcRange(9, 3, 0)) == "xyz"
    assert source.line_text(2) == "// é"
    assert source.line_text(3) == "xyz"
    assert source.line_text(99) == ""
    assert source.line_count == 3
    location = source.location(SrcRange(9, 3, 0))
    assert (location.line, location.column, location.end_line, location.end_column) == (3, 1, 3, 4)
    assert location.short() == "x.sol:3:1"


def test_position_clamps_out_of_range_offsets() -> None:
    source = SourceFile("x.sol", "abc")
    assert source.position(-5) == (1, 1)
    assert source.position(500) == (1, 4)


def test_bundle_loads_with_compiler_version() -> None:
    ast_input = load("dev/reentrancy/EtherBank_vuln")
    assert ast_input.compiler_version == "0.8.26+commit.8a97fa7a"
    assert [u.path for u in ast_input.units] == ["dev/reentrancy/EtherBank_vuln.sol"]
    assert ast_input.metadata["format"] == solast.BUNDLE_FORMAT


def test_index_locations_and_parents() -> None:
    ast_input = load("dev/reentrancy/EtherBank_vuln")
    index = AstIndex(ast_input)
    contract = next(n for n in index.nodes.values() if n.get("nodeType") == "ContractDefinition")
    location = index.location(contract)
    assert location is not None
    assert location.line == 5
    assert index.text(contract).startswith("contract EtherBank")
    member = contract["nodes"][0]
    assert index.parent_of(member) is contract
    assert index.get(None) is None
    assert index.location({"nodeType": "X"}) is None
    assert index.text({"nodeType": "X"}) == ""
    assert index.location({"nodeType": "X", "src": "0:1:99"}) is None


def test_iter_and_child_nodes() -> None:
    tree = {
        "nodeType": "A",
        "x": [{"nodeType": "B"}, {"nodeType": "C", "y": {"nodeType": "D"}}],
        "z": 1,
    }
    assert [n["nodeType"] for n in iter_nodes(tree)] == ["A", "B", "C", "D"]
    assert [n["nodeType"] for n in child_nodes(tree)] == ["B", "C"]


def _standard_output(tmp_path: Path) -> tuple[dict[str, object], Path]:
    bundle = json.loads(fixture_path("dev/reentrancy/EtherBank_vuln").read_text())
    path = "dev/reentrancy/EtherBank_vuln.sol"
    entry = bundle["sources"][path]
    root = tmp_path / "src"
    (root / Path(path).parent).mkdir(parents=True)
    (root / path).write_text(entry["content"])
    return {"sources": {path: {"id": entry["id"], "ast": entry["ast"]}}}, root


def test_standard_json_output_needs_source_root(tmp_path: Path) -> None:
    document, root = _standard_output(tmp_path)
    loaded = parse_document(document, "solc.json", root)
    assert loaded.units[0].source.content.startswith("// SPDX")
    with pytest.raises(InputError, match="--source-root"):
        parse_document(document, "solc.json", tmp_path / "nowhere")


@pytest.mark.parametrize("escape", ["../outside.sol", "/etc/hosts"])
def test_source_paths_cannot_escape_the_root(tmp_path: Path, escape: str) -> None:
    document, root = _standard_output(tmp_path)
    (tmp_path / "outside.sol").write_text("// not part of the project\n")
    sources = document["sources"]
    assert isinstance(sources, dict)
    sources[escape] = sources.pop(next(iter(sources)))
    with pytest.raises(InputError, match="escapes the source root"):
        parse_document(document, "solc.json", root)


def test_relative_source_resolves_against_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    document, root = _standard_output(tmp_path)
    monkeypatch.chdir(root)
    assert parse_document(document, "solc.json").units[0].source.content.startswith("// SPDX")


def test_bare_source_unit(tmp_path: Path) -> None:
    document, root = _standard_output(tmp_path)
    unit = next(iter(document["sources"].values()))["ast"]  # type: ignore[attr-defined]
    loaded = parse_document(unit, "unit.json", root)
    assert len(loaded.units) == 1


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ([], "must be an object"),
        ({"hello": 1}, "not a solsentry bundle"),
        ({"format": solast.BUNDLE_FORMAT, "sources": {}}, "no sources"),
        ({"format": solast.BUNDLE_FORMAT, "sources": {"a.sol": {"ast": {}}}}, "lacks 'content'"),
        ({"sources": {"a.sol": {"id": 0}}}, "has no 'ast'"),
        ({"sources": {}, "errors": [{"severity": "error", "formattedMessage": "boom"}]}, "boom"),
    ],
)
def test_bad_documents(document: object, message: str) -> None:
    with pytest.raises(InputError, match=message):
        parse_document(document, "x.json")


def test_non_source_unit_ast_rejected() -> None:
    document = {
        "format": solast.BUNDLE_FORMAT,
        "sources": {"a.sol": {"content": "", "ast": {"nodeType": "X"}}},
    }
    with pytest.raises(AstFormatError, match="SourceUnit"):
        parse_document(document, "x.json")


def test_load_path_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(InputError, match="cannot read"):
        load_path(tmp_path / "missing.json")
    broken = tmp_path / "broken.json"
    broken.write_text("{nope")
    with pytest.raises(InputError, match="not valid JSON"):
        load_path(broken)
    monkeypatch.setattr(solast, "MAX_INPUT_BYTES", 1)
    with pytest.raises(InputError, match="limit"):
        load_path(broken)


def test_make_bundle_roundtrip() -> None:
    bundle = json.loads(fixture_path("dev/reentrancy/EtherBank_vuln").read_text())
    path = "dev/reentrancy/EtherBank_vuln.sol"
    entry = bundle["sources"][path]
    output = {"sources": {path: {"id": 0, "ast": entry["ast"]}}}
    rebuilt = make_bundle({path: entry["content"]}, output, "0.8.26+commit.8a97fa7a")
    assert rebuilt["sources"][path]["ast"] == entry["ast"]
    with pytest.raises(AstFormatError):
        make_bundle({"other.sol": ""}, output, "0.8.26")
