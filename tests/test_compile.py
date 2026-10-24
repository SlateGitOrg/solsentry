"""Pinned-compiler wrapper (with a fake solc, so no network or real compiler is needed)."""

from __future__ import annotations

import hashlib
import json
import stat
import sys
from pathlib import Path

import pytest

from solsentry import compile as solc
from solsentry.cli import main
from solsentry.errors import CompileError
from tests.conftest import fixture_path


@pytest.mark.parametrize(
    ("text", "version"),
    [
        ("pragma solidity ^0.7.6;", "0.7.6"),
        ("pragma solidity >=0.6.0 <0.8.0;", "0.7.6"),
        ("pragma solidity ^0.8.20;", "0.8.26"),
        ("// no pragma", "0.8.26"),
    ],
)
def test_select_version(text: str, version: str) -> None:
    assert solc.select_version(text) == version


def test_platform_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(solc.platform, "system", lambda: "Linux")
    assert solc.platform_key() == "linux-amd64"
    monkeypatch.setattr(solc.platform, "system", lambda: "Darwin")
    assert solc.platform_key() == "macosx-amd64"
    monkeypatch.setattr(solc.platform, "system", lambda: "Windows")
    with pytest.raises(CompileError, match="no pinned solc"):
        solc.platform_key()


def _fake_solc(tmp_path: Path, output: str, exit_code: int = 0) -> Path:
    script = tmp_path / "solc-fake"
    payload = tmp_path / "payload.json"
    payload.write_text(output)
    script.write_text(
        f"#!{sys.executable}\nimport sys\nsys.stdin.read()\n"
        f"sys.stdout.write(open({str(payload)!r}).read())\nsys.exit({exit_code})\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return script


def _solc_output() -> tuple[str, str, str]:
    bundle = json.loads(fixture_path("dev/reentrancy/EtherBank_vuln").read_text())
    path, entry = next(iter(bundle["sources"].items()))
    return path, entry["content"], json.dumps({"sources": {path: {"id": 0, "ast": entry["ast"]}}})


def test_compile_bundle_with_fake_binary(tmp_path: Path) -> None:
    path, text, output = _solc_output()
    bundle = solc.compile_bundle({path: text}, "0.8.26", binary=_fake_solc(tmp_path, output))
    assert bundle["compiler"]["version"] == "0.8.26+commit.8a97fa7a"
    assert bundle["sources"][path]["content"] == text


@pytest.mark.parametrize(
    ("output", "code", "message"),
    [
        ("not json", 0, "invalid JSON"),
        ("[]", 0, "not a JSON object"),
        (json.dumps({"errors": [{"severity": "error", "formattedMessage": "Boom"}]}), 0, "Boom"),
        ("{}", 3, "exited with 3"),
    ],
)
def test_run_solc_failures(tmp_path: Path, output: str, code: int, message: str) -> None:
    with pytest.raises(CompileError, match=message):
        solc.run_solc(_fake_solc(tmp_path, output, code), {"a.sol": ""})


def test_run_solc_missing_binary(tmp_path: Path) -> None:
    with pytest.raises(CompileError, match="failed to run"):
        solc.run_solc(tmp_path / "absent", {"a.sol": ""})


def test_compile_bundle_argument_errors() -> None:
    with pytest.raises(CompileError, match="nothing to compile"):
        solc.compile_bundle({})
    with pytest.raises(CompileError, match="bad version"):
        solc.compile_bundle({"a.sol": ""}, "latest", binary=Path("unused"))


def test_solc_binary_checksum_verification(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOLCX_BINARY_PATH", str(tmp_path))
    monkeypatch.setattr(solc.platform, "system", lambda: "Linux")
    fake = tmp_path / "solc-v0.8.26"
    fake.write_bytes(b"not the real compiler")
    with pytest.raises(CompileError, match="checksum mismatch"):
        solc.solc_binary("0.8.26")
    digest = hashlib.sha256(b"not the real compiler").hexdigest()
    monkeypatch.setitem(solc.PINNED_SOLC, "0.8.26", {"linux-amd64": digest})
    assert solc.solc_binary("0.8.26") == fake
    with pytest.raises(CompileError, match="not pinned"):
        solc.solc_binary("0.4.24")
    assert solc.sha256_file(fake) == digest
    assert solc.install_dir() == tmp_path


def test_cli_compile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path, text, output = _solc_output()
    source = tmp_path / Path(path).name
    source.write_text(text)
    fake = _fake_solc(tmp_path, output.replace(path, source.name))
    monkeypatch.setattr(solc, "solc_binary", lambda _version: fake)
    out = tmp_path / "bundle.json"
    assert main(["compile", str(source), "-o", str(out)]) == 0
    assert json.loads(out.read_text())["sources"][source.name]["content"] == text
