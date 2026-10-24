"""Compile Solidity with a *pinned, checksum-verified* solc and wrap the AST in a bundle.

This module is only needed to (re)generate ASTs; analysis itself never runs a compiler.
Binaries are installed with ``py-solc-x`` (optional dependency group ``compile``) and then
verified against the SHA-256 published in binaries.soliditylang.org's ``list.json`` for the
two pinned versions, so a tampered or substituted compiler is rejected before it runs.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
from pathlib import Path
from typing import Any

from solsentry.errors import CompileError
from solsentry.model import parse_version, pragma_min_version
from solsentry.solast import Node, make_bundle

#: version -> platform -> sha256 of the release binary (from binaries.soliditylang.org list.json)
PINNED_SOLC: dict[str, dict[str, str]] = {
    "0.8.26": {
        "macosx-amd64": "0ff016aef2396b12d1fc65429d8ea6cf53c2ee4b041bb8925644615ee1c30ab9",
        "linux-amd64": "d5f23436f443edb85d8e76906d12f0a86ce0490e7663a9e608efeb7a93f149ef",
    },
    "0.7.6": {
        "macosx-amd64": "a6a8f9f9388c5fcd9222474e00270242c832e936b0f5257c20374d27ee5bd1ab",
        "linux-amd64": "bd69ea85427bf2f4da74cb426ad951dd78db9dfdd01d791208eccc2d4958a6bb",
    },
}
LONG_VERSIONS = {"0.8.26": "0.8.26+commit.8a97fa7a", "0.7.6": "0.7.6+commit.7338295f"}
DEFAULT_VERSION = "0.8.26"
LEGACY_VERSION = "0.7.6"
SOLC_TIMEOUT_SECONDS = 120


def platform_key() -> str:
    system = platform.system()
    if system == "Darwin":
        return "macosx-amd64"  # solc ships x86-64/universal macOS builds; Rosetta runs old ones
    if system == "Linux":
        return "linux-amd64"
    raise CompileError(f"no pinned solc binary for platform {system!r}")


def select_version(source_text: str) -> str:
    """Pick the pinned compiler for a source file from its ``pragma solidity`` line."""
    for line in source_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("pragma solidity"):
            literals = ["solidity", stripped[len("pragma solidity") :].rstrip(";").strip()]
            minimum = pragma_min_version(literals)
            if minimum is not None and minimum < (0, 8, 0):
                return LEGACY_VERSION
            return DEFAULT_VERSION
    return DEFAULT_VERSION


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def install_dir() -> Path:
    return Path(os.environ.get("SOLCX_BINARY_PATH", Path.cwd() / ".solcx"))


def solc_binary(version: str) -> Path:
    """Install (if needed) and checksum-verify the pinned solc ``version``."""
    if version not in PINNED_SOLC:
        raise CompileError(f"solc {version} is not pinned; choose one of {sorted(PINNED_SOLC)}")
    expected = PINNED_SOLC[version][platform_key()]
    target_dir = install_dir()
    binary = target_dir / f"solc-v{version}"
    if not binary.exists():
        try:
            import solcx  # noqa: PLC0415 - optional dependency
        except ImportError as exc:
            raise CompileError("py-solc-x is not installed; run `uv sync --extra compile`") from exc
        target_dir.mkdir(parents=True, exist_ok=True)
        os.environ["SOLCX_BINARY_PATH"] = str(target_dir)
        solcx.install_solc(version, show_progress=False)
    actual = sha256_file(binary)
    if actual != expected:
        raise CompileError(f"checksum mismatch for {binary}: expected {expected}, got {actual}")
    return binary


def run_solc(binary: Path, sources: dict[str, str]) -> Node:
    """Run ``solc --standard-json`` requesting only the AST (no code generation)."""
    request = {
        "language": "Solidity",
        "sources": {path: {"content": text} for path, text in sources.items()},
        "settings": {"outputSelection": {"*": {"": ["ast"]}}},
    }
    try:
        completed = subprocess.run(
            [str(binary), "--standard-json"],
            input=json.dumps(request),
            capture_output=True,
            text=True,
            timeout=SOLC_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CompileError(f"failed to run {binary}: {exc}") from exc
    if completed.returncode != 0:
        raise CompileError(f"solc exited with {completed.returncode}: {completed.stderr.strip()}")
    try:
        output: Any = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise CompileError(f"solc produced invalid JSON: {exc}") from exc
    if not isinstance(output, dict):
        raise CompileError("solc output is not a JSON object")
    errors = [e for e in output.get("errors", []) if e.get("severity") == "error"]
    if errors:
        messages = "; ".join(
            str(e.get("formattedMessage", e.get("message"))).strip() for e in errors
        )
        raise CompileError(f"solc reported errors: {messages}")
    return output


def compile_bundle(
    sources: dict[str, str], version: str | None = None, binary: Path | None = None
) -> Node:
    """Compile ``sources`` (path -> text) and return a solsentry bundle."""
    if not sources:
        raise CompileError("nothing to compile")
    chosen = version or select_version(next(iter(sources.values())))
    if parse_version(chosen) is None:
        raise CompileError(f"bad version {chosen!r}")
    solc = binary or solc_binary(chosen)
    output = run_solc(solc, sources)
    return make_bundle(sources, output, LONG_VERSIONS.get(chosen, chosen))
