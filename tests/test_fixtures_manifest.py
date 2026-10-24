"""Offline integrity checks: every fixture source has an up-to-date committed AST bundle."""

from __future__ import annotations

import hashlib
import json

from solsentry.compile import LONG_VERSIONS, select_version
from tests.conftest import AST_DIR, CONTRACTS_DIR, ROOT

MANIFEST = json.loads((ROOT / "fixtures" / "MANIFEST.json").read_text())


def test_every_source_is_in_the_manifest() -> None:
    sources = {p.relative_to(CONTRACTS_DIR).as_posix() for p in CONTRACTS_DIR.rglob("*.sol")}
    assert sources == set(MANIFEST)


def test_hashes_and_compiler_match() -> None:
    for relative, entry in MANIFEST.items():
        text = (CONTRACTS_DIR / relative).read_text(encoding="utf-8")
        assert hashlib.sha256(text.encode()).hexdigest() == entry["source_sha256"], relative
        bundle_path = AST_DIR / relative.replace(".sol", ".json")
        data = bundle_path.read_bytes()
        assert hashlib.sha256(data).hexdigest() == entry["ast_sha256"], relative
        bundle = json.loads(data)
        assert bundle["sources"][relative]["content"] == text
        assert bundle["compiler"]["version"] == entry["solc"] == LONG_VERSIONS[select_version(text)]


def test_vulnerable_and_fixed_files_come_in_pairs() -> None:
    for split in ("dev", "holdout"):
        stems = [p for p in (CONTRACTS_DIR / split).rglob("*.sol") if p.parent.name != "mixed"]
        vuln = {p.name.removesuffix("_vuln.sol") for p in stems if p.name.endswith("_vuln.sol")}
        fixed = {p.name.removesuffix("_fixed.sol") for p in stems if p.name.endswith("_fixed.sol")}
        assert vuln == fixed and len(vuln) * 2 == len(stems)


def test_fixtures_are_marked_as_intentionally_vulnerable() -> None:
    for path in CONTRACTS_DIR.rglob("*_vuln.sol"):
        assert "intentionally vulnerable" in path.read_text(), path
