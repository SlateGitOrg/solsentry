"""Compile every fixture contract with the pinned solc and write committed AST bundles.

    uv run --extra compile python scripts/compile_fixtures.py            # (re)generate
    uv run --extra compile python scripts/compile_fixtures.py --verify   # recompile + diff

Each ``fixtures/contracts/<split>/<detector>/<Name>.sol`` becomes
``fixtures/ast/<split>/<detector>/<Name>.json`` and an entry in ``fixtures/MANIFEST.json``
recording the compiler and the SHA-256 of both the source and the bundle, so tests can detect
a source edited without regenerating its AST -- entirely offline.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from solsentry.compile import LONG_VERSIONS, compile_bundle, select_version
from solsentry.errors import CompileError

ROOT = Path(__file__).resolve().parent.parent
CONTRACTS = ROOT / "fixtures" / "contracts"
ASTS = ROOT / "fixtures" / "ast"
MANIFEST = ROOT / "fixtures" / "MANIFEST.json"


def encode(bundle: object) -> bytes:
    return (json.dumps(bundle, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--verify", action="store_true", help="recompile and compare, write nothing"
    )
    args = parser.parse_args(argv)
    manifest: dict[str, dict[str, str]] = {}
    mismatches: list[str] = []
    for source_path in sorted(CONTRACTS.rglob("*.sol")):
        relative = source_path.relative_to(CONTRACTS).as_posix()
        text = source_path.read_text(encoding="utf-8")
        version = select_version(text)
        try:
            bundle = compile_bundle({relative: text}, version)
        except CompileError as exc:
            print(f"FAIL {relative}: {exc}", file=sys.stderr)
            return 1
        data = encode(bundle)
        out_path = ASTS / Path(relative).with_suffix(".json")
        if args.verify:
            if not out_path.exists() or out_path.read_bytes() != data:
                mismatches.append(relative)
        else:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_bytes(data)
        manifest[relative] = {
            "solc": LONG_VERSIONS[version],
            "source_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "ast_sha256": hashlib.sha256(data).hexdigest(),
        }
        print(f"{'checked' if args.verify else 'compiled'} {relative} with solc {version}")
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if args.verify:
        if not MANIFEST.exists() or MANIFEST.read_bytes() != manifest_bytes:
            mismatches.append("MANIFEST.json")
        if mismatches:
            print("stale or non-reproducible: " + ", ".join(mismatches), file=sys.stderr)
            return 1
        print(f"all {len(manifest)} fixture ASTs reproduce byte-for-byte")
        return 0
    MANIFEST.write_bytes(manifest_bytes)
    print(f"wrote {len(manifest)} bundles and {MANIFEST.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
