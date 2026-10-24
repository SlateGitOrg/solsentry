"""Offline end-to-end demo over the bundled fixtures (run with ``make demo``).

1. list the detectors;
2. analyse three realistic "mixed" holdout contracts and print the findings;
3. print the CFG of one function to show modifier inlining and branch structure;
4. write a SARIF report and summarise it;
5. score the detectors on the dev and holdout splits.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from solsentry.cli import main as cli

ROOT = Path(__file__).resolve().parent.parent
AST = ROOT / "fixtures" / "ast"
OUT = ROOT / "out"


def banner(title: str) -> None:
    print(f"\n=== {title} ===", flush=True)


def run(*argv: str) -> int:
    code = cli(list(argv))
    sys.stdout.flush()
    return code


def main() -> int:
    banner("detectors")
    run("detectors")

    banner("analyze holdout/mixed (realistic contracts, labels hidden from the tool)")
    mixed = AST / "holdout" / "mixed"
    run("analyze", str(mixed))

    banner("CFG of Escrow.release with the nonReentrant modifier inlined")
    run("cfg", str(AST / "dev" / "reentrancy" / "Escrow_fixed.json"), "Escrow.release")

    banner("SARIF 2.1.0 report")
    OUT.mkdir(exist_ok=True)
    sarif_path = OUT / "demo.sarif"
    run("analyze", str(AST / "dev"), str(AST / "holdout"), "-f", "sarif", "-o", str(sarif_path))
    document = json.loads(sarif_path.read_text())
    results = document["runs"][0]["results"]
    by_rule: dict[str, int] = {}
    for result in results:
        by_rule[result["ruleId"]] = by_rule.get(result["ruleId"], 0) + 1
    print(f"wrote {sarif_path.relative_to(ROOT)}: {len(results)} results")
    for rule, count in sorted(by_rule.items()):
        print(f"  {rule:<26} {count}")

    banner("precision / recall")
    run("eval", str(AST / "dev"), "--name", "dev")
    print()
    run("eval", str(AST / "holdout"), "--name", "holdout")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
