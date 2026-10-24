"""Command-line interface.

Exit codes: 0 success (no findings at or above ``--fail-on``), 1 findings at or above
``--fail-on``, 2 usage or input error.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

from solsentry import __version__
from solsentry.cfg import build_cfg
from solsentry.detectors import detector_infos
from solsentry.engine import AnalysisResult, analyze_path, expand_inputs
from solsentry.errors import SolsentryError
from solsentry.evaluation import evaluate
from solsentry.findings import Severity
from solsentry.model import Program
from solsentry.report import render_json, render_sarif, render_text
from solsentry.solast import load_path

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2

log = logging.getLogger("solsentry")


def _csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _severity(value: str) -> Severity:
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="solsentry",
        description="Static security analysis of Solidity via the solc compact JSON AST.",
    )
    parser.add_argument("--version", action="version", version=f"solsentry {__version__}")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="-v info, -vv debug")
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="run detectors over AST inputs")
    analyze.add_argument(
        "inputs", nargs="+", type=Path, help="bundle/solc JSON files or directories"
    )
    analyze.add_argument("-f", "--format", choices=["text", "json", "sarif"], default="text")
    analyze.add_argument(
        "-o", "--output", type=Path, help="write the report here instead of stdout"
    )
    analyze.add_argument(
        "--detectors", type=_csv, help="comma-separated detector ids (default: all)"
    )
    analyze.add_argument("--exclude", type=_csv, help="comma-separated detector ids to skip")
    analyze.add_argument("--min-severity", type=_severity, default=Severity.INFO)
    analyze.add_argument(
        "--fail-on",
        type=_severity,
        default=None,
        help="exit 1 if a finding has this severity or higher",
    )
    analyze.add_argument(
        "--source-root", type=Path, help="where to find sources for solc JSON inputs"
    )
    analyze.add_argument("--color", action="store_true", help="colourise text output")

    detectors = sub.add_parser("detectors", help="list detectors and their soundness limits")
    detectors.add_argument("-f", "--format", choices=["text", "json"], default="text")

    cfg = sub.add_parser("cfg", help="print the control-flow graph of one function")
    cfg.add_argument("input", type=Path)
    cfg.add_argument("function", help="Contract.function (constructor/fallback/receive by kind)")
    cfg.add_argument("--dot", action="store_true", help="Graphviz DOT instead of text")
    cfg.add_argument("--source-root", type=Path)

    ev = sub.add_parser("eval", help="precision/recall against @expect labels in fixture sources")
    ev.add_argument("inputs", nargs="+", type=Path)
    ev.add_argument("--name", default="fixtures")
    ev.add_argument("-f", "--format", choices=["markdown", "json"], default="markdown")
    ev.add_argument("-o", "--output", type=Path)

    comp = sub.add_parser("compile", help="compile .sol files with a pinned solc into a bundle")
    comp.add_argument("sources", nargs="+", type=Path)
    comp.add_argument("--solc", help="pinned solc version (default: chosen from the pragma)")
    comp.add_argument("-o", "--output", type=Path, required=True)
    return parser


def _emit(text: str, output: Path | None) -> None:
    if output is None:
        sys.stdout.write(text + "\n")
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text + "\n", encoding="utf-8")
        log.info("wrote %s", output)


def _cmd_analyze(args: argparse.Namespace) -> int:
    paths = expand_inputs(args.inputs)
    if not paths:
        raise SolsentryError("no input files found")
    results: list[AnalysisResult] = [
        analyze_path(p, args.detectors, args.exclude, args.min_severity, args.source_root)
        for p in paths
    ]
    if args.format == "sarif":
        text = render_sarif(results)
    elif args.format == "json":
        text = render_json(results)
    else:
        text = render_text(results, color=args.color)
    _emit(text, args.output)
    if args.fail_on is not None:
        worst = [f for r in results for f in r.findings if f.severity.rank >= args.fail_on.rank]
        if worst:
            return EXIT_FINDINGS
    return EXIT_OK


def _cmd_detectors(args: argparse.Namespace) -> int:
    infos = detector_infos()
    if args.format == "json":
        payload = [
            {
                "id": i.id,
                "title": i.title,
                "severity": i.severity.value,
                "confidence": i.confidence.value,
                "cwe": i.cwe,
                "swc": i.swc,
                "description": i.description,
                "soundness": i.soundness,
                "remediation": i.remediation,
            }
            for i in infos
        ]
        _emit(json.dumps(payload, indent=2), None)
        return EXIT_OK
    for info in infos:
        print(f"{info.id:<26} {info.severity.value:<7} {info.swc:<8} {info.title}")
    return EXIT_OK


def _cmd_cfg(args: argparse.Namespace) -> int:
    program = Program(load_path(args.input, args.source_root))
    function = program.function_by_name(args.function)
    if function is None or function.body is None:
        names = sorted(f.qualified_name for f in program.analyzable_functions())
        raise SolsentryError(
            f"no function {args.function!r} with a body; available: {', '.join(names)}"
        )
    graph = build_cfg(program, function)
    _emit(graph.to_dot() if args.dot else graph.to_text(), None)
    return EXIT_OK


def _cmd_eval(args: argparse.Namespace) -> int:
    report = evaluate(args.inputs, args.name)
    text = json.dumps(report.to_dict(), indent=2) if args.format == "json" else report.to_markdown()
    _emit(text, args.output)
    return EXIT_OK


def _cmd_compile(args: argparse.Namespace) -> int:
    from solsentry.compile import compile_bundle  # noqa: PLC0415 - optional dependency path

    sources = {p.name: p.read_text(encoding="utf-8") for p in args.sources}
    bundle = compile_bundle(sources, args.solc)
    _emit(json.dumps(bundle, sort_keys=True, separators=(",", ":")), args.output)
    return EXIT_OK


_COMMANDS = {
    "analyze": _cmd_analyze,
    "detectors": _cmd_detectors,
    "cfg": _cmd_cfg,
    "eval": _cmd_eval,
    "compile": _cmd_compile,
}


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    level = logging.WARNING - 10 * min(args.verbose, 2)
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")
    try:
        return _COMMANDS[args.command](args)
    except (SolsentryError, ValueError, OSError) as exc:
        print(f"solsentry: error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
