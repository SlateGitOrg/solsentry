"""Loading solc compact JSON ASTs and indexing their nodes.

Three input shapes are accepted:

* a **solsentry bundle** (``{"format": "solsentry-bundle/1", "compiler": {...},
  "sources": {path: {"id", "content", "ast"}}}``) -- self-contained, used for fixtures;
* **solc standard-JSON output** (``{"sources": {path: {"id", "ast"}}}``); the source text
  is read from ``source_root / absolutePath`` because solc does not echo it back;
* a bare ``SourceUnit`` AST node (same source lookup rule).

The loader never executes anything from the input; it is plain JSON parsing with a size cap.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from solsentry.errors import AstFormatError, InputError
from solsentry.source import Location, SourceFile, SrcRange, parse_src

Node = dict[str, Any]

BUNDLE_FORMAT = "solsentry-bundle/1"
MAX_INPUT_BYTES = 64 * 1024 * 1024

log = logging.getLogger(__name__)


@dataclass
class SourceUnitInput:
    """One source unit: its solc file index, path, text and AST root."""

    file_index: int
    path: str
    source: SourceFile
    ast: Node


@dataclass
class AstInput:
    """Everything parsed from one input file."""

    origin: str
    units: list[SourceUnitInput]
    compiler_version: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


def iter_nodes(root: Any) -> Iterator[Node]:
    """Yield every dict that carries a ``nodeType`` beneath ``root`` (pre-order, iterative)."""
    stack: list[Any] = [root]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            if "nodeType" in item:
                yield item
            stack.extend(reversed(list(item.values())))
        elif isinstance(item, list):
            stack.extend(reversed(item))


def child_nodes(node: Node) -> Iterator[Node]:
    """Yield the direct AST children of ``node`` (dicts carrying ``nodeType``)."""
    for value in node.values():
        if isinstance(value, dict) and "nodeType" in value:
            yield value
        elif isinstance(value, list):
            for element in value:
                if isinstance(element, dict) and "nodeType" in element:
                    yield element


class AstIndex:
    """Id-based index over all source units of one input."""

    def __init__(self, ast_input: AstInput) -> None:
        self.input = ast_input
        self.nodes: dict[int, Node] = {}
        self.parent: dict[int, Node] = {}
        self.sources: dict[int, SourceFile] = {}
        for unit in ast_input.units:
            self.sources[unit.file_index] = unit.source
            self._index_unit(unit.ast)

    def _index_unit(self, root: Node) -> None:
        stack: list[tuple[Any, Node | None]] = [(root, None)]
        while stack:
            item, parent = stack.pop()
            if isinstance(item, list):
                stack.extend((element, parent) for element in item)
                continue
            if not isinstance(item, dict):
                continue
            current = parent
            if "nodeType" in item:
                node_id = item.get("id")
                if isinstance(node_id, int):
                    self.nodes[node_id] = item
                    if parent is not None:
                        self.parent[node_id] = parent
                    current = item
            for value in item.values():
                if isinstance(value, (dict, list)):
                    stack.append((value, current))

    def get(self, node_id: int | None) -> Node | None:
        if node_id is None:
            return None
        return self.nodes.get(node_id)

    def parent_of(self, node: Node) -> Node | None:
        node_id = node.get("id")
        return self.parent.get(node_id) if isinstance(node_id, int) else None

    def location(self, node: Node) -> Location | None:
        src = node.get("src")
        if not isinstance(src, str):
            return None
        rng = parse_src(src)
        source = self.sources.get(rng.file_index)
        if source is None:
            return None
        return source.location(rng)

    def text(self, node: Node) -> str:
        src = node.get("src")
        if not isinstance(src, str):
            return ""
        rng: SrcRange = parse_src(src)
        source = self.sources.get(rng.file_index)
        return source.text(rng) if source is not None else ""


def _read_json(path: Path) -> Any:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise InputError(f"cannot read {path}: {exc.strerror}") from exc
    if size > MAX_INPUT_BYTES:
        raise InputError(f"{path} is {size} bytes; the limit is {MAX_INPUT_BYTES}")
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except json.JSONDecodeError as exc:
        raise InputError(f"{path} is not valid JSON: {exc}") from exc
    except RecursionError as exc:  # pragma: no cover - pathological nesting
        raise InputError(f"{path} is nested too deeply to parse") from exc


def _unit_index(ast: Node) -> int:
    src = ast.get("src")
    if not isinstance(src, str):
        raise AstFormatError("SourceUnit without src attribute")
    return parse_src(src).file_index


def _load_text(absolute_path: str, source_root: Path | None) -> str:
    """Read a source named by a solc ``absolutePath``, confined to ``source_root`` (default: cwd).

    A crafted AST must not be able to make solsentry read (and echo into a report) files
    outside the project, so the resolved path has to stay under the root.
    """
    root = (source_root if source_root is not None else Path.cwd()).resolve()
    candidate = (root / absolute_path).resolve()
    if not candidate.is_relative_to(root):
        raise InputError(f"source path {absolute_path!r} escapes the source root {root}")
    if candidate.is_file():
        return candidate.read_text(encoding="utf-8")
    raise InputError(
        f"source text for {absolute_path!r} not found; pass --source-root or use a bundle"
    )


def _require_source_unit(ast: Any, where: str) -> Node:
    if not isinstance(ast, dict) or ast.get("nodeType") != "SourceUnit":
        raise AstFormatError(f"{where}: expected a SourceUnit AST node")
    return ast


def parse_document(document: Any, origin: str, source_root: Path | None = None) -> AstInput:
    """Turn an already-decoded JSON document into an :class:`AstInput`."""
    if not isinstance(document, dict):
        raise InputError(f"{origin}: top-level JSON value must be an object")
    if document.get("format") == BUNDLE_FORMAT:
        return _parse_bundle(document, origin)
    if document.get("nodeType") == "SourceUnit":
        unit = _require_source_unit(document, origin)
        path = str(unit.get("absolutePath", origin))
        text = _load_text(path, source_root)
        return AstInput(
            origin,
            [SourceUnitInput(_unit_index(unit), path, SourceFile(path, text), unit)],
        )
    sources = document.get("sources")
    if isinstance(sources, dict):
        _raise_on_compiler_errors(document, origin)
        units = []
        for path, entry in sources.items():
            if not isinstance(entry, dict) or "ast" not in entry:
                raise InputError(
                    f"{origin}: source {path!r} has no 'ast' (enable it in outputSelection)"
                )
            unit = _require_source_unit(entry["ast"], f"{origin}:{path}")
            text = (
                entry["content"]
                if isinstance(entry.get("content"), str)
                else _load_text(path, source_root)
            )
            units.append(SourceUnitInput(_unit_index(unit), path, SourceFile(path, text), unit))
        return AstInput(origin, sorted(units, key=lambda u: u.file_index))
    raise InputError(f"{origin}: not a solsentry bundle, solc standard-JSON output or SourceUnit")


def _raise_on_compiler_errors(document: Node, origin: str) -> None:
    errors = document.get("errors") or []
    fatal = [e for e in errors if isinstance(e, dict) and e.get("severity") == "error"]
    if fatal:
        first = fatal[0].get("formattedMessage") or fatal[0].get("message") or "unknown error"
        raise InputError(f"{origin}: solc reported {len(fatal)} error(s); first: {first.strip()}")


def _parse_bundle(document: Node, origin: str) -> AstInput:
    sources = document.get("sources")
    if not isinstance(sources, dict) or not sources:
        raise InputError(f"{origin}: bundle has no sources")
    units = []
    for path, entry in sources.items():
        if not isinstance(entry, dict) or not isinstance(entry.get("content"), str):
            raise InputError(f"{origin}: bundle source {path!r} lacks 'content'")
        unit = _require_source_unit(entry.get("ast"), f"{origin}:{path}")
        units.append(
            SourceUnitInput(_unit_index(unit), path, SourceFile(path, entry["content"]), unit)
        )
    compiler = document.get("compiler")
    version = compiler.get("version") if isinstance(compiler, dict) else None
    metadata = {k: v for k, v in document.items() if k not in {"sources"}}
    return AstInput(
        origin,
        sorted(units, key=lambda u: u.file_index),
        version if isinstance(version, str) else None,
        metadata,
    )


def load_path(path: Path, source_root: Path | None = None) -> AstInput:
    """Load one AST input file from disk."""
    log.debug("loading %s", path)
    return parse_document(_read_json(path), str(path), source_root)


def make_bundle(sources: dict[str, str], solc_output: Node, compiler_version: str) -> Node:
    """Build a solsentry bundle from source texts and a solc standard-JSON output."""
    _raise_on_compiler_errors(solc_output, "solc output")
    out_sources: dict[str, Any] = {}
    compiled = solc_output.get("sources", {})
    for path, text in sorted(sources.items()):
        entry = compiled.get(path)
        if not isinstance(entry, dict) or "ast" not in entry:
            raise AstFormatError(f"solc output has no AST for {path!r}")
        out_sources[path] = {
            "id": entry.get("id"),
            "content": text,
            "ast": entry["ast"],
        }
    return {
        "format": BUNDLE_FORMAT,
        "compiler": {"name": "solc", "version": compiler_version},
        "sources": out_sources,
    }
