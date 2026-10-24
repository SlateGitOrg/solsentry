"""Per-function control-flow graphs at statement granularity.

Each CFG node evaluates at most one statement (or one branch condition). Modifiers are
*inlined*: the function CFG starts with the body of its first modifier, every ``_``
placeholder expands to the next modifier (or the function body), and a ``return`` in an inner
level resumes after the placeholder of the enclosing level -- exactly Solidity's semantics.
This lets every analysis see checks performed by ``onlyOwner``-style modifiers as ordinary
dominating guard nodes.

Three distinguished nodes exist in every CFG: ``ENTRY``, ``EXIT`` (normal return) and
``REVERT`` (explicit ``require``/``assert``/``revert`` failure). ``selfdestruct`` halts and is
modelled as an edge to ``EXIT`` labelled ``halt``.
"""

from __future__ import annotations

import logging
from collections import deque
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from enum import Enum

from solsentry.errors import AstFormatError
from solsentry.expr import CallKind, call_kind
from solsentry.model import FunctionInfo, Program
from solsentry.solast import Node

log = logging.getLogger(__name__)

Edge = tuple[int, str]


class NodeKind(Enum):
    ENTRY = "entry"
    EXIT = "exit"
    REVERT = "revert"
    STATEMENT = "stmt"
    CONDITION = "cond"
    RETURN = "return"
    ASSEMBLY = "asm"
    BIND = "bind"
    JOIN = "join"
    TRY = "try"


@dataclass(eq=False)
class CfgNode:
    id: int
    kind: NodeKind
    origin: FunctionInfo
    stmt: Node | None = None
    exprs: list[Node] = field(default_factory=list)
    unchecked: bool = False
    bindings: list[tuple[int, Node | None]] = field(default_factory=list)
    bind_labels: frozenset[str] = frozenset()
    note: str = ""
    succs: list[Edge] = field(default_factory=list)
    preds: list[Edge] = field(default_factory=list)

    @property
    def anchor(self) -> Node | None:
        """The AST node used to report a location for this CFG node."""
        if self.stmt is not None:
            return self.stmt
        return self.exprs[0] if self.exprs else None


class Cfg:
    """Control-flow graph of one function (with its modifiers inlined)."""

    def __init__(self, function: FunctionInfo, program: Program) -> None:
        self.function = function
        self.program = program
        self.nodes: dict[int, CfgNode] = {}
        self.entry = -1
        self.exit = -1
        self.revert = -1

    def __iter__(self) -> Iterator[CfgNode]:
        return iter(self.nodes.values())

    def __len__(self) -> int:
        return len(self.nodes)

    def node(self, node_id: int) -> CfgNode:
        return self.nodes[node_id]

    def successors(self, node_id: int) -> list[int]:
        return [target for target, _ in self.nodes[node_id].succs]

    def predecessors(self, node_id: int) -> list[int]:
        return [source for source, _ in self.nodes[node_id].preds]

    def reachable_from(self, start: int, include_start: bool = False) -> set[int]:
        """Nodes reachable from ``start`` by one or more edges (``start`` only if on a cycle)."""
        seen: set[int] = set()
        queue = deque(self.successors(start))
        while queue:
            current = queue.popleft()
            if current in seen:
                continue
            seen.add(current)
            queue.extend(self.successors(current))
        if include_start:
            seen.add(start)
        return seen

    def can_reach(self, target: int) -> set[int]:
        """All nodes from which ``target`` is reachable (including ``target``)."""
        seen = {target}
        queue = deque([target])
        while queue:
            current = queue.popleft()
            for pred in self.predecessors(current):
                if pred not in seen:
                    seen.add(pred)
                    queue.append(pred)
        return seen

    def reverse_postorder(self) -> list[int]:
        order: list[int] = []
        seen: set[int] = set()
        stack: list[tuple[int, Iterator[int]]] = [(self.entry, iter(self.successors(self.entry)))]
        seen.add(self.entry)
        while stack:
            node_id, children = stack[-1]
            for child in children:
                if child not in seen:
                    seen.add(child)
                    stack.append((child, iter(self.successors(child))))
                    break
            else:
                stack.pop()
                order.append(node_id)
        order.reverse()
        return order

    # -- presentation ---------------------------------------------------------------------

    def describe(self, node: CfgNode) -> str:
        if node.kind in {NodeKind.ENTRY, NodeKind.EXIT, NodeKind.REVERT, NodeKind.JOIN}:
            return node.note or node.kind.name
        if node.kind is NodeKind.BIND:
            return node.note
        anchor = node.anchor
        text = " ".join(self.program.index.text(anchor).split()) if anchor is not None else ""
        if len(text) > 60:
            text = text[:57] + "..."
        location = self.program.index.location(anchor) if anchor is not None else None
        prefix = f"L{location.line} " if location is not None else ""
        return f"{prefix}{text}"

    def to_text(self) -> str:
        lines = [f"CFG {self.function.qualified_name} ({len(self.nodes)} nodes)"]
        for node in self.nodes.values():
            succs = ", ".join(f"{t}{'/' + lbl if lbl else ''}" for t, lbl in node.succs)
            lines.append(f"  n{node.id:<3} {node.kind.value:<6} {self.describe(node)}  -> {succs}")
        return "\n".join(lines)

    def to_dot(self) -> str:
        lines = [
            f'digraph "{self.function.qualified_name}" {{',
            "  node [shape=box, fontname=monospace];",
        ]
        for node in self.nodes.values():
            label = f"n{node.id} {node.kind.value}\\n{self.describe(node)}".replace('"', '\\"')
            shape = "diamond" if node.kind is NodeKind.CONDITION else "box"
            lines.append(f'  n{node.id} [label="{label}", shape={shape}];')
            for target, edge_label in node.succs:
                lines.append(f'  n{node.id} -> n{target} [label="{edge_label}"];')
        lines.append("}")
        return "\n".join(lines)


@dataclass
class _Ctx:
    origin: FunctionInfo
    return_target: int
    unchecked: bool = False
    breaks: list[Edge] | None = None
    continues: list[Edge] | None = None
    placeholder: Callable[[list[Edge]], list[Edge]] | None = None


_SIMPLE_STATEMENTS = {
    "ExpressionStatement",
    "VariableDeclarationStatement",
    "EmitStatement",
}


class CfgBuilder:
    """Builds the CFG of a single function."""

    MAX_NODES = 50_000

    def __init__(self, program: Program, function: FunctionInfo) -> None:
        self.program = program
        self.function = function
        self.cfg = Cfg(function, program)
        self._next_id = 0

    def build(self) -> Cfg:
        if self.function.body is None:
            raise AstFormatError(f"{self.function.qualified_name} has no body")
        cfg = self.cfg
        cfg.entry = self._new(NodeKind.ENTRY, self.function, note="ENTRY")
        cfg.exit = self._new(NodeKind.EXIT, self.function, note="EXIT")
        cfg.revert = self._new(NodeKind.REVERT, self.function, note="REVERT")
        out = self._level(0, [(cfg.entry, "")], cfg.exit)
        self._connect(out, cfg.exit)
        self._prune()
        return cfg

    # -- graph primitives -----------------------------------------------------------------

    def _new(self, kind: NodeKind, origin: FunctionInfo, **fields: object) -> int:
        if self._next_id >= self.MAX_NODES:
            raise AstFormatError(
                f"{self.function.qualified_name}: CFG exceeds {self.MAX_NODES} nodes"
            )
        node = CfgNode(self._next_id, kind, origin, **fields)  # type: ignore[arg-type]
        self.cfg.nodes[node.id] = node
        self._next_id += 1
        return node.id

    def _connect(self, edges: list[Edge], target: int) -> None:
        for source, label in edges:
            self.cfg.nodes[source].succs.append((target, label))
            self.cfg.nodes[target].preds.append((source, label))

    def _prune(self) -> None:
        cfg = self.cfg
        keep = cfg.reachable_from(cfg.entry, include_start=True) | {
            cfg.exit,
            cfg.revert,
        }
        for node_id in list(cfg.nodes):
            if node_id not in keep:
                del cfg.nodes[node_id]
        for node in cfg.nodes.values():
            node.preds = [(s, lbl) for s, lbl in node.preds if s in keep]

    # -- modifier inlining ----------------------------------------------------------------

    def _level(self, level: int, preds: list[Edge], return_target: int) -> list[Edge]:
        modifiers = self.function.modifiers
        if level >= len(modifiers):
            ctx = _Ctx(origin=self.function, return_target=return_target)
            body = self.function.body
            assert body is not None
            return self._statement(body, preds, ctx)
        call = modifiers[level]
        definition = call.definition
        params = [int(p["id"]) for p in definition.parameters]
        args: list[Node | None] = list(call.arguments) + [None] * (
            len(params) - len(call.arguments)
        )
        bind = self._new(
            NodeKind.BIND,
            definition,
            stmt=call.invocation,
            bindings=list(zip(params, args, strict=False)),
            note=f"modifier {definition.name}",
        )
        self._connect(preds, bind)
        if definition.body is None:
            return self._level(level + 1, [(bind, "")], return_target)

        def placeholder(inner_preds: list[Edge]) -> list[Edge]:
            join = self._new(NodeKind.JOIN, definition, note=f"after _ in {definition.name}")
            inner_out = self._level(level + 1, inner_preds, join)
            self._connect(inner_out, join)
            return [(join, "")]

        ctx = _Ctx(origin=definition, return_target=return_target, placeholder=placeholder)
        return self._statement(definition.body, [(bind, "")], ctx)

    # -- statements -----------------------------------------------------------------------

    def _statement(self, stmt: Node, preds: list[Edge], ctx: _Ctx) -> list[Edge]:
        node_type = stmt.get("nodeType")
        handler = getattr(self, f"_stmt_{node_type}", None)
        if handler is not None:
            result: list[Edge] = handler(stmt, preds, ctx)
            return result
        if node_type in _SIMPLE_STATEMENTS:
            return self._simple(stmt, preds, ctx)
        log.debug("unknown statement type %s treated as opaque", node_type)
        node = self._new(NodeKind.STATEMENT, ctx.origin, stmt=stmt, unchecked=ctx.unchecked)
        self._connect(preds, node)
        return [(node, "")]

    def _stmt_Block(self, stmt: Node, preds: list[Edge], ctx: _Ctx) -> list[Edge]:
        current = preds
        for child in stmt.get("statements") or []:
            current = self._statement(child, current, ctx)
        return current

    def _stmt_UncheckedBlock(self, stmt: Node, preds: list[Edge], ctx: _Ctx) -> list[Edge]:
        inner = _Ctx(
            ctx.origin,
            ctx.return_target,
            True,
            ctx.breaks,
            ctx.continues,
            ctx.placeholder,
        )
        return self._stmt_Block(stmt, preds, inner)

    def _simple(self, stmt: Node, preds: list[Edge], ctx: _Ctx) -> list[Edge]:
        node_type = stmt.get("nodeType")
        if node_type == "ExpressionStatement":
            exprs = [stmt["expression"]]
        elif node_type == "EmitStatement":
            exprs = [stmt["eventCall"]]
        else:
            exprs = [stmt["initialValue"]] if stmt.get("initialValue") is not None else []
        node = self._new(
            NodeKind.STATEMENT,
            ctx.origin,
            stmt=stmt,
            exprs=exprs,
            unchecked=ctx.unchecked,
        )
        self._connect(preds, node)
        top = exprs[0] if exprs and node_type == "ExpressionStatement" else None
        if top is not None and top.get("nodeType") == "FunctionCall":
            kind = call_kind(top)
            if kind in {CallKind.REQUIRE, CallKind.ASSERT}:
                self._connect([(node, "fail")], self.cfg.revert)
            elif kind is CallKind.REVERT:
                self._connect([(node, "revert")], self.cfg.revert)
                return []
            elif kind is CallKind.SELFDESTRUCT:
                self._connect([(node, "halt")], self.cfg.exit)
                return []
        return [(node, "")]

    def _stmt_IfStatement(self, stmt: Node, preds: list[Edge], ctx: _Ctx) -> list[Edge]:
        cond = self._new(
            NodeKind.CONDITION,
            ctx.origin,
            stmt=stmt["condition"],
            exprs=[stmt["condition"]],
            unchecked=ctx.unchecked,
        )
        self._connect(preds, cond)
        out = self._statement(stmt["trueBody"], [(cond, "true")], ctx)
        false_body = stmt.get("falseBody")
        if false_body is not None:
            out = out + self._statement(false_body, [(cond, "false")], ctx)
        else:
            out = [*out, (cond, "false")]
        return out

    def _loop_ctx(self, ctx: _Ctx) -> _Ctx:
        return _Ctx(ctx.origin, ctx.return_target, ctx.unchecked, [], [], ctx.placeholder)

    def _stmt_WhileStatement(self, stmt: Node, preds: list[Edge], ctx: _Ctx) -> list[Edge]:
        cond = self._new(
            NodeKind.CONDITION,
            ctx.origin,
            stmt=stmt["condition"],
            exprs=[stmt["condition"]],
            unchecked=ctx.unchecked,
        )
        self._connect(preds, cond)
        loop = self._loop_ctx(ctx)
        body_out = self._statement(stmt["body"], [(cond, "true")], loop)
        assert loop.continues is not None
        assert loop.breaks is not None
        self._connect(body_out + loop.continues, cond)
        return [(cond, "false"), *loop.breaks]

    def _stmt_DoWhileStatement(self, stmt: Node, preds: list[Edge], ctx: _Ctx) -> list[Edge]:
        head = self._new(NodeKind.JOIN, ctx.origin, note="do")
        self._connect(preds, head)
        loop = self._loop_ctx(ctx)
        body_out = self._statement(stmt["body"], [(head, "")], loop)
        cond = self._new(
            NodeKind.CONDITION,
            ctx.origin,
            stmt=stmt["condition"],
            exprs=[stmt["condition"]],
            unchecked=ctx.unchecked,
        )
        assert loop.continues is not None
        assert loop.breaks is not None
        self._connect(body_out + loop.continues, cond)
        self._connect([(cond, "true")], head)
        return [(cond, "false"), *loop.breaks]

    def _stmt_ForStatement(self, stmt: Node, preds: list[Edge], ctx: _Ctx) -> list[Edge]:
        current = preds
        if stmt.get("initializationExpression") is not None:
            current = self._statement(stmt["initializationExpression"], current, ctx)
        head = self._new(NodeKind.JOIN, ctx.origin, note="for")
        self._connect(current, head)
        loop = self._loop_ctx(ctx)
        condition = stmt.get("condition")
        exits: list[Edge] = []
        if condition is not None:
            cond = self._new(
                NodeKind.CONDITION,
                ctx.origin,
                stmt=condition,
                exprs=[condition],
                unchecked=ctx.unchecked,
            )
            self._connect([(head, "")], cond)
            body_preds: list[Edge] = [(cond, "true")]
            exits.append((cond, "false"))
        else:
            body_preds = [(head, "")]
        body_out = self._statement(stmt["body"], body_preds, loop)
        assert loop.continues is not None
        assert loop.breaks is not None
        step_in = body_out + loop.continues
        if stmt.get("loopExpression") is not None:
            step_in = self._statement(stmt["loopExpression"], step_in, ctx)
        self._connect(step_in, head)
        return exits + loop.breaks

    def _stmt_Break(self, _stmt: Node, preds: list[Edge], ctx: _Ctx) -> list[Edge]:
        if ctx.breaks is None:
            raise AstFormatError("break outside of a loop")
        ctx.breaks.extend(preds)
        return []

    def _stmt_Continue(self, _stmt: Node, preds: list[Edge], ctx: _Ctx) -> list[Edge]:
        if ctx.continues is None:
            raise AstFormatError("continue outside of a loop")
        ctx.continues.extend(preds)
        return []

    def _stmt_Return(self, stmt: Node, preds: list[Edge], ctx: _Ctx) -> list[Edge]:
        exprs = [stmt["expression"]] if stmt.get("expression") is not None else []
        node = self._new(
            NodeKind.RETURN, ctx.origin, stmt=stmt, exprs=exprs, unchecked=ctx.unchecked
        )
        self._connect(preds, node)
        self._connect([(node, "return")], ctx.return_target)
        return []

    def _stmt_RevertStatement(self, stmt: Node, preds: list[Edge], ctx: _Ctx) -> list[Edge]:
        node = self._new(NodeKind.STATEMENT, ctx.origin, stmt=stmt, exprs=[stmt["errorCall"]])
        self._connect(preds, node)
        self._connect([(node, "revert")], self.cfg.revert)
        return []

    def _stmt_Throw(self, stmt: Node, preds: list[Edge], ctx: _Ctx) -> list[Edge]:
        node = self._new(NodeKind.STATEMENT, ctx.origin, stmt=stmt)
        self._connect(preds, node)
        self._connect([(node, "revert")], self.cfg.revert)
        return []

    def _stmt_PlaceholderStatement(self, _stmt: Node, preds: list[Edge], ctx: _Ctx) -> list[Edge]:
        if ctx.placeholder is None:
            raise AstFormatError("placeholder statement outside of a modifier")
        return ctx.placeholder(preds)

    def _stmt_InlineAssembly(self, stmt: Node, preds: list[Edge], ctx: _Ctx) -> list[Edge]:
        node = self._new(NodeKind.ASSEMBLY, ctx.origin, stmt=stmt, unchecked=True)
        self._connect(preds, node)
        return [(node, "")]

    def _stmt_TryStatement(self, stmt: Node, preds: list[Edge], ctx: _Ctx) -> list[Edge]:
        call = stmt["externalCall"]
        node = self._new(NodeKind.TRY, ctx.origin, stmt=stmt, exprs=[call], unchecked=ctx.unchecked)
        self._connect(preds, node)
        out: list[Edge] = []
        for position, clause in enumerate(stmt.get("clauses") or []):
            params = (clause.get("parameters") or {}).get("parameters") or []
            success = position == 0
            label = "success" if success else f"catch {clause.get('errorName') or ''}".strip()
            bind = self._new(
                NodeKind.BIND,
                ctx.origin,
                stmt=clause,
                bindings=[(int(p["id"]), call if success else None) for p in params],
                bind_labels=frozenset() if success else frozenset({"EXTCALL"}),
                note=label,
            )
            self._connect([(node, label)], bind)
            out.extend(self._statement(clause["block"], [(bind, "")], ctx))
        return out


def build_cfg(program: Program, function: FunctionInfo) -> Cfg:
    """Build the CFG of ``function`` with its modifiers inlined."""
    return CfgBuilder(program, function).build()
