"""Expression-level helpers: call classification, l-value roots and read/write effects.

These functions look only at a single expression or statement. Flow-sensitive questions
(which definition reaches here, is this value attacker-controlled) are answered by
:mod:`solsentry.defuse` and :mod:`solsentry.taint`, which consume the effects computed here.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import Enum

from solsentry.model import Program
from solsentry.solast import Node, child_nodes


class CallKind(Enum):
    INTERNAL = "internal"
    EXTERNAL = "external"  # high-level call to another contract (or this.f())
    LIBRARY = "library"  # external library function (DELEGATECALL into code we compiled)
    LOW_CALL = "call"
    LOW_DELEGATECALL = "delegatecall"
    LOW_STATICCALL = "staticcall"
    SEND = "send"
    TRANSFER = "transfer"
    SELFDESTRUCT = "selfdestruct"
    REQUIRE = "require"
    ASSERT = "assert"
    REVERT = "revert"
    EVENT = "event"
    ERROR = "error"
    CONVERSION = "conversion"
    STRUCT = "struct"
    CREATION = "creation"
    ARRAY_PUSH = "push"
    ARRAY_POP = "pop"
    HASH = "hash"
    BUILTIN = "builtin"


#: Calls that can transfer control to code we have not analysed (reentrancy-capable).
REENTRANT_KINDS = frozenset({CallKind.EXTERNAL, CallKind.LOW_CALL, CallKind.LOW_DELEGATECALL})
#: Low-level calls whose boolean success flag must be checked.
LOW_LEVEL_KINDS = frozenset(
    {
        CallKind.LOW_CALL,
        CallKind.LOW_DELEGATECALL,
        CallKind.LOW_STATICCALL,
        CallKind.SEND,
    }
)

_PREFIX_KINDS: tuple[tuple[str, CallKind], ...] = (
    ("t_function_barecallcode", CallKind.LOW_DELEGATECALL),
    ("t_function_barecall", CallKind.LOW_CALL),
    ("t_function_baredelegatecall", CallKind.LOW_DELEGATECALL),
    ("t_function_barestaticcall", CallKind.LOW_STATICCALL),
    ("t_function_send", CallKind.SEND),
    ("t_function_transfer", CallKind.TRANSFER),
    ("t_function_selfdestruct", CallKind.SELFDESTRUCT),
    ("t_function_require", CallKind.REQUIRE),
    ("t_function_assert", CallKind.ASSERT),
    ("t_function_revert", CallKind.REVERT),
    ("t_function_external", CallKind.EXTERNAL),
    ("t_function_delegatecall", CallKind.LIBRARY),
    ("t_function_internal", CallKind.INTERNAL),
    ("t_function_event", CallKind.EVENT),
    ("t_function_error", CallKind.ERROR),
    ("t_function_creation", CallKind.CREATION),
    ("t_function_arraypush", CallKind.ARRAY_PUSH),
    ("t_function_arraypop", CallKind.ARRAY_POP),
    ("t_function_keccak256", CallKind.HASH),
    ("t_function_sha256", CallKind.HASH),
    ("t_function_ripemd160", CallKind.HASH),
)

_MAGIC = {
    ("msg", "sender"): "SENDER",
    ("msg", "value"): "VALUE",
    ("msg", "data"): "CALLDATA",
    ("msg", "sig"): "CALLDATA",
    ("tx", "origin"): "ORIGIN",
    ("block", "timestamp"): "TIMESTAMP",
    ("block", "number"): "BLOCK",
}


def type_id(node: Node) -> str:
    return str(node.get("typeDescriptions", {}).get("typeIdentifier", ""))


def type_string(node: Node) -> str:
    return str(node.get("typeDescriptions", {}).get("typeString", ""))


def unwrap_callee(call: Node) -> Node:
    """The callee expression with ``{value: ..}`` options and ``.value()`` chains removed."""
    callee: Node = call["expression"]
    while callee.get("nodeType") == "FunctionCallOptions":
        callee = callee["expression"]
    return callee


def call_kind(call: Node) -> CallKind:
    """Classify a ``FunctionCall`` node."""
    kind = call.get("kind")
    if kind == "typeConversion":
        return CallKind.CONVERSION
    if kind == "structConstructorCall":
        return CallKind.STRUCT
    callee_type = type_id(call.get("expression", {}))
    for prefix, result in _PREFIX_KINDS:
        if callee_type.startswith(prefix):
            return result
    callee = unwrap_callee(call)
    if callee.get("nodeType") == "NewExpression":
        return CallKind.CREATION
    if callee.get("nodeType") == "Identifier" and callee.get("name") in {
        "selfdestruct",
        "suicide",
    }:
        return CallKind.SELFDESTRUCT
    return CallKind.BUILTIN


def is_reentrant_call(call: Node) -> bool:
    """A call that may run attacker code able to re-enter with state-changing calls.

    ``view``/``pure`` external functions and ``staticcall`` compile to STATICCALL, whose callee
    cannot modify state; ``transfer``/``send`` forward only the 2300-gas stipend.
    """
    kind = call_kind(call)
    if kind not in REENTRANT_KINDS:
        return False
    callee_type = type_id(call.get("expression", {}))
    return not callee_type.startswith(("t_function_external_view", "t_function_external_pure"))


def internal_target(call: Node, program: Program) -> int | None:
    """Declaration id of the function an internal call statically resolves to."""
    callee = unwrap_callee(call)
    ref = callee.get("referencedDeclaration")
    if isinstance(ref, int) and ref in program.functions:
        return ref
    return None


def internal_call_args(call: Node, program: Program) -> list[Node]:
    """Arguments of an internal call, including the bound receiver of ``using for`` calls."""
    args: list[Node] = list(call.get("arguments") or [])
    target = internal_target(call, program)
    callee = unwrap_callee(call)
    if target is None or callee.get("nodeType") != "MemberAccess":
        return args
    if len(program.functions[target].parameters) == len(args) + 1:
        return [callee["expression"], *args]
    return args


def call_receiver(call: Node) -> Node | None:
    """The address/contract expression a call is made on (``t`` in ``t.call(..)``)."""
    callee = unwrap_callee(call)
    if callee.get("nodeType") == "MemberAccess":
        receiver: Node = callee["expression"]
        return receiver
    return None


def call_value(call: Node) -> Node | None:
    """The wei amount sent by a call, if any (``{value: v}``, ``send(v)``, ``transfer(v)``)."""
    kind = call_kind(call)
    args = call.get("arguments") or []
    if kind in {CallKind.SEND, CallKind.TRANSFER}:
        return args[0] if args else None
    callee = call.get("expression", {})
    while callee.get("nodeType") == "FunctionCallOptions":
        names = callee.get("names") or []
        options = callee.get("options") or []
        for name, option in zip(names, options, strict=False):
            if name == "value":
                result: Node = option
                return result
        callee = callee["expression"]
    return None


def magic_label(node: Node) -> str | None:
    """Taint label for ``msg.sender``, ``tx.origin``, ``block.timestamp``, ``now`` ..."""
    node_type = node.get("nodeType")
    if node_type == "Identifier" and node.get("name") == "now":
        ref = node.get("referencedDeclaration")
        return "TIMESTAMP" if not isinstance(ref, int) or ref < 0 else None
    if node_type != "MemberAccess":
        return None
    base = node.get("expression", {})
    if base.get("nodeType") != "Identifier":
        return None
    ref = base.get("referencedDeclaration")
    if isinstance(ref, int) and ref >= 0:
        return None
    return _MAGIC.get((str(base.get("name")), str(node.get("memberName"))))


def is_self_balance(node: Node) -> bool:
    """``address(this).balance``."""
    if node.get("nodeType") != "MemberAccess" or node.get("memberName") != "balance":
        return False
    base = node.get("expression", {})
    if base.get("nodeType") == "FunctionCall" and base.get("kind") == "typeConversion":
        args = base.get("arguments") or []
        base = args[0] if args else {}
    return base.get("nodeType") == "Identifier" and base.get("name") == "this"


def lvalue_roots(expr: Node) -> list[tuple[Node, bool]]:
    """Root identifiers written by an assignment target, with a *strong update* flag.

    ``x = ..`` strongly updates ``x``; ``m[k] = ..`` / ``s.f = ..`` weakly update the root.
    Tuple targets yield one entry per non-empty component.
    """
    node_type = expr.get("nodeType")
    if node_type == "TupleExpression":
        roots: list[tuple[Node, bool]] = []
        for component in expr.get("components") or []:
            if component is not None:
                roots.extend(lvalue_roots(component))
        return roots
    strong = node_type == "Identifier"
    current = expr
    while current.get("nodeType") in {
        "MemberAccess",
        "IndexAccess",
        "IndexRangeAccess",
    }:
        key = "expression" if current.get("nodeType") == "MemberAccess" else "baseExpression"
        current = current[key]
    if current.get("nodeType") == "Identifier":
        return [(current, strong)]
    return []


@dataclass(frozen=True)
class Write:
    """A (possibly weak) definition of variable ``var`` at some node."""

    var: int
    strong: bool
    sources: tuple[Node, ...]
    site: Node
    extra_labels: frozenset[str] = frozenset()


@dataclass
class Effects:
    """Variables read and written, and calls made, by one CFG node."""

    reads: set[int] = field(default_factory=set)
    writes: list[Write] = field(default_factory=list)
    calls: list[Node] = field(default_factory=list)


class EffectCollector:
    """Computes :class:`Effects` for expressions and statements."""

    def __init__(self, program: Program) -> None:
        self.program = program

    def _var_ref(self, ident: Node) -> int | None:
        ref = ident.get("referencedDeclaration")
        if isinstance(ref, int) and self.program.is_variable(ref):
            return ref
        return None

    def expression(self, expr: Node, effects: Effects) -> None:
        self._visit(expr, effects, lvalue=False)

    def _visit(self, expr: Node, effects: Effects, lvalue: bool) -> None:
        node_type = expr.get("nodeType")
        if node_type == "Identifier":
            ref = self._var_ref(expr)
            if ref is not None and not lvalue:
                effects.reads.add(ref)
        elif node_type == "MemberAccess":
            self._visit(expr["expression"], effects, lvalue)
        elif node_type == "IndexAccess":
            self._visit(expr["baseExpression"], effects, lvalue)
            if expr.get("indexExpression") is not None:
                self._visit(expr["indexExpression"], effects, False)
        elif node_type == "Assignment":
            self._assignment(expr, effects)
        elif node_type == "UnaryOperation":
            self._unary(expr, effects)
        elif node_type == "FunctionCall":
            self._call(expr, effects)
        elif node_type == "TupleExpression":
            for component in expr.get("components") or []:
                if component is not None:
                    self._visit(component, effects, lvalue)
        else:
            for child in child_nodes(expr):
                if not str(child.get("nodeType", "")).endswith(("TypeName", "Mapping")):
                    self._visit(child, effects, False)

    def _assignment(self, expr: Node, effects: Effects) -> None:
        lhs, rhs = expr["leftHandSide"], expr["rightHandSide"]
        operator = expr.get("operator", "=")
        self._visit(lhs, effects, lvalue=True)
        if operator != "=":
            self._visit(lhs, effects, lvalue=False)
        self._visit(rhs, effects, lvalue=False)
        targets = lvalue_roots(lhs)
        pairwise = (
            lhs.get("nodeType") == "TupleExpression"
            and rhs.get("nodeType") == "TupleExpression"
            and len(lhs.get("components") or []) == len(rhs.get("components") or [])
        )
        if pairwise:
            for target, value in zip(lhs["components"], rhs["components"], strict=True):
                if target is None:
                    continue
                for root, strong in lvalue_roots(target):
                    self._add_write(effects, root, strong, (value,) if value else (), expr)
            return
        sources = (rhs,) if operator == "=" else (lhs, rhs)
        for root, strong in targets:
            self._add_write(effects, root, strong and operator == "=", sources, expr)

    def _unary(self, expr: Node, effects: Effects) -> None:
        operator = expr.get("operator")
        sub = expr["subExpression"]
        if operator in {"++", "--"}:
            self._visit(sub, effects, lvalue=False)
            for root, strong in lvalue_roots(sub):
                self._add_write(effects, root, strong, (sub,), expr)
        elif operator == "delete":
            self._visit(sub, effects, lvalue=True)
            for root, strong in lvalue_roots(sub):
                self._add_write(effects, root, strong, (), expr)
        else:
            self._visit(sub, effects, lvalue=False)

    def _call(self, call: Node, effects: Effects) -> None:
        kind = call_kind(call)
        callee = call["expression"]
        if kind is not CallKind.CONVERSION:
            self._visit(callee, effects, lvalue=False)
        args = call.get("arguments") or []
        for arg in args:
            self._visit(arg, effects, lvalue=False)
        effects.calls.append(call)
        if kind in {CallKind.ARRAY_PUSH, CallKind.ARRAY_POP}:
            receiver = call_receiver(call)
            if receiver is not None:
                for root, _ in lvalue_roots(receiver):
                    self._add_write(effects, root, False, tuple(args), call)

    def _add_write(
        self,
        effects: Effects,
        root: Node,
        strong: bool,
        sources: tuple[Node, ...],
        site: Node,
        extra: frozenset[str] = frozenset(),
    ) -> None:
        ref = self._var_ref(root)
        if ref is not None:
            effects.writes.append(Write(ref, strong, sources, site, extra))

    # -- statement-level helpers used by the CFG ----------------------------------------------

    def declaration_statement(self, stmt: Node, effects: Effects) -> None:
        declarations = stmt.get("declarations") or []
        initial = stmt.get("initialValue")
        if initial is not None:
            self.expression(initial, effects)
        pairwise = (
            initial is not None
            and initial.get("nodeType") == "TupleExpression"
            and len(initial.get("components") or []) == len(declarations)
        )
        for position, decl in enumerate(declarations):
            if decl is None:
                continue
            if pairwise and initial is not None:
                value = initial["components"][position]
                sources: tuple[Node, ...] = (value,) if value is not None else ()
            else:
                sources = (initial,) if initial is not None else ()
            effects.writes.append(Write(int(decl["id"]), True, sources, stmt))


def iter_calls(expr: Node) -> Iterator[Node]:
    """All ``FunctionCall`` nodes within an expression, outermost first."""
    stack = [expr]
    while stack:
        node = stack.pop()
        if node.get("nodeType") == "FunctionCall":
            yield node
        stack.extend(reversed(list(child_nodes(node))))


def iter_subexpressions(expr: Node) -> Iterator[Node]:
    """``expr`` and every expression node beneath it (pre-order)."""
    stack = [expr]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(list(child_nodes(node))))


def expr_key(expr: Node) -> str:
    """Structural identity of an expression, used to match checks against operations.

    Two syntactically different spellings of the same access path (``balances[msg.sender]``
    written twice) map to the same key; type conversions are transparent.
    """
    node_type = expr.get("nodeType")
    if node_type == "Identifier":
        ref = expr.get("referencedDeclaration")
        return f"v{ref}" if isinstance(ref, int) and ref >= 0 else f"g:{expr.get('name')}"
    if node_type == "MemberAccess":
        return f"{expr_key(expr['expression'])}.{expr.get('memberName')}"
    if node_type == "IndexAccess":
        index = expr.get("indexExpression")
        inner = expr_key(index) if index is not None else ""
        return f"{expr_key(expr['baseExpression'])}[{inner}]"
    if node_type == "Literal":
        return f"lit:{expr.get('value')}"
    if node_type == "BinaryOperation":
        left, right = (
            expr_key(expr["leftExpression"]),
            expr_key(expr["rightExpression"]),
        )
        return f"({left}{expr.get('operator')}{right})"
    if node_type == "TupleExpression":
        components = [c for c in expr.get("components") or [] if c is not None]
        if len(components) == 1:
            return expr_key(components[0])
    if node_type == "FunctionCall":
        args = expr.get("arguments") or []
        if expr.get("kind") == "typeConversion" and len(args) == 1:
            return expr_key(args[0])
        inner = ",".join(expr_key(a) for a in args)
        return f"{expr_key(expr['expression'])}({inner})"
    return f"#{node_type}:{expr.get('id')}"


def is_literal(expr: Node) -> bool:
    if expr.get("nodeType") == "Literal":
        return True
    if expr.get("nodeType") == "FunctionCall" and expr.get("kind") == "typeConversion":
        args = expr.get("arguments") or []
        return len(args) == 1 and is_literal(args[0])
    return bool(expr.get("isConstant")) and bool(expr.get("isPure"))
