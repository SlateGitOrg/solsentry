"""Semantic model and expression helpers."""

from __future__ import annotations

import pytest

from solsentry.expr import (
    CallKind,
    call_kind,
    call_value,
    expr_key,
    internal_call_args,
    is_literal,
    is_reentrant_call,
    iter_calls,
    lvalue_roots,
    magic_label,
)
from solsentry.model import literal_address, parse_version, pragma_min_version
from tests.conftest import program


@pytest.mark.parametrize(
    ("literals", "expected"),
    [
        (["solidity", "^", "0.7", ".6"], (0, 7, 6)),
        (["solidity", ">=", "0.6", ".0", "<", "0.8", ".0"], (0, 6, 0)),
        (["solidity", "<", "0.8", ".0"], None),
        (["solidity", "0.8", ".26"], (0, 8, 26)),
        (["abicoder", "v2"], None),
        ([], None),
    ],
)
def test_pragma_min_version(literals: list[str], expected: tuple[int, int, int] | None) -> None:
    assert pragma_min_version(literals) == expected


def test_parse_version() -> None:
    assert parse_version("0.8.26+commit.8a97fa7a") == (0, 8, 26)
    assert parse_version("0.7") == (0, 7, 0)
    assert parse_version("nightly") is None


def test_program_structure() -> None:
    prog = program("unit/Features")
    contract = next(c for c in prog.contracts.values() if c.name == "Features")
    assert {v.name for v in contract.state_vars} == {
        "owner",
        "total",
        "items",
        "balances",
        "entered",
    }
    names = {f.name for f in contract.functions}
    assert {"loops", "modified", "guarded", "tryIt", "asmDestroy"} <= names
    modified = prog.function_by_name("Features.modified")
    assert modified is not None
    assert [m.definition.name for m in modified.modifiers] == ["twice", "early"]
    assert modified.is_entrypoint and modified.is_state_changing
    ctor = next(f for f in contract.functions if f.is_constructor)
    assert not ctor.is_entrypoint
    assert prog.function_by_name("Nope.nothing") is None
    interface = next(c for c in prog.contracts.values() if c.name == "IThing")
    assert interface.kind == "interface"
    assert all(f.contract.kind != "interface" for f in prog.analyzable_functions())


def test_checked_arithmetic_follows_compiler() -> None:
    modern, legacy = program("unit/Features"), program("unit/Legacy")
    some_node = next(iter(modern.index.nodes.values()))
    assert modern.checked_arithmetic(some_node)
    legacy_node = next(iter(legacy.index.nodes.values()))
    assert not legacy.checked_arithmetic(legacy_node)
    legacy.compiler_version = None  # fall back to the pragma (>=0.7.0 <0.8.0)
    assert not legacy.checked_arithmetic(legacy_node)
    assert legacy.checked_arithmetic({"nodeType": "X"})  # unknown file: assume modern


def _calls(relative: str, function: str) -> list[dict[str, object]]:
    prog = program(relative)
    info = prog.function_by_name(function)
    assert info is not None and info.body is not None
    return list(iter_calls(info.body))


def test_call_classification() -> None:
    kinds = [call_kind(c) for c in _calls("unit/Features", "Features.tryIt")]
    assert CallKind.EXTERNAL in kinds
    kinds = {call_kind(c) for c in _calls("unit/Features", "Features.popAndDelete")}
    assert {CallKind.REQUIRE, CallKind.ARRAY_POP} <= kinds
    sd = _calls("dev/unprotected-selfdestruct/Killable_vuln", "Killable.kill")
    assert [call_kind(c) for c in sd] == [CallKind.SELFDESTRUCT, CallKind.CONVERSION]
    sends = _calls("dev/unchecked-call/Payout_vuln", "Payout.pay")
    assert CallKind.SEND in {call_kind(c) for c in sends}
    view = [
        c for c in _calls("unit/Features", "Features.viewCall") if call_kind(c) is CallKind.EXTERNAL
    ]
    assert view and not is_reentrant_call(view[0])


def test_call_value_and_receiver() -> None:
    calls = _calls("dev/reentrancy/EtherBank_vuln", "EtherBank.withdraw")
    low = next(c for c in calls if call_kind(c) is CallKind.LOW_CALL)
    value = call_value(low)
    assert value is not None and value.get("name") == "amount"
    assert is_reentrant_call(low)
    transfer = next(
        c
        for c in _calls("dev/tx-origin/OriginWallet_vuln", "OriginWallet.transferTo")
        if call_kind(c) is CallKind.TRANSFER
    )
    assert call_value(transfer) is not None
    require = next(c for c in calls if call_kind(c) is CallKind.REQUIRE)
    assert call_value(require) is None


def test_using_for_receiver_is_first_argument() -> None:
    prog = program("dev/integer-overflow/BatchToken_fixed")
    calls = _calls("dev/integer-overflow/BatchToken_fixed", "BatchToken.batchTransfer")
    mul = next(c for c in calls if call_kind(c) is CallKind.INTERNAL)
    args = internal_call_args(mul, prog)
    assert [a.get("name") for a in args] == ["count", "value"]


def test_magic_labels() -> None:
    def member(base: str, name: str, ref: int = -1) -> dict[str, object]:
        ident = {"nodeType": "Identifier", "name": base, "referencedDeclaration": ref}
        return {"nodeType": "MemberAccess", "expression": ident, "memberName": name}

    assert magic_label(member("msg", "sender")) == "SENDER"
    assert magic_label(member("tx", "origin")) == "ORIGIN"
    assert magic_label(member("block", "timestamp")) == "TIMESTAMP"
    assert magic_label(member("msg", "sender", ref=5)) is None  # shadowed local named msg
    assert (
        magic_label({"nodeType": "Identifier", "name": "now", "referencedDeclaration": -17})
        == "TIMESTAMP"
    )
    assert (
        magic_label({"nodeType": "Identifier", "name": "now", "referencedDeclaration": 3}) is None
    )
    assert magic_label({"nodeType": "MemberAccess", "expression": {"nodeType": "Literal"}}) is None


def test_expr_keys_and_lvalues() -> None:
    ident = {"nodeType": "Identifier", "referencedDeclaration": 7, "name": "x"}
    index = {
        "nodeType": "IndexAccess",
        "baseExpression": ident,
        "indexExpression": {"nodeType": "Literal", "value": "1"},
    }
    member = {"nodeType": "MemberAccess", "expression": index, "memberName": "f"}
    conversion = {
        "nodeType": "FunctionCall",
        "kind": "typeConversion",
        "arguments": [ident],
        "expression": {},
    }
    assert expr_key(member) == "v7[lit:1].f"
    assert expr_key(conversion) == "v7"
    assert expr_key({"nodeType": "TupleExpression", "components": [ident]}) == "v7"
    assert (
        expr_key({"nodeType": "Identifier", "name": "msg", "referencedDeclaration": -15}) == "g:msg"
    )
    assert expr_key({"nodeType": "Conditional", "id": 4}) == "#Conditional:4"
    assert lvalue_roots(ident) == [(ident, True)]
    assert lvalue_roots(member) == [(ident, False)]
    tuple_expr = {"nodeType": "TupleExpression", "components": [ident, None, member]}
    assert lvalue_roots(tuple_expr) == [(ident, True), (ident, False)]
    call = {"nodeType": "FunctionCall", "kind": "functionCall", "arguments": [], "expression": {}}
    assert lvalue_roots(call) == []
    assert is_literal({"nodeType": "Literal"})
    assert is_literal(
        {
            "nodeType": "FunctionCall",
            "kind": "typeConversion",
            "arguments": [{"nodeType": "Literal"}],
        }
    )
    assert not is_literal(ident)


def test_literal_address() -> None:
    lit = {"nodeType": "Literal", "value": "0x1234", "typeDescriptions": {"typeString": "address"}}
    zero = {"nodeType": "Literal", "value": "0", "typeDescriptions": {"typeString": "int_const 0"}}
    conv = {"nodeType": "FunctionCall", "kind": "typeConversion", "arguments": [lit]}
    assert literal_address(lit)
    assert literal_address(conv)
    assert not literal_address(zero)
    assert not literal_address({"nodeType": "Literal", "value": "hello"})
    assert not literal_address({"nodeType": "Identifier"})
