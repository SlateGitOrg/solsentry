"""Semantic model built on top of the raw AST: contracts, functions, modifiers, state.

The model is deliberately thin. It resolves the things every analysis needs (which
declarations are state variables, which functions are entry points, which modifiers a
function invokes and with which arguments, which compiler semantics apply) and leaves
everything else to the AST nodes themselves.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from solsentry.solast import AstIndex, AstInput, Node
from solsentry.source import parse_src

Version = tuple[int, int, int]

_VERSION_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")


def parse_version(text: str) -> Version | None:
    """Parse the leading ``X.Y.Z`` of a version string such as ``0.8.26+commit.8a97fa7a``."""
    match = _VERSION_RE.search(text)
    if match is None:
        return None
    major, minor, patch = match.group(1), match.group(2), match.group(3) or "0"
    return int(major), int(minor), int(patch)


def pragma_min_version(literals: list[str]) -> Version | None:
    """Lowest version admitted by a ``pragma solidity`` literal list.

    solc splits ``pragma solidity ^0.7.6;`` into ``["solidity", "^", "0.7", ".6"]``; a range
    like ``>=0.6.0 <0.8.0`` becomes ``["solidity", ">=", "0.6", ".0", "<", "0.8", ".0"]``.
    The first version that is not preceded by ``<`` / ``<=`` is the lower bound.
    """
    if not literals or literals[0] != "solidity":
        return None
    text = "".join(literals[1:])
    for match in re.finditer(r"(<=|>=|<|>|\^|~|=)?\s*(\d+\.\d+(?:\.\d+)?)", text):
        operator, number = match.group(1) or "", match.group(2)
        if operator.startswith("<"):
            continue
        return parse_version(number)
    return None


@dataclass(eq=False)
class StateVar:
    id: int
    name: str
    contract: ContractInfo
    type_string: str
    constant: bool
    immutable: bool
    node: Node

    @property
    def is_bool(self) -> bool:
        return self.type_string == "bool"


@dataclass(eq=False)
class ModifierCall:
    """One ``ModifierInvocation`` on a function, resolved to its definition."""

    definition: FunctionInfo
    arguments: list[Node]
    invocation: Node


@dataclass(eq=False)
class FunctionInfo:
    """A function or modifier definition with a body."""

    id: int
    name: str
    kind: str  # function | constructor | fallback | receive | modifier
    contract: ContractInfo
    visibility: str
    mutability: str
    node: Node
    parameters: list[Node]
    returns: list[Node]
    modifiers: list[ModifierCall] = field(default_factory=list)

    @property
    def body(self) -> Node | None:
        body = self.node.get("body")
        return body if isinstance(body, dict) else None

    @property
    def is_modifier(self) -> bool:
        return self.kind == "modifier"

    @property
    def is_constructor(self) -> bool:
        return self.kind == "constructor"

    @property
    def is_entrypoint(self) -> bool:
        """Callable from outside: public/external/fallback/receive in a non-library contract."""
        if self.is_modifier or self.is_constructor or self.contract.kind == "library":
            return False
        return self.visibility in {"public", "external"} or self.kind in {
            "fallback",
            "receive",
        }

    @property
    def is_state_changing(self) -> bool:
        return self.mutability not in {"view", "pure", "constant"}

    @property
    def qualified_name(self) -> str:
        label = self.name or self.kind
        return f"{self.contract.name}.{label}"

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<FunctionInfo {self.qualified_name}#{self.id}>"


@dataclass(eq=False)
class ContractInfo:
    id: int
    name: str
    kind: str  # contract | interface | library
    abstract: bool
    path: str
    node: Node
    linearized: list[int]
    state_vars: list[StateVar] = field(default_factory=list)
    functions: list[FunctionInfo] = field(default_factory=list)
    modifiers: list[FunctionInfo] = field(default_factory=list)


class Program:
    """All contracts, functions and state variables of one analysis input."""

    def __init__(self, ast_input: AstInput) -> None:
        self.input = ast_input
        self.index = AstIndex(ast_input)
        self.contracts: dict[int, ContractInfo] = {}
        self.state_vars: dict[int, StateVar] = {}
        self.functions: dict[int, FunctionInfo] = {}
        self.compiler_version = (
            parse_version(ast_input.compiler_version) if ast_input.compiler_version else None
        )
        self._pragma_versions: dict[int, Version | None] = {}
        for unit in ast_input.units:
            self._load_unit(unit.file_index, unit.path, unit.ast)
        for function in list(self.functions.values()):
            function.modifiers = self._resolve_modifiers(function)

    # -- loading ---------------------------------------------------------------------------

    def _load_unit(self, file_index: int, path: str, unit: Node) -> None:
        pragma: Version | None = None
        for item in unit.get("nodes", []):
            node_type = item.get("nodeType")
            if node_type == "PragmaDirective" and pragma is None:
                pragma = pragma_min_version([str(x) for x in item.get("literals", [])])
            elif node_type == "ContractDefinition":
                self._load_contract(path, item)
        self._pragma_versions[file_index] = pragma

    def _load_contract(self, path: str, node: Node) -> None:
        contract = ContractInfo(
            id=int(node["id"]),
            name=str(node.get("name", "")),
            kind=str(node.get("contractKind", "contract")),
            abstract=bool(node.get("abstract", False)),
            path=path,
            node=node,
            linearized=[int(x) for x in node.get("linearizedBaseContracts", [node["id"]])],
        )
        self.contracts[contract.id] = contract
        for member in node.get("nodes", []):
            member_type = member.get("nodeType")
            if member_type == "VariableDeclaration":
                var = StateVar(
                    id=int(member["id"]),
                    name=str(member.get("name", "")),
                    contract=contract,
                    type_string=str(member.get("typeDescriptions", {}).get("typeString", "")),
                    constant=bool(member.get("constant", False)),
                    immutable=member.get("mutability") == "immutable",
                    node=member,
                )
                contract.state_vars.append(var)
                self.state_vars[var.id] = var
            elif member_type in {"FunctionDefinition", "ModifierDefinition"}:
                info = self._function_info(contract, member)
                self.functions[info.id] = info
                if info.is_modifier:
                    contract.modifiers.append(info)
                else:
                    contract.functions.append(info)

    @staticmethod
    def _function_info(contract: ContractInfo, node: Node) -> FunctionInfo:
        is_modifier = node.get("nodeType") == "ModifierDefinition"
        kind = "modifier" if is_modifier else str(node.get("kind", "function"))
        if not is_modifier and node.get("isConstructor"):  # solc < 0.5 shape
            kind = "constructor"
        params = node.get("parameters", {}).get("parameters", [])
        returns = node.get("returnParameters", {}).get("parameters", []) if not is_modifier else []
        return FunctionInfo(
            id=int(node["id"]),
            name=str(node.get("name", "")),
            kind=kind,
            contract=contract,
            visibility=str(node.get("visibility", "internal")),
            mutability=str(node.get("stateMutability", "nonpayable")),
            node=node,
            parameters=list(params),
            returns=list(returns),
        )

    def _resolve_modifiers(self, function: FunctionInfo) -> list[ModifierCall]:
        calls: list[ModifierCall] = []
        for invocation in function.node.get("modifiers", []) or []:
            name_node = invocation.get("modifierName", {})
            target = self.functions.get(name_node.get("referencedDeclaration", -1))
            if target is None or not target.is_modifier:
                continue  # base-constructor specifier or unresolved
            calls.append(ModifierCall(target, list(invocation.get("arguments") or []), invocation))
        return calls

    # -- queries ---------------------------------------------------------------------------

    def is_state_var(self, decl_id: int) -> bool:
        return decl_id in self.state_vars

    def declaration(self, node_id: int | None) -> Node | None:
        return self.index.get(node_id)

    def is_variable(self, decl_id: int) -> bool:
        node = self.index.get(decl_id)
        return node is not None and node.get("nodeType") == "VariableDeclaration"

    def file_index_of(self, node: Node) -> int:
        src = node.get("src")
        return parse_src(src).file_index if isinstance(src, str) else -1

    def checked_arithmetic(self, node: Node) -> bool:
        """Whether arithmetic at ``node`` reverts on overflow (solc >= 0.8, not ``unchecked``)."""
        version = self.compiler_version or self._pragma_versions.get(self.file_index_of(node))
        if version is None:
            return True  # unknown: assume modern semantics to avoid noise
        return version >= (0, 8, 0)

    def analyzable_functions(self) -> list[FunctionInfo]:
        """Functions (not modifiers) that have a body, excluding interfaces."""
        return [
            f
            for f in self.functions.values()
            if not f.is_modifier and f.body is not None and f.contract.kind != "interface"
        ]

    def function_by_name(self, qualified: str) -> FunctionInfo | None:
        for function in self.functions.values():
            if function.qualified_name == qualified:
                return function
        return None


def literal_address(node: Node) -> bool:
    """True for a non-zero address literal such as ``0x5B38...`` or ``address(0x1234)``."""
    type_string = str(node.get("typeDescriptions", {}).get("typeString", ""))
    if node.get("nodeType") == "Literal":
        value = str(node.get("value", ""))
        try:
            nonzero = int(value, 0) != 0
        except ValueError:
            nonzero = False
        return nonzero and (type_string.startswith("address") or value.startswith("0x"))
    if node.get("nodeType") == "FunctionCall" and node.get("kind") == "typeConversion":
        args: list[Any] = node.get("arguments") or []
        return len(args) == 1 and literal_address(args[0])
    return False
