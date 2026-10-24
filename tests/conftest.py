"""Shared helpers: fixture loading and cached analyses."""

from __future__ import annotations

from functools import cache
from pathlib import Path

import pytest

from solsentry.analysis import FunctionAnalysis, ProgramAnalysis
from solsentry.model import Program
from solsentry.solast import AstInput, load_path

ROOT = Path(__file__).resolve().parent.parent
AST_DIR = ROOT / "fixtures" / "ast"
CONTRACTS_DIR = ROOT / "fixtures" / "contracts"


def fixture_path(relative: str) -> Path:
    """``dev/reentrancy/EtherBank_vuln`` -> the committed bundle path."""
    return AST_DIR / f"{relative}.json"


@cache
def load(relative: str) -> AstInput:
    return load_path(fixture_path(relative))


@cache
def program(relative: str) -> Program:
    return Program(load(relative))


@cache
def analysis(relative: str) -> ProgramAnalysis:
    return ProgramAnalysis(program(relative))


def function_analysis(relative: str, qualified: str) -> FunctionAnalysis:
    pa = analysis(relative)
    for fa in pa.functions.values():
        if fa.function.qualified_name == qualified:
            return fa
    raise KeyError(qualified)


@pytest.fixture
def features() -> ProgramAnalysis:
    return analysis("unit/Features")
