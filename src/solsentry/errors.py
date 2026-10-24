"""Exception hierarchy for solsentry.

Every error raised deliberately by the library derives from :class:`SolsentryError`
so callers (and the CLI) can distinguish analyzer failures from programming bugs.
"""

from __future__ import annotations


class SolsentryError(Exception):
    """Base class for all solsentry errors."""


class InputError(SolsentryError):
    """The input file could not be read or is not a recognised AST format."""


class AstFormatError(SolsentryError):
    """The AST is structurally invalid or uses an unsupported shape."""


class CompileError(SolsentryError):
    """Invoking solc failed (missing binary, checksum mismatch, compiler errors)."""
