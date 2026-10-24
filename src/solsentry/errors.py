"""Exception hierarchy for solsentry.

Every error raised deliberately by the library derives from :class:`SolsentryError`
so callers (and the CLI) can distinguish analyzer failures from programming bugs.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager

log = logging.getLogger(__name__)


class SolsentryError(Exception):
    """Base class for all solsentry errors."""


class InputError(SolsentryError):
    """The input file could not be read or is not a recognised AST format."""


class AstFormatError(SolsentryError):
    """The AST is structurally invalid or uses an unsupported shape."""


class CompileError(SolsentryError):
    """Invoking solc failed (missing binary, checksum mismatch, compiler errors)."""


# Exceptions that analysis code raises when an AST lacks a key or holds a value of the wrong
# type (``node["expression"]`` on a missing key, ``None["id"]``, ``len(5)``, ...), or nests
# expressions deeper than the interpreter's recursion limit.
_MALFORMED_INPUT = (KeyError, TypeError, AttributeError, IndexError, ValueError, RecursionError)


@contextmanager
def input_boundary(origin: str) -> Iterator[None]:
    """Turn a crash on input-derived data into :class:`AstFormatError`.

    solsentry walks solc ASTs with direct key access; validating every node shape up front
    would duplicate the whole analyzer. Instead, everything that runs on one input file runs
    inside this boundary, so a malformed or hostile file ends as an ``AstFormatError`` (exit
    code 2, no traceback) rather than an uncaught exception. Deliberate ``SolsentryError``
    subclasses pass through unchanged. The original traceback is logged at debug level
    (``-vv``) because a genuine analyzer bug on a valid AST would surface here too.
    """
    try:
        yield
    except SolsentryError:
        raise
    except _MALFORMED_INPUT as exc:
        log.debug("malformed input %s", origin, exc_info=True)
        detail = "nesting too deep" if isinstance(exc, RecursionError) else _describe(exc)
        raise AstFormatError(
            f"{origin}: malformed or unsupported AST ({detail}); rerun with -vv for the traceback"
        ) from exc


def _describe(exc: BaseException) -> str:
    text = str(exc)
    if len(text) > 200:
        text = text[:197] + "..."
    return f"{type(exc).__name__}: {text}" if text else type(exc).__name__
