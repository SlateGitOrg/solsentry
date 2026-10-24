"""Source text handling: solc ``src`` ranges, byte offsets and line/column mapping.

solc encodes positions as ``"start:length:fileIndex"`` where ``start`` and ``length``
are *byte* offsets into the UTF-8 encoded source. Line and column numbers reported by
solsentry are 1-based; columns count bytes, matching what solc's own diagnostics do.
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass

from solsentry.errors import AstFormatError

_SRC_RE = re.compile(r"^(-?\d+):(-?\d+):(-?\d+)$")


@dataclass(frozen=True, slots=True)
class SrcRange:
    """A parsed solc ``src`` attribute."""

    start: int
    length: int
    file_index: int


def parse_src(value: str) -> SrcRange:
    """Parse a solc ``src`` string such as ``"120:34:0"``."""
    match = _SRC_RE.match(value)
    if match is None:
        raise AstFormatError(f"malformed src attribute: {value!r}")
    start, length, index = (int(group) for group in match.groups())
    return SrcRange(start, length, index)


@dataclass(frozen=True, slots=True)
class Location:
    """A resolved source location (1-based lines and columns)."""

    path: str
    start: int
    length: int
    line: int
    column: int
    end_line: int
    end_column: int

    def short(self) -> str:
        return f"{self.path}:{self.line}:{self.column}"


class SourceFile:
    """The text of one source unit plus a byte-offset to line index."""

    def __init__(self, path: str, content: str) -> None:
        self.path = path
        self.content = content
        self.data = content.encode("utf-8")
        self._line_starts = [0]
        for offset, byte in enumerate(self.data):
            if byte == 0x0A:
                self._line_starts.append(offset + 1)

    @property
    def line_count(self) -> int:
        return len(self._line_starts)

    def position(self, offset: int) -> tuple[int, int]:
        """Return the 1-based (line, column) of a byte offset."""
        offset = max(0, min(offset, len(self.data)))
        line_index = bisect.bisect_right(self._line_starts, offset) - 1
        return line_index + 1, offset - self._line_starts[line_index] + 1

    def location(self, rng: SrcRange) -> Location:
        line, column = self.position(rng.start)
        end_line, end_column = self.position(rng.start + max(rng.length, 0))
        return Location(self.path, rng.start, rng.length, line, column, end_line, end_column)

    def text(self, rng: SrcRange) -> str:
        return self.data[rng.start : rng.start + rng.length].decode("utf-8", errors="replace")

    def line_text(self, line: int) -> str:
        """Return the text of a 1-based line without its newline."""
        if line < 1 or line > len(self._line_starts):
            return ""
        start = self._line_starts[line - 1]
        end = self._line_starts[line] - 1 if line < len(self._line_starts) else len(self.data)
        return self.data[start:end].decode("utf-8", errors="replace").rstrip("\r")
