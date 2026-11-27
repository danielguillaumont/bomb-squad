"""Convert parser positions to SARIF regions: 1-based lines, columns in UTF-16 code units."""

from __future__ import annotations

from bisect import bisect_right

from bombsquad.model import Region


def utf16_len(text: str) -> int:
    return len(text.encode("utf-16-le")) // 2


class Positions:
    """Line lookups for one text, from Python indexes or from UTF-8 byte offsets."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.line_starts = [0]
        for i, ch in enumerate(text):
            if ch == "\n":
                self.line_starts.append(i + 1)
        self._lines_utf8: list[bytes] | None = None

    def line_text(self, line: int) -> str:
        start = self.line_starts[line - 1]
        end = self.line_starts[line] - 1 if line < len(self.line_starts) else len(self.text)
        return self.text[start:end]

    def _point(self, index: int) -> tuple[int, int]:
        line = bisect_right(self.line_starts, index)
        start = self.line_starts[line - 1]
        return line, utf16_len(self.text[start:index]) + 1

    def region(self, start: int, end: int) -> Region:
        """Region for the Python slice text[start:end]."""
        line, column = self._point(start)
        end_line, end_column = self._point(max(start, end))
        return Region(line, column, end_line, end_column)

    def from_utf8(self, line: int, byte_column: int) -> tuple[int, int]:
        """(line, UTF-16 column) from a 1-based line and a 0-based UTF-8 byte column."""
        line = max(1, min(line, len(self.line_starts)))
        prefix = self.line_text(line).encode("utf-8")[:byte_column]
        return line, utf16_len(prefix.decode("utf-8", errors="replace")) + 1

    def region_utf8(self, line: int, byte_column: int, end_line: int, end_byte_column: int
                    ) -> Region:
        start = self.from_utf8(line, byte_column)
        end = self.from_utf8(end_line, end_byte_column)
        return Region(start[0], start[1], end[0], end[1])

    def line_region(self, line: int) -> Region:
        return Region(line, 1, line, utf16_len(self.line_text(line)) + 1)
