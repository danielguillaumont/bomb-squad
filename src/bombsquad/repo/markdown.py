"""Just enough Markdown structure to tell instructions from code: front matter, fenced
code blocks, inline code spans and HTML comments, each with its position in the file.

Nothing is rendered. The text is never changed, so every position maps back to the file.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})[ \t]*([^\s`]*)[^\n]*$")
_COMMENT = re.compile(r"<!--.*?(?:-->|\Z)", re.DOTALL)
_INLINE = re.compile(r"(?<!`)(`+)(?!`)(.+?)(?<!`)\1(?!`)")


@dataclass
class Fence:
    info: str  # the language word after the opening fence, lower case
    line: int  # 1-based line of the opening fence
    start: int  # index of the first character of the body
    body: str  # the body, as in the file


@dataclass
class Span:
    start: int  # index in the file
    text: str


@dataclass
class Markdown:
    text: str
    lines: list[tuple[int, str]] = field(default_factory=list)  # (start index, line text)
    fences: list[Fence] = field(default_factory=list)
    prose: list[int] = field(default_factory=list)  # 1-based lines outside code blocks
    front_matter: Span | None = None
    comments: list[tuple[int, int]] = field(default_factory=list)  # [start, end) in prose

    def in_comment(self, index: int) -> bool:
        return any(start <= index < end for start, end in self.comments)

    def inline_code(self, line: int) -> list[Span]:
        start, text = self.lines[line - 1]
        return [Span(start + m.start(2), m.group(2)) for m in _INLINE.finditer(text)]


def parse(text: str) -> Markdown:
    doc = Markdown(text)
    index = 0
    for raw in text.split("\n"):
        doc.lines.append((index, raw.removesuffix("\r")))
        index += len(raw) + 1
    total = len(doc.lines)
    line = 1
    if total and doc.lines[0][1].strip() == "---":
        for end in range(2, total + 1):
            if doc.lines[end - 1][1].strip() in ("---", "..."):
                start = doc.lines[1][0] if total > 1 else len(text)
                doc.front_matter = Span(start, text[start:doc.lines[end - 1][0]])
                doc.prose.extend(range(2, end))  # read by the agent like any other text
                line = end + 1
                break
    in_code: set[int] = set()
    while line <= total:
        match = _FENCE.match(doc.lines[line - 1][1])
        if not match:
            doc.prose.append(line)
            line += 1
            continue
        marker, info = match.group(1), match.group(2).lower()
        close = line + 1
        while close <= total:
            candidate = doc.lines[close - 1][1].strip()
            if candidate.startswith(marker[0] * len(marker)) and not candidate.strip(
                    marker[0]):
                break
            close += 1
        body_start = doc.lines[line][0] if line < total else len(text)
        body_end = doc.lines[close - 1][0] if close <= total else len(text)
        doc.fences.append(Fence(info, line, body_start, text[body_start:body_end]))
        in_code.update(range(line, min(close, total) + 1))
        line = close + 1
    for match in _COMMENT.finditer(text):
        if _line_of(doc, match.start()) not in in_code:
            doc.comments.append((match.start(), match.end()))
    return doc


def _line_of(doc: Markdown, index: int) -> int:
    low, high = 0, len(doc.lines) - 1
    while low < high:
        mid = (low + high + 1) // 2
        if doc.lines[mid][0] <= index:
            low = mid
        else:
            high = mid - 1
    return low + 1
