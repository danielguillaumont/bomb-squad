"""YAML read as a node graph with source positions, never constructed into objects.

`yaml.compose` with the safe loader stops before construction, so tags such as
`!!python/object` stay inert strings. Aliases point at the node they name rather than
being copied, so an alias bomb costs nothing unless something walks the whole graph;
the readers here only follow the keys they need.
"""

from __future__ import annotations

from dataclasses import dataclass

import yaml

from bombsquad.model import Region
from bombsquad.textpos import Positions


class YamlError(ValueError):
    pass


def compose(text: str) -> yaml.Node | None:
    try:
        return yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.MarkedYAMLError as exc:
        # The message alone: str(exc) quotes the offending input line.
        mark = exc.problem_mark
        where = f" at line {mark.line + 1}" if mark is not None else ""
        raise YamlError(f"{exc.problem or exc.context or 'invalid YAML'}{where}") from None
    except yaml.YAMLError:
        raise YamlError("invalid YAML") from None
    except RecursionError:
        raise YamlError("nested too deeply to read") from None


def text(node: yaml.Node | None) -> str | None:
    return node.value if isinstance(node, yaml.ScalarNode) else None


def pairs(node: yaml.Node | None) -> list[tuple[str, yaml.Node, yaml.Node]]:
    """(key, key node, value node) for a mapping with scalar keys."""
    if not isinstance(node, yaml.MappingNode):
        return []
    return [(k.value, k, v) for k, v in node.value if isinstance(k, yaml.ScalarNode)]


def get(node: yaml.Node | None, key: str) -> yaml.Node | None:
    found = None
    for name, _, value in pairs(node):
        if name == key:
            found = value  # a repeated key keeps its last value
    return found


def key_node(node: yaml.Node | None, key: str) -> yaml.Node | None:
    found = None
    for name, k, _ in pairs(node):
        if name == key:
            found = k
    return found


def items(node: yaml.Node | None) -> list[yaml.Node]:
    return list(node.value) if isinstance(node, yaml.SequenceNode) else []


def strings(node: yaml.Node | None) -> list[str]:
    """A scalar or a sequence of scalars, as a list of strings."""
    if isinstance(node, yaml.ScalarNode):
        return [node.value]
    return [n.value for n in items(node) if isinstance(n, yaml.ScalarNode)]


def region(positions: Positions, node: yaml.Node) -> Region:
    return positions.region(node.start_mark.index, node.end_mark.index)


def first_line(positions: Positions, node: yaml.Node) -> Region:
    return positions.line_region(node.start_mark.line + 1)


@dataclass
class ScalarMap:
    """Where the characters of a scalar's value sit in the file.

    Available for literal blocks (`|`) whose lines can be matched one to one with the
    file, and for one-line plain or quoted scalars without escapes. Otherwise findings
    fall back to the scalar's first line.
    """

    positions: Positions
    node: yaml.Node
    starts: list[int] | None  # file index of each value line's first character

    @classmethod
    def build(cls, positions: Positions, node: yaml.Node) -> ScalarMap:
        if not isinstance(node, yaml.ScalarNode):
            return cls(positions, node, None)
        return cls(positions, node, _line_starts(positions, node))

    def index(self, i: int) -> int | None:
        if self.starts is None:
            return None
        value = self.node.value
        line = value.count("\n", 0, i)
        column = i - (value.rfind("\n", 0, i) + 1)
        return self.starts[line] + column

    def region(self, start: int, end: int) -> Region:
        a, b = self.index(start), self.index(end)
        if a is None or b is None:
            return first_line(self.positions, self.node)
        return self.positions.region(a, b)

    def offset(self) -> tuple[int, int] | None:
        """(line delta, column delta) that maps a region in the value onto the file, when
        every value line starts at the same column."""
        if not self.starts:
            return None
        lines = self.node.value.split("\n")
        columns = {self.positions.region(s, s).column
                   for s, piece in zip(self.starts, lines, strict=True) if piece}
        if len(columns) != 1:
            return None
        line = self.positions.region(self.starts[0], self.starts[0]).line
        return line - 1, columns.pop() - 1


def _line_starts(positions: Positions, node: yaml.ScalarNode) -> list[int] | None:
    value = node.value
    source = positions.text
    start, end = node.start_mark.index, node.end_mark.index
    if node.style is None or node.style in ("'", '"'):
        if "\n" in value:
            return None
        inner = source[start:end]
        if node.style:
            inner = inner[1:-1]
            start += 1
        return [start] if inner == value else None
    if node.style != "|":
        return None
    lines = value.split("\n")
    header = node.start_mark.line + 1  # 1-based line of the `|` indicator
    file_lines = len(positions.line_starts)
    content = [header + 1 + i for i in range(len(lines))]
    body = [n for n, v in zip(content, lines, strict=True) if v]
    if not body or body[-1] > file_lines:
        return None
    indent = None
    starts: list[int] = []
    for line_no, piece in zip(content, lines, strict=True):
        if line_no > file_lines:
            if piece:
                return None
            starts.append(len(source))
            continue
        raw = positions.line_text(line_no).rstrip("\r")
        if piece:
            if indent is None:
                indent = len(raw) - len(piece)
                if indent < 0:
                    return None
            if raw[indent:] != piece or raw[:indent].strip(" "):
                return None
        starts.append(positions.line_starts[line_no - 1] + (indent or 0))
    if indent is None:
        return None
    # Blank lines may be shorter than the indent; keep their start inside the line.
    for k, line_no in enumerate(content):
        if line_no <= file_lines and not lines[k]:
            starts[k] = positions.line_starts[line_no - 1] + min(
                indent, len(positions.line_text(line_no).rstrip("\r")))
    return starts


__all__ = ["ScalarMap", "YamlError", "compose", "first_line", "get", "items", "key_node",
           "pairs", "region", "strings", "text"]
