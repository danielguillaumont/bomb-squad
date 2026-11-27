"""JSON with comments and trailing commas (VS Code's format), read with source positions.

`json` cannot read `.vscode/tasks.json` or `devcontainer.json`, which allow `//` and
`/* */` comments and trailing commas, and it does not say where a value sits. This reader
returns nodes that carry their character offsets, so findings point at the exact key.
It builds plain Python values only; nothing in the input is evaluated.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

MAX_DEPTH = 200


class JsoncError(ValueError):
    def __init__(self, message: str, index: int) -> None:
        super().__init__(message)
        self.index = index


@dataclass
class Node:
    value: object  # str, int, float, bool, None, list[Node] or dict[str, Node]
    start: int
    end: int
    key_spans: dict[str, tuple[int, int]] = field(default_factory=dict)  # objects only

    def get(self, key: str) -> Node | None:
        return self.value.get(key) if isinstance(self.value, dict) else None

    def key_span(self, key: str) -> tuple[int, int]:
        return self.key_spans.get(key, (self.start, self.start + 1))

    def text(self) -> str | None:
        return self.value if isinstance(self.value, str) else None

    def items(self) -> list[Node]:
        return self.value if isinstance(self.value, list) else []


_NUMBER = re.compile(r"-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?")
_STRING = re.compile(r'"(?:[^"\\\n]|\\.)*"')


class _Reader:
    def __init__(self, text: str) -> None:
        self.text = text
        self.i = 0

    def skip(self) -> None:
        text, n = self.text, len(self.text)
        while self.i < n:
            ch = text[self.i]
            if ch in " \t\r\n\ufeff":
                self.i += 1
            elif text.startswith("//", self.i):
                end = text.find("\n", self.i)
                self.i = n if end < 0 else end + 1
            elif text.startswith("/*", self.i):
                end = text.find("*/", self.i + 2)
                if end < 0:
                    raise JsoncError("unterminated comment", self.i)
                self.i = end + 2
            else:
                return

    def value(self, depth: int) -> Node:
        if depth > MAX_DEPTH:
            raise JsoncError(f"nested more than {MAX_DEPTH} levels", self.i)
        self.skip()
        if self.i >= len(self.text):
            raise JsoncError("unexpected end of input", self.i)
        ch = self.text[self.i]
        start = self.i
        if ch == "{":
            return self.obj(depth)
        if ch == "[":
            return self.array(depth)
        if ch == '"':
            return Node(self.string(), start, self.i)
        for word, value in (("true", True), ("false", False), ("null", None)):
            if self.text.startswith(word, self.i):
                self.i += len(word)
                return Node(value, start, self.i)
        match = _NUMBER.match(self.text, self.i)
        if match:
            self.i = match.end()
            number = json.loads(match.group())
            return Node(number, start, self.i)
        raise JsoncError(f"unexpected character {ch!r}", self.i)

    def string(self) -> str:
        match = _STRING.match(self.text, self.i)
        if not match:
            raise JsoncError("unterminated string", self.i)
        self.i = match.end()
        try:
            return json.loads(match.group())
        except ValueError as exc:
            raise JsoncError("invalid string escape", match.start()) from exc

    def obj(self, depth: int) -> Node:
        start = self.i
        self.i += 1
        values: dict[str, Node] = {}
        spans: dict[str, tuple[int, int]] = {}
        while True:
            self.skip()
            if self.text.startswith("}", self.i):
                self.i += 1
                return Node(values, start, self.i, spans)
            if not self.text.startswith('"', self.i):
                raise JsoncError("expected a quoted key", self.i)
            key_start = self.i
            key = self.string()
            key_end = self.i
            self.skip()
            if not self.text.startswith(":", self.i):
                raise JsoncError("expected ':'", self.i)
            self.i += 1
            values[key] = self.value(depth + 1)  # a repeated key keeps its last value
            spans[key] = (key_start, key_end)
            self.skip()
            if self.text.startswith(",", self.i):
                self.i += 1
            elif not self.text.startswith("}", self.i):
                raise JsoncError("expected ',' or '}'", self.i)

    def array(self, depth: int) -> Node:
        start = self.i
        self.i += 1
        values: list[Node] = []
        while True:
            self.skip()
            if self.text.startswith("]", self.i):
                self.i += 1
                return Node(values, start, self.i)
            values.append(self.value(depth + 1))
            self.skip()
            if self.text.startswith(",", self.i):
                self.i += 1
            elif not self.text.startswith("]", self.i):
                raise JsoncError("expected ',' or ']'", self.i)


def parse(text: str) -> Node:
    reader = _Reader(text)
    node = reader.value(0)
    reader.skip()
    if reader.i != len(text):
        raise JsoncError("unexpected text after the value", reader.i)
    return node
