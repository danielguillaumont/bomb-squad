"""Run the PowerShell parser on untrusted text without running the text.

The syntax tree comes from PowerShell's own parser (`Parser.ParseInput`), called by
`dump_ast.ps1` in a separate process. Before parsing, `using module` and
`using assembly` statements are blanked out, because the parser opens the files they
name (a network path would mean a network connection from the scanning machine).
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from importlib import resources

from bombsquad.model import Region


class ParserUnavailable(Exception):
    """Neither PowerShell 7 (pwsh) nor Windows PowerShell was found."""


class ParserFailed(Exception):
    """The parser process failed or returned something unreadable."""


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    line: int
    column: int
    end_line: int
    end_column: int

    @classmethod
    def from_dict(cls, data: dict) -> Span:
        return cls(**{k: int(data[k]) for k in ("start", "end", "line", "column", "end_line",
                                                 "end_column")})

    def contains(self, other: Span) -> bool:
        return self.start <= other.start and other.end <= self.end

    @property
    def region(self) -> Region:
        return Region(self.line, self.column, self.end_line, self.end_column)


@dataclass(frozen=True)
class Element:
    kind: str  # parameter | value
    name: str | None
    value: str | None
    has_argument: bool
    text: str
    span: Span
    variables: tuple[str, ...]


@dataclass(frozen=True)
class Command:
    name: str | None
    name_source: str | None  # literal | folded | None when computed at run time
    name_text: str
    operator: str  # Unknown | Ampersand | Dot
    text: str
    span: Span
    elements: tuple[Element, ...]
    pipeline: Span | None
    pipeline_index: int
    # For `& $Tool`, the values [ValidateSet()] allows $Tool, when they are string literals.
    name_choices: tuple[str, ...] = ()


@dataclass(frozen=True)
class Invocation:
    member: str | None
    static: bool
    type_name: str | None
    target_text: str
    arguments: tuple[str | None, ...]
    arg_count: int
    variables: tuple[str, ...]
    text: str
    span: Span


@dataclass(frozen=True)
class StringValue:
    value: str
    span: Span
    folded: bool


@dataclass(frozen=True)
class Assignment:
    variable: str
    value_span: Span


@dataclass(frozen=True)
class BlankedUsing:
    kind: str
    text: str
    span: Span


@dataclass
class ParsedDocument:
    id: str
    text: str
    parse_errors: list[dict]
    commands: list[Command]
    invocations: list[Invocation]
    strings: list[StringValue]
    assignments: list[Assignment]
    functions: set[str]
    blanked_usings: list[BlankedUsing] = field(default_factory=list)


def _list(value) -> list:
    """A JSON array from the dumper. Windows PowerShell 5.1 serialises some arrays as
    {"value": [...], "Count": n} and some empty arrays as {}, so both are unwrapped."""
    if value is None:
        return []
    if isinstance(value, dict) and "value" in value and "Count" in value:
        return _list(value["value"])
    if value == {}:
        return []
    return value if isinstance(value, list) else [value]


def _element(data: dict) -> Element:
    return Element(
        kind=data["kind"],
        name=data.get("name"),
        value=data.get("value"),
        has_argument=bool(data.get("has_argument")),
        text=data.get("text") or "",
        span=Span.from_dict(data["span"]),
        variables=tuple(v.lower() for v in _list(data.get("variables"))),
    )


def _document(data: dict, text: str, blanked: list[BlankedUsing]) -> ParsedDocument:
    return ParsedDocument(
        id=data["id"],
        text=text,
        parse_errors=[
            {"message": e["message"], "error_id": e.get("error_id"),
             "line": e["span"]["line"], "column": e["span"]["column"]}
            for e in _list(data.get("parse_errors"))
        ],
        commands=[
            Command(
                name=c.get("name"),
                name_source=c.get("name_source"),
                name_text=c.get("name_text") or "",
                operator=c.get("operator") or "Unknown",
                text=c.get("text") or "",
                span=Span.from_dict(c["span"]),
                elements=tuple(_element(e) for e in _list(c.get("elements"))),
                pipeline=Span.from_dict(c["pipeline"]) if c.get("pipeline") else None,
                pipeline_index=int(c.get("pipeline_index") or 0),
                name_choices=tuple(str(v) for v in _list(c.get("name_choices"))),
            )
            for c in _list(data.get("commands"))
        ],
        invocations=[
            Invocation(
                member=i.get("member"),
                static=bool(i.get("static")),
                type_name=i.get("type_name"),
                target_text=i.get("target_text") or "",
                arguments=tuple(_list(i.get("arguments"))),
                arg_count=int(i.get("arg_count") or 0),
                variables=tuple(v.lower() for v in _list(i.get("variables"))),
                text=i.get("text") or "",
                span=Span.from_dict(i["span"]),
            )
            for i in _list(data.get("invocations"))
        ],
        strings=[
            StringValue(value=s.get("value") or "", span=Span.from_dict(s["span"]),
                        folded=bool(s.get("folded")))
            for s in _list(data.get("strings"))
        ],
        assignments=[
            Assignment(variable=a["variable"].lower(), value_span=Span.from_dict(a["value_span"]))
            for a in _list(data.get("assignments"))
        ],
        functions={f.lower() for f in _list(data.get("functions"))},
        blanked_usings=blanked,
    )


def utf16_len(text: str) -> int:
    return len(text.encode("utf-16-le")) // 2


def _span_for(text: str, start: int, end: int) -> Span:
    """A Span in the parser's terms (UTF-16 offsets and columns) for a Python slice."""
    def position(index: int) -> tuple[int, int]:
        line = text.count("\n", 0, index) + 1
        line_start = text.rfind("\n", 0, index) + 1
        return line, utf16_len(text[line_start:index]) + 1

    line, column = position(start)
    end_line, end_column = position(end)
    return Span(utf16_len(text[:start]), utf16_len(text[:end]), line, column, end_line, end_column)


def _skip_trivia(text: str, pos: int) -> int:
    """Skip whitespace, line continuations and comments that may precede a using statement."""
    while pos < len(text):
        if text[pos].isspace():
            pos += 1
        elif text.startswith("`\r\n", pos):
            pos += 3
        elif text.startswith("`\n", pos):
            pos += 2
        elif text.startswith("<#", pos):
            close = text.find("#>", pos + 2)
            pos = len(text) if close < 0 else close + 2
        elif text[pos] == "#":
            newline = text.find("\n", pos)
            pos = len(text) if newline < 0 else newline
        else:
            break
    return pos


def _statement_end(text: str, pos: int) -> int:
    """End of a using statement: an unquoted newline (without a backtick before it) or ';'."""
    quote = None
    while pos < len(text):
        ch = text[pos]
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "`" and pos + 1 < len(text):
            pos += 2
            continue
        elif ch in ";\n":
            return pos
        pos += 1
    return pos


def blank_using_statements(text: str) -> tuple[str, list[BlankedUsing]]:
    """Replace `using module` and `using assembly` statements with spaces.

    Using statements may only appear at the start of a script, after comments and other
    using statements, so only that region is examined. Every character is replaced by
    the same number of UTF-16 code units, so all offsets, lines and columns stay valid.
    """
    blanked: list[BlankedUsing] = []
    chars = list(text)
    pos = 0
    while True:
        pos = _skip_trivia(text, pos)
        if text[pos:pos + 5].lower() != "using":
            break
        after = _skip_trivia(text, pos + 5)
        if after == pos + 5:
            break  # "using" must be followed by whitespace
        word_end = after
        while word_end < len(text) and text[word_end].isalpha():
            word_end += 1
        kind = text[after:word_end].lower()
        if kind not in ("module", "assembly", "namespace"):
            break
        end = _statement_end(text, word_end)
        if kind in ("module", "assembly"):
            blanked.append(BlankedUsing(kind, text[pos:end], _span_for(text, pos, end)))
            for i in range(pos, end):
                if chars[i] not in "\r\n":
                    chars[i] = "  " if ord(chars[i]) > 0xFFFF else " "
        pos = end + 1 if end < len(text) else end
    return "".join(chars), blanked


def find_powershell() -> str:
    """Path to PowerShell 7 (pwsh), or Windows PowerShell 5.1 when pwsh is not installed.

    BOMBSQUAD_POWERSHELL overrides the search.
    """
    override = os.environ.get("BOMBSQUAD_POWERSHELL")
    for candidate in [override] if override else ["pwsh", "powershell"]:
        found = shutil.which(candidate)
        if found:
            return found
    raise ParserUnavailable(
        "PowerShell is needed to parse PowerShell: install PowerShell 7 (pwsh), "
        "or set BOMBSQUAD_POWERSHELL to a PowerShell executable."
    )


def parse_documents(documents: list[tuple[str, str]], *, timeout: float = 120.0
                    ) -> tuple[dict, list[ParsedDocument]]:
    """Parse (id, text) pairs in one PowerShell process.

    Returns the parser's edition and version and one ParsedDocument per input.
    """
    blanked_texts: dict[str, tuple[str, list[BlankedUsing]]] = {
        doc_id: blank_using_statements(text) for doc_id, text in documents
    }
    request = {"documents": [{"id": doc_id, "text": blanked_texts[doc_id][0]}
                             for doc_id, _ in documents]}
    payload = base64.b64encode(json.dumps(request).encode("utf-8")).decode("ascii")

    executable = find_powershell()
    script = resources.files("bombsquad.powershell").joinpath("dump_ast.ps1")
    with resources.as_file(script) as script_path, tempfile.TemporaryDirectory() as workdir:
        command = [executable, "-NoProfile", "-NonInteractive", "-NoLogo"]
        if os.name == "nt":
            command += ["-ExecutionPolicy", "Bypass"]  # applies to dump_ast.ps1 only
        command += ["-File", str(script_path)]
        try:
            completed = subprocess.run(
                command, input=payload, capture_output=True, text=True, encoding="ascii",
                errors="replace", timeout=timeout, cwd=workdir, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ParserFailed(f"the PowerShell parser timed out after {timeout:.0f}s") from exc
    if completed.returncode != 0:
        raise ParserFailed(f"the PowerShell parser failed: {completed.stderr.strip()[-2000:]}")
    try:
        response = json.loads(base64.b64decode(completed.stdout.strip()).decode("utf-8"))
    except ValueError as exc:
        raise ParserFailed("the PowerShell parser returned unreadable output") from exc

    originals = dict(documents)
    parsed = [
        _document(d, originals[d["id"]], blanked_texts[d["id"]][1])
        for d in _list(response.get("documents"))
    ]
    return response.get("parser") or {}, parsed
