"""Findings, rules and reports shared by every analyzer and output format."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Level(StrEnum):
    """How urgently a finding needs a person to look at it before the code runs."""

    HIGH = "high"
    REVIEW = "review"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"info": 0, "review": 1, "high": 2}[self.value]


@dataclass(frozen=True)
class Rule:
    id: str
    family: str
    title: str
    level: Level
    effect: str
    next_step: str
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class Region:
    """1-based lines and columns. Columns count UTF-16 code units, as SARIF expects."""

    line: int
    column: int
    end_line: int
    end_column: int


@dataclass
class Finding:
    rule: Rule
    path: str
    region: Region
    evidence: str
    level: Level
    via: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule.id,
            "title": self.rule.title,
            "family": self.rule.family,
            "level": self.level.value,
            "path": self.path,
            "line": self.region.line,
            "column": self.region.column,
            "end_line": self.region.end_line,
            "end_column": self.region.end_column,
            "evidence": self.evidence,
            "effect": self.rule.effect,
            "via": list(self.via),
            "limitations": [*self.rule.limitations, *self.limitations],
            "next_step": self.rule.next_step,
        }


@dataclass
class FileResult:
    path: str
    language: str
    status: str  # analysed | not_analysed | unreadable
    encoding: str | None = None
    parse_errors: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "language": self.language,
            "status": self.status,
            "encoding": self.encoding,
            "parse_errors": self.parse_errors,
            "notes": self.notes,
        }


@dataclass
class Signal:
    """A fact about how a version was published, or where it came from, as opposed to
    what its code does."""

    id: str
    level: Level
    detail: str

    def to_dict(self) -> dict:
        return {"signal": self.id, "level": self.level.value, "detail": self.detail}


@dataclass
class EntryPoint:
    """Something that runs without anyone choosing to run it."""

    surface: str  # npm | python | ...
    kind: str  # e.g. "postinstall script", ".pth import line"
    trigger: str  # when it runs
    path: str
    region: Region
    runs: str  # the command or code, as written
    targets: list[str] = field(default_factory=list)  # files analysed because of it

    def describe(self) -> str:
        return f"runs on {self.trigger}: {self.kind} in {self.path}:{self.region.line}"

    def to_dict(self) -> dict:
        return {
            "surface": self.surface,
            "kind": self.kind,
            "trigger": self.trigger,
            "path": self.path,
            "line": self.region.line,
            "column": self.region.column,
            "runs": self.runs,
            "targets": list(self.targets),
        }


REPORT_LIMITATIONS = (
    "Static analysis only: nothing in the input was run, imported or installed.",
    "Findings are operations the code could perform, not proof that it would.",
    "No findings does not mean safe.",
    "Values computed at run time are not resolved, except string literals folded as noted "
    "and decoded content that is present in the file.",
)


@dataclass
class ScanReport:
    tool_version: str
    files: list[FileResult]
    findings: list[Finding]
    parser: dict | None = None
    entry_points: list[EntryPoint] = field(default_factory=list)
    files_read: int = 0

    def highest_level(self) -> Level | None:
        if not self.findings:
            return None
        return max((f.level for f in self.findings), key=lambda level: level.rank)

    def to_dict(self) -> dict:
        return {
            "schema_version": 1,
            "tool": {"name": "bombsquad", "version": self.tool_version},
            "parser": self.parser,
            "limitations": list(REPORT_LIMITATIONS),
            "files_read": self.files_read,
            "entry_points": [e.to_dict() for e in self.entry_points],
            "files": [f.to_dict() for f in self.files],
            "findings": [f.to_dict() for f in self.findings],
        }
