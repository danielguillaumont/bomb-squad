"""Shared helpers.

Some samples are assembled from fragments at run time (see `fragments`) so that no test
file on disk spells out a download cradle, an encoded command or AMSI internals.
Antivirus products quarantine files that do, which would break checkouts and test runs.
Assertions compare rule IDs only, so failing tests do not print the samples either.
"""

from __future__ import annotations

import base64

import pytest

from bombsquad.model import FileResult, Finding
from bombsquad.powershell.analyze import analyze_sources


def fragments(*parts: str) -> str:
    return "".join(parts)


def encoded(command: str) -> str:
    """What `powershell -EncodedCommand` expects: base64 of UTF-16LE."""
    return base64.b64encode(command.encode("utf-16-le")).decode("ascii")


def analyse(cases: dict[str, str]) -> tuple[dict, dict[str, list[Finding]],
                                            dict[str, FileResult]]:
    results = {name: FileResult(name, "powershell", "analysed") for name in cases}
    parser, findings = analyze_sources(list(cases.items()), results)
    grouped: dict[str, list[Finding]] = {name: [] for name in cases}
    for f in findings:
        grouped[f.path].append(f)
    return parser, grouped, results


@pytest.fixture
def rule_ids():
    def ids(findings: list[Finding]) -> set[str]:
        return {f.rule.id for f in findings}
    return ids
