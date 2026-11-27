"""Scan files or pasted text and build a report."""

from __future__ import annotations

from pathlib import Path

from bombsquad import __version__
from bombsquad.model import FileResult, ScanReport
from bombsquad.powershell.analyze import analyze_sources
from bombsquad.sources import (
    POWERSHELL_SUFFIXES,
    InputError,
    collect_files,
    display_path,
    read_source,
)

STDIN_PATH = "<stdin>"


def scan(paths: list[Path] | None = None, stdin_text: str | None = None) -> ScanReport:
    """Scan PowerShell files (directories are searched) and optionally pasted text."""
    results: dict[str, FileResult] = {}
    sources: list[tuple[str, str]] = []
    for path in collect_files(paths or []):
        shown = display_path(path)
        if path.suffix.lower() not in POWERSHELL_SUFFIXES:
            results[shown] = FileResult(shown, "unknown", "not_analysed",
                                        notes=["Not a PowerShell file (.ps1, .psm1, .psd1)."])
            continue
        try:
            text, encoding = read_source(path)
        except (InputError, OSError) as exc:
            results[shown] = FileResult(shown, "powershell", "unreadable", notes=[str(exc)])
            continue
        results[shown] = FileResult(shown, "powershell", "analysed", encoding=encoding)
        sources.append((shown, text))
    if stdin_text is not None:
        results[STDIN_PATH] = FileResult(STDIN_PATH, "powershell", "analysed", encoding="utf-8")
        sources.append((STDIN_PATH, stdin_text))

    parser_info: dict | None = None
    findings = []
    if sources:
        parser_info, findings = analyze_sources(sources, results)
        if parser_info.get("edition") == "Desktop":
            for r in results.values():
                if r.parse_errors:
                    r.notes.append(
                        "Parsed with Windows PowerShell 5.1, which rejects PowerShell 7 syntax "
                        "such as && and ternaries. Install pwsh to parse it as PowerShell 7.")
    return ScanReport(__version__, list(results.values()), findings,
                      {"name": "PowerShell", **parser_info} if parser_info else None)
