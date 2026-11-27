"""Human-readable output."""

from __future__ import annotations

from collections import Counter

from bombsquad.model import REPORT_LIMITATIONS, ScanReport


def _first_line(text: str, limit: int = 160) -> str:
    lines = text.strip().splitlines() or [""]
    line = lines[0]
    if len(line) > limit:
        line = line[:limit] + "…"
    return line + (" …" if len(lines) > 1 else "")


def render(report: ScanReport) -> str:
    out: list[str] = []
    if report.entry_points:
        count = len(report.entry_points)
        out.append(f"Runs without being asked ({count} entry point{'s' if count != 1 else ''})")
        for e in report.entry_points:
            out.append(f"  {e.path}:{e.region.line}  {e.kind}")
            out.append(f"      runs on: {e.trigger}")
            out.append(f"      runs: {_first_line(e.runs)}")
            for target in e.targets:
                if target != e.path:
                    out.append(f"      reaches: {target}")
        out.append("")
    by_path: dict[str, list] = {}
    for f in report.findings:
        by_path.setdefault(f.path, []).append(f)
    for result in report.files:
        findings = by_path.get(result.path, [])
        if not findings and not result.notes and not result.parse_errors:
            continue
        out.append(result.path)
        for f in findings:
            out.append(f"  {f.region.line}:{f.region.column}  {f.level.value:<6}  {f.rule.id}  "
                       f"{f.rule.title}")
            out.append(f"      {_first_line(f.evidence)}")
            for step in f.via:
                out.append(f"      via: {_first_line(step)}")
            for limit in f.limitations:
                out.append(f"      note: {limit}")
        for error in result.parse_errors:
            out.append(f"  {error['line']}:{error['column']}  parse error: {error['message']}")
        for note in result.notes:
            out.append(f"  note: {note}")
        out.append("")

    levels = Counter(f.level.value for f in report.findings)
    analysed = sum(1 for r in report.files if r.status == "analysed")
    summary = f"{len(report.findings)} finding{'s' if len(report.findings) != 1 else ''}"
    if report.findings:
        summary += " (" + ", ".join(f"{levels[k]} {k}" for k in ("high", "review", "info")
                                    if levels[k]) + ")"
    summary += f" in {analysed} of {len(report.files)} file{'s' if len(report.files) != 1 else ''}"
    if report.files_read:
        summary += f" ({report.files_read} read)"
    if report.parser:
        summary += (f", parsed with PowerShell {report.parser.get('version')} "
                    f"({report.parser.get('edition')})")
    out.append(summary + ".")
    out.extend(REPORT_LIMITATIONS)
    return "\n".join(out) + "\n"
