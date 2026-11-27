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


def render_diff(diff) -> str:
    """A `bombsquad diff` report: what the new version gains, then what it lost."""
    from bombsquad.diff import DIFF_LIMITATIONS

    out = [f"{diff.subject}: {diff.old.label} -> {diff.new.label}"
           if diff.subject else f"{diff.old.label} -> {diff.new.label}", ""]
    for side in (diff.old, diff.new):
        release = side.release
        if release is None:
            continue
        line = f"  {side.label}"
        if release.published:
            line += f"  published {release.published.strftime('%Y-%m-%d %H:%M UTC')}"
        if release.publisher:
            line += f" by {release.publisher}"
        provenance = {True: "yes", False: "no", None: "unknown"}[release.provenance]
        out.append(line + f"  provenance: {provenance}")
        for artifact in release.artifacts:
            out.append(f"      {artifact.filename}  {artifact.algorithm} {artifact.digest[:16]}… "
                       "matches the registry")
    if diff.old.release:
        out.append("")

    if diff.signals:
        out.append("Publish signals")
        for s in diff.signals:
            out.append(f"  {s.level.value:<6}  {s.id}: {s.detail}")
        out.append("")

    if diff.added_entries or diff.changed_entries:
        out.append("New or changed entry points")
        for e in diff.added_entries:
            out.append(f"  new      {e.path}:{e.region.line}  {e.kind}")
            out.append(f"      runs on: {e.trigger}")
            out.append(f"      runs: {_first_line(e.runs)}")
            for target in e.targets:
                if target != e.path:
                    out.append(f"      reaches: {target}")
        for old, new in diff.changed_entries:
            out.append(f"  changed  {new.path}:{new.region.line}  {new.kind}")
            out.append(f"      was: {_first_line(old.runs)}")
            out.append(f"      now: {_first_line(new.runs)}")
        out.append("")

    if diff.added_findings:
        out.append(f"New findings ({len(diff.added_findings)})")
        for f in diff.added_findings:
            out.append(f"  {f.path}:{f.region.line}:{f.region.column}  {f.level.value:<6}  "
                       f"{f.rule.id}  {f.rule.title}")
            out.append(f"      {_first_line(f.evidence)}")
            for step in f.via:
                out.append(f"      via: {_first_line(step)}")
        out.append("")

    if diff.grew:
        out.append("Files with a new minified or packed line")
        for path, detail in diff.grew:
            out.append(f"  {path}  {detail}")
        out.append("")

    if diff.added_files or diff.removed_files:
        out.append(f"Files: {len(diff.added_files)} added, {len(diff.removed_files)} removed")
        for path in diff.added_files[:20]:
            out.append(f"  + {path}")
        if len(diff.added_files) > 20:
            out.append(f"  … and {len(diff.added_files) - 20} more")
        out.append("")

    gone = len(diff.removed_findings) + len(diff.removed_entries)
    if gone:
        out.append(f"No longer present: {len(diff.removed_entries)} entry points, "
                   f"{len(diff.removed_findings)} findings.")
        out.append("")
    for side in (diff.old, diff.new):
        for note in [*(side.release.notes if side.release else []), *side.notes]:
            out.append(f"note ({side.label}): {note}")
    summary = (f"{len(diff.added_entries)} new and {len(diff.changed_entries)} changed entry "
               f"points, {len(diff.added_findings)} new findings, {len(diff.signals)} publish "
               "signals.")
    out.append(summary)
    out.extend(DIFF_LIMITATIONS)
    return "\n".join(out) + "\n"
