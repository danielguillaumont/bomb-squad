"""`bombsquad gate`: what a pull request newly runs.

The base and head of the pull request are two folders. The repository is compared as
`bombsquad diff` compares two versions of a package: new and changed entry points and new
findings, wherever they are (workflows, editor and hook files, agent files, package
scripts). Every dependency version the head's lockfiles pin and the base's did not is then
reviewed from the registry, against the version it replaces.

Neither folder, nor any dependency, is installed, built or run.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from bombsquad import __version__
from bombsquad.actionrefs import ECOSYSTEM, action_changes, read_refs, review_action, short
from bombsquad.archive import ArchiveError
from bombsquad.diff import DiffReport, compare, diff_release, scan_side
from bombsquad.lockfiles import Change, changes, read_tree
from bombsquad.model import Finding, Level, ScanReport
from bombsquad.powershell.parser import ParserFailed, ParserUnavailable
from bombsquad.registry import Fetch, FetchError, http_get

MAX_PACKAGES = 25
COMMENT_MARKER = "<!-- bombsquad-gate -->"
COMMENT_LIMIT = 60_000  # GitHub allows 65,536 characters in a comment
ITEMS = 30  # per section, in the comment
GATE_LIMITATIONS = (
    "Static analysis only: nothing in this pull request or its dependencies was installed, "
    "built or run.",
    "Findings and signals are what the new code could do, or how it was published, not proof "
    "that it would do harm. No new findings does not mean safe.",
    "Code fetched or decoded only at run time, and payloads gated on time or environment, "
    "are not seen. Lockfile formats other than npm, uv, Poetry and pinned requirements are "
    "not read. Actions that an updated action itself uses are not followed.",
    "Registry times are publish times, not when any change was made.",
)


@dataclass
class DependencyReview:
    change: Change
    report: DiffReport | None = None
    error: str | None = None


@dataclass
class GateReport:
    repository: DiffReport
    dependencies: list[DependencyReview] = field(default_factory=list)
    not_reviewed: list[Change] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def highest_level(self) -> Level | None:
        levels = [r.highest_level() for r in [self.repository] + [
            d.report for d in self.dependencies if d.report]]
        present = [level for level in levels if level is not None]
        return max(present, key=lambda level: level.rank) if present else None

    def new_findings(self) -> list[Finding]:
        return self.repository.added_findings

    def to_dict(self) -> dict:
        def change(c: Change) -> dict:
            return {"ecosystem": c.ecosystem, "name": c.name, "old": c.old, "new": c.new,
                    "lockfiles": list(c.lockfiles), "direct": c.direct}

        highest = self.highest_level()
        return {
            "schema_version": 1,
            "kind": "gate",
            "tool": {"name": "bombsquad", "version": __version__},
            "limitations": list(GATE_LIMITATIONS),
            "highest_level": highest.value if highest else None,
            "repository": self.repository.to_dict(),
            "dependencies": [{**change(d.change), "error": d.error,
                              "diff": d.report.to_dict() if d.report else None}
                             for d in self.dependencies],
            "not_reviewed": [change(c) for c in self.not_reviewed],
            "notes": self.notes,
        }


def gate(base: Path, head: Path, fetch: Fetch = http_get, now: datetime | None = None,
         max_packages: int = MAX_PACKAGES, source: bool = False) -> GateReport:
    base, head = base.resolve(), head.resolve()
    for path in (base, head):
        if not path.is_dir():
            raise FileNotFoundError(f"not a folder: {path}")
    if base == head or base.is_relative_to(head) or head.is_relative_to(base):
        raise ValueError("the base and head folders must be separate, neither inside the other")
    old, new = scan_side("base", base), scan_side("head", head)
    for side in (old, new):  # a git worktree has a .git file where a clone has a folder
        side.files.pop(".git", None)
    report = GateReport(compare("", old, new, now))

    base_pins, head_pins = read_tree(base), read_tree(head)
    report.notes += sorted(set(head_pins.notes) - set(base_pins.notes))
    packages = changes(base_pins, head_pins)
    base_refs, _ = read_refs(base)
    head_refs, ref_notes = read_refs(head)
    report.notes += ref_notes
    actions = action_changes(base_refs, head_refs)
    # Direct dependencies and actions first: they are what the change asked for.
    found = ([c for c in packages if c.direct] + actions
             + [c for c in packages if not c.direct])
    report.not_reviewed = found[max_packages:]
    for change in found[:max_packages]:
        review = DependencyReview(change)
        try:
            if change.ecosystem == ECOSYSTEM:
                review.report = review_action(change, fetch)
            else:
                review.report = diff_release(change.ecosystem, change.name, change.old,
                                             change.new, fetch, now, source=source)
        except (FetchError, ArchiveError, ValueError, OSError, ParserFailed,
                ParserUnavailable) as exc:
            review.error = str(exc)
        report.dependencies.append(review)
    return report


def gate_sarif_report(report: GateReport) -> ScanReport:
    """The repository's new findings, for code scanning. Dependency findings are in files
    the repository does not have, so they stay in the comment and the JSON report."""
    return ScanReport(__version__, [], report.new_findings(), entry_points=[])


# Markdown, for a pull request comment ---------------------------------------------------

_ESCAPED = set("\\`*_[]<>#|~!{}()")


def plain(text: str, limit: int = 300) -> str:
    """Text from the pull request or a registry, safe to put in a comment: Markdown and
    HTML are escaped, and @mentions cannot notify anyone."""
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[:limit] + "…"
    out = []
    for ch in text:
        if ch in _ESCAPED:
            out.append("\\" + ch)
        elif ch == "@":
            out.append("&#64;")
        elif ch == "&":
            out.append("&amp;")
        else:
            out.append(ch)
    return "".join(out)


def code(text: str, limit: int = 200) -> str:
    """Inline code that the text cannot break out of."""
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[:limit] + "…"
    longest = run = 0
    for ch in text:
        run = run + 1 if ch == "`" else 0
        longest = max(longest, run)
    fence = "`" * (longest + 1)
    pad = " " if text.startswith("`") or text.endswith("`") or not text.strip() else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def _diff_lines(diff: DiffReport, indent: str = "") -> list[str]:
    out = []
    for s in diff.signals:
        out.append(f"{indent}- **{s.level.value}** {code(s.id)}: {plain(s.detail)}")
    entries = [(e, None) for e in diff.added_entries] + [(n, o) for o, n in
                                                         diff.changed_entries]
    for e, before in entries[:ITEMS]:
        what = "changed entry point" if before else "new entry point"
        line = (f"{indent}- **{what}** {code(f'{e.path}:{e.region.line}')} {plain(e.kind)}, "
                f"runs on {plain(e.trigger)}: {code(e.runs)}")
        reached = [t for t in e.targets if t != e.path]
        if reached:
            line += " → " + ", ".join(code(t) for t in reached[:5])
        out.append(line)
    if len(entries) > ITEMS:
        out.append(f"{indent}- … and {len(entries) - ITEMS} more entry points")
    for f in diff.added_findings[:ITEMS]:
        out.append(f"{indent}- **{f.level.value}** {code(f.rule.id)} {plain(f.rule.title)}, "
                   f"{code(f'{f.path}:{f.region.line}')}: {code(f.evidence)}")
    if len(diff.added_findings) > ITEMS:
        out.append(f"{indent}- … and {len(diff.added_findings) - ITEMS} more findings")
    for path, detail in diff.grew[:10]:
        out.append(f"{indent}- **minified line** {code(path)}: {plain(detail)}")
    check = diff.source
    if check is not None and (check.only_in_artifact or check.differs):
        out.append(f"{indent}- against {code(check.repository or '')} at "
                   f"{code(check.tag or (check.compared or '')[:12])}: "
                   f"{len(check.only_in_artifact)} files only in the package, "
                   f"{len(check.differs)} differ")
    return out


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}{'' if n == 1 else 's'}"


def render_markdown(report: GateReport) -> str:
    repo = report.repository
    highest = report.highest_level()
    reviewed = [d for d in report.dependencies if d.report]
    failed = [d for d in report.dependencies if d.error]
    entries = len(repo.added_entries) + len(repo.changed_entries)
    out = [COMMENT_MARKER, "### Bomb Squad: what this pull request newly runs", ""]
    dependency_entries = sum(len(d.report.added_entries) + len(d.report.changed_entries)
                             for d in reviewed if d.report)
    if highest:
        summary = f"**Highest level: {highest.value}.** "
    elif entries or dependency_entries:
        summary = "**New entry points, with no findings or signals.** "
    else:
        summary = "**No new entry points, findings or signals.** "
    summary += (f"Repository: {_count(entries, 'new or changed entry point')}, "
                f"{_count(len(repo.added_findings), 'new finding')}. Dependencies and actions: "
                f"{_count(len(reviewed), 'update')} reviewed")
    if failed:
        summary += f", {len(failed)} could not be"
    if report.not_reviewed:
        summary += f", {len(report.not_reviewed)} over the limit not reviewed"
    out += [summary + ".", ""]

    lines = _diff_lines(repo)
    out.append("#### Repository")
    out += lines or ["No new or changed entry points and no new findings."]
    out.append("")

    if report.dependencies or report.not_reviewed:
        out.append("#### Dependency and action updates")
        for d in report.dependencies:
            c = d.change
            label = (f"{code(f'{c.ecosystem}:{c.name}')} {code(short(c.old))} → "
                     f"{code(short(c.new))}" if c.old else
                     f"{code(f'{c.ecosystem}:{c.name}')} {code(short(c.new))} (new)")
            where = ", ".join(code(path) for path in c.lockfiles[:3])
            if d.error:
                out.append(f"- {label} in {where}: could not be reviewed: {plain(d.error)}")
                continue
            assert d.report is not None
            level = d.report.highest_level()
            out.append(f"- {label}{' (direct)' if c.direct else ''} in {where}: "
                       f"{level.value if level else 'nothing new reported'}")
            out += _diff_lines(d.report, "  ")
        if report.not_reviewed:
            names = ", ".join(code(f"{c.ecosystem}:{c.name}@{c.new}")
                              for c in report.not_reviewed[:ITEMS])
            more = len(report.not_reviewed) - ITEMS
            out.append(f"- Not reviewed, over the limit: {names}"
                       + (f" and {more} more" if more > 0 else ""))
        out.append("")

    if report.notes:
        out.append("<details><summary>Notes</summary>")
        out.append("")
        out += [f"- {plain(note)}" for note in report.notes[:ITEMS]]
        out += ["", "</details>", ""]

    out.append("<sub>" + " ".join(plain(text, 1000) for text in GATE_LIMITATIONS) + "</sub>")
    text = "\n".join(out) + "\n"
    if len(text) > COMMENT_LIMIT:
        cut = text.rfind("\n", 0, COMMENT_LIMIT - 400)
        text = (text[:cut] + "\n\n… The report was cut to fit a comment; the full report is "
                "in the job summary and the JSON output.\n\n<sub>No findings does not mean "
                "safe.</sub>\n")
    return text


def render_text(report: GateReport) -> str:
    from bombsquad.text_report import render_diff

    parts = ["Repository: base -> head", render_diff(report.repository)]
    for d in report.dependencies:
        if d.error:
            parts.append(f"{d.change.spec}: could not be reviewed: {d.error}\n")
        elif d.report is not None:
            parts.append(render_diff(d.report))
    if report.not_reviewed:
        parts.append("Not reviewed, over the limit: " + ", ".join(
            f"{c.ecosystem}:{c.name}@{c.new}" for c in report.not_reviewed) + "\n")
    parts += [f"note: {n}\n" for n in report.notes]
    parts += [f"{text}\n" for text in GATE_LIMITATIONS]
    return "\n".join(parts)
