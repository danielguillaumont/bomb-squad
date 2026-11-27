"""What a new version gains: entry points, findings and files that are new or changed since
the previous version, and the registry's publish signals for both.

Both versions are scanned the same way as `bombsquad scan`. Findings are matched by rule,
file and evidence rather than line, so code that only moved is not reported again.
"""

from __future__ import annotations

import os
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from bombsquad import __version__
from bombsquad.archive import unpack
from bombsquad.discovery import LANGUAGE_BY_SUFFIX
from bombsquad.model import EntryPoint, Finding, Level, ScanReport, Signal
from bombsquad.registry import Fetch, Release, download, http_get, npm_releases, pypi_releases
from bombsquad.scan import scan
from bombsquad.source import SourceCheck, compare_to_source
from bombsquad.sources import MAX_FILE_BYTES, SKIPPED_DIRS, display_path

LONG_LINE = 1000  # characters; minified bundles and packed payloads run far longer
RECENT_DAYS = 7  # the same cooldown this project applies to its own dependencies
ARCHIVE_SUFFIXES = (".tgz", ".tar.gz", ".tar", ".tar.bz2", ".whl", ".zip")

DIFF_LIMITATIONS = (
    "Static analysis only: neither version was installed, built or run.",
    "Changes are what the new version could do that the old one could not, not proof that it "
    "would. No new findings does not mean safe.",
    "Code fetched or decoded only at run time, and payloads gated on time or environment, "
    "are not seen.",
    "Registry times are publish times, not when any change was made.",
)


@dataclass
class Side:
    label: str
    report: ScanReport
    files: dict[str, tuple[int, int]]  # relative path -> (bytes, longest line)
    release: Release | None = None
    notes: list[str] = field(default_factory=list)


@dataclass
class DiffReport:
    subject: str
    old: Side
    new: Side
    signals: list[Signal]
    added_entries: list[EntryPoint]
    removed_entries: list[EntryPoint]
    changed_entries: list[tuple[EntryPoint, EntryPoint]]
    added_findings: list[Finding]
    removed_findings: list[Finding]
    added_files: list[str]
    removed_files: list[str]
    grew: list[tuple[str, str]]  # (path, what changed)
    source: SourceCheck | None = None

    def highest_level(self) -> Level | None:
        levels = [f.level for f in self.added_findings] + [s.level for s in self.signals]
        return max(levels, key=lambda level: level.rank) if levels else None

    def to_dict(self) -> dict:
        def side(s: Side) -> dict:
            r = s.release
            return {
                "label": s.label,
                "version": r.version if r else None,
                "published": r.published.isoformat() if r and r.published else None,
                "publisher": r.publisher if r else None,
                "maintainers": r.maintainers if r else None,
                "provenance": r.provenance if r else None,
                "artifacts": [{"kind": a.kind, "filename": a.filename, "algorithm": a.algorithm,
                               "digest": a.digest, "provenance": a.provenance}
                              for a in r.artifacts] if r else [],
                "entry_points": len(s.report.entry_points),
                "findings": len(s.report.findings),
                "files": len(s.files),
                "notes": [*(r.notes if r else []), *s.notes],
            }
        return {
            "schema_version": 1,
            "kind": "diff",
            "tool": {"name": "bombsquad", "version": __version__},
            "subject": self.subject,
            "limitations": list(DIFF_LIMITATIONS),
            "old": side(self.old),
            "new": side(self.new),
            "signals": [s.to_dict() for s in self.signals],
            "entry_points": {
                "added": [e.to_dict() for e in self.added_entries],
                "removed": [e.to_dict() for e in self.removed_entries],
                "changed": [{"old": a.to_dict(), "new": b.to_dict()}
                            for a, b in self.changed_entries],
            },
            "findings": {"added": [f.to_dict() for f in self.added_findings],
                         "removed": [f.to_dict() for f in self.removed_findings]},
            "files": {"added": self.added_files, "removed": self.removed_files,
                      "grew": [{"path": p, "detail": d} for p, d in self.grew]},
            "source": self.source.to_dict() if self.source else None,
        }


# Scanning one side -------------------------------------------------------------------------

def _relative(report: ScanReport, root: Path) -> None:
    """Show paths relative to the package root, so both versions line up."""
    prefix = display_path(root).rstrip("/") + "/"

    def rel(path: str) -> str:
        return path[len(prefix):] if path.startswith(prefix) else path

    for f in report.findings:
        f.path = rel(f.path)
        f.via = [step.replace(prefix, "") for step in f.via]
    for e in report.entry_points:
        e.path = rel(e.path)
        e.targets = [rel(t) for t in e.targets]
    for r in report.files:
        r.path = rel(r.path)


def _inventory(root: Path) -> dict[str, tuple[int, int]]:
    files: dict[str, tuple[int, int]] = {}
    for folder, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIPPED_DIRS - {"node_modules"})
        for name in names:
            path = Path(folder, name)
            if path.is_symlink():
                continue
            size = path.stat().st_size
            longest = 0
            if size <= MAX_FILE_BYTES:
                data = path.read_bytes()
                if b"\x00" not in data[:8192]:
                    longest = max((len(line) for line in data.split(b"\n")), default=0)
            files[path.relative_to(root).as_posix()] = (size, longest)
    return files


def scan_side(label: str, root: Path, release: Release | None = None,
              notes: list[str] | None = None, package: bool = False) -> Side:
    """`package`: a published package, where only what installing it runs keeps its
    level (see `scan`)."""
    report = scan([root], package=package)
    _relative(report, root)
    return Side(label, report, _inventory(root), release, list(notes or []))


# Comparing -----------------------------------------------------------------------------------

def _finding_key(f: Finding) -> tuple[str, str, str]:
    return f.rule.id, f.path, " ".join(f.evidence.split())


def _entry_key(e: EntryPoint) -> tuple[str, str, str]:
    return e.surface, e.kind, e.path


def compare(subject: str, old: Side, new: Side, now: datetime | None = None) -> DiffReport:
    old_entries = {_entry_key(e): e for e in old.report.entry_points}
    new_entries = {_entry_key(e): e for e in new.report.entry_points}
    added_entries = [e for k, e in new_entries.items() if k not in old_entries]
    removed_entries = [e for k, e in old_entries.items() if k not in new_entries]
    changed_entries = [(old_entries[k], e) for k, e in new_entries.items()
                       if k in old_entries and " ".join(old_entries[k].runs.split()) != " ".join(
                           e.runs.split())]

    remaining = Counter(_finding_key(f) for f in old.report.findings)
    added_findings = []
    for f in new.report.findings:
        key = _finding_key(f)
        if remaining[key]:
            remaining[key] -= 1
        else:
            added_findings.append(f)
    still = Counter(_finding_key(f) for f in new.report.findings)
    removed_findings = []
    for f in old.report.findings:
        key = _finding_key(f)
        if still[key]:
            still[key] -= 1
        else:
            removed_findings.append(f)
    added_findings.sort(key=lambda f: (-f.level.rank, f.path, f.region.line, f.rule.id))

    added_files = sorted(set(new.files) - set(old.files))
    removed_files = sorted(set(old.files) - set(new.files))
    grew = []
    for path, (size, longest) in sorted(new.files.items()):
        before = old.files.get(path)
        if longest < LONG_LINE or Path(path).suffix.lower() not in LANGUAGE_BY_SUFFIX:
            continue
        if before is None:
            grew.append((path, f"new file with a {longest:,}-character line ({size:,} bytes)"))
        elif before[1] < LONG_LINE:
            grew.append((path, f"now has a {longest:,}-character line; it grew from "
                               f"{before[0]:,} to {size:,} bytes"))
    return DiffReport(subject, old, new, signals(old.release, new.release, now),
                      added_entries, removed_entries, changed_entries, added_findings,
                      removed_findings, added_files, removed_files, grew)


def signals(old: Release | None, new: Release | None, now: datetime | None = None
            ) -> list[Signal]:
    """Publish signals for `new`, compared with `old` when there is one."""
    if new is None:
        return []
    out = _changes(old, new) if old is not None else []
    if new.published is not None:
        out.append(_age(new, now))
    return out


def _changes(old: Release, new: Release) -> list[Signal]:
    out: list[Signal] = []
    if old.publisher and new.publisher and old.publisher != new.publisher:
        out.append(Signal("publisher-changed", Level.REVIEW,
                          f"{old.version} was published by {old.publisher}, {new.version} by "
                          f"{new.publisher}"))
    if old.maintainers is not None and new.maintainers is not None:
        joined = sorted(set(new.maintainers) - set(old.maintainers))
        left = sorted(set(old.maintainers) - set(new.maintainers))
        if joined or left:
            parts = ([f"added {', '.join(joined)}"] if joined else []) + (
                [f"removed {', '.join(left)}"] if left else [])
            out.append(Signal("maintainers-changed", Level.REVIEW, "; ".join(parts)))
    if old.provenance is True and new.provenance is False:
        out.append(Signal("provenance-missing", Level.REVIEW,
                          f"{old.version} has provenance attestations and {new.version} does "
                          "not. Provenance shows where a package was built, not that its code "
                          "is benign; losing it means the new version was built some other "
                          "way."))
    if old.repository and new.repository and old.repository != new.repository:
        out.append(Signal("repository-changed", Level.REVIEW,
                          f"the declared repository changed from {old.repository} to "
                          f"{new.repository}"))
    return out


def _age(new: Release, now: datetime | None) -> Signal:
    assert new.published is not None
    moment = now or datetime.now(UTC)
    published = new.published if new.published.tzinfo else new.published.replace(tzinfo=UTC)
    age = moment - published
    days = age.total_seconds() / 86400
    when = published.strftime("%Y-%m-%d %H:%M UTC")
    if days < RECENT_DAYS:
        hours = max(0, int(age.total_seconds() // 3600))
        return Signal("recent-release", Level.REVIEW,
                      f"{new.version} was published {when}, {hours} hours before this scan, "
                      f"inside the {RECENT_DAYS}-day cooldown this project uses for its own "
                      "dependencies")
    return Signal("release-age", Level.INFO,
                  f"{new.version} was published {when}, {int(days)} days before this scan")


# Registries and local paths -----------------------------------------------------------------

def parse_spec(spec: str) -> tuple[str, str, str, str]:
    """`npm:<name>@<old>..<new>` or `pypi:<name>@<old>..<new>`."""
    ecosystem, sep, rest = spec.partition(":")
    name, at, versions = rest.rpartition("@")
    old, dots, new = versions.partition("..")
    if not sep or ecosystem not in ("npm", "pypi") or not at or not name or not dots or not (
            old and new):
        raise ValueError(f"expected npm:<name>@<old>..<new> or pypi:<name>@<old>..<new>, got "
                         f"{spec!r}")
    return ecosystem, name, old, new


def diff_registry(spec: str, fetch: Fetch = http_get, now: datetime | None = None,
                  source: bool = False, record: Path | None = None) -> DiffReport:
    """Compare two published versions. With `source`, also compare the new version with
    its GitHub repository at the release tag; with `record`, also check that tag against
    earlier observations kept in that file, and add this one."""
    ecosystem, name, old_version, new_version = parse_spec(spec)
    return diff_release(ecosystem, name, old_version, new_version, fetch, now, source, record)


def unpack_release(release: Release, folder: Path, fetch: Fetch = http_get
                   ) -> tuple[Path, list[str]]:
    """Download each of the release's artifacts, check it against the registry's hash, and
    unpack it into `folder/<kind>` (npm-tarball, sdist, wheel). Returns the folder to scan:
    the one artifact's folder, or `folder` when there are several. Nothing is run."""
    notes: list[str] = []
    for artifact in release.artifacts:
        data = download(artifact, fetch)  # checked against the registry's hash
        kind = artifact.kind.replace(" ", "-")
        raw = folder / f".{kind}"
        raw.mkdir()
        unpacked, skipped = unpack(data, artifact.filename, raw)
        # sdists wrap their files in name-version/; a fixed folder name lets two versions'
        # paths line up.
        unpacked.rename(folder / kind)
        if raw.exists():
            raw.rmdir()
        notes += [f"{artifact.filename}: {n}" for n in skipped]
    root = folder / release.artifacts[0].kind.replace(" ", "-") if len(
        release.artifacts) == 1 else folder
    return root, notes


def diff_release(ecosystem: str, name: str, old_version: str | None, new_version: str,
                 fetch: Fetch = http_get, now: datetime | None = None, source: bool = False,
                 record: Path | None = None) -> DiffReport:
    """`diff_registry` for parsed versions. With no old version, everything the new one
    has is reported as new."""
    lookup = npm_releases if ecosystem == "npm" else pypi_releases
    if old_version is None:
        [new_release] = lookup(name, [new_version], fetch)
        old_release = None
    else:
        old_release, new_release = lookup(name, [old_version, new_version], fetch)
    with tempfile.TemporaryDirectory(prefix="bombsquad-",
                                     ignore_cleanup_errors=True) as work:
        sides = []
        if old_release is None:
            sides.append(Side("(not a dependency before)", ScanReport(__version__, [], []), {}))
        for label, release in (("old", old_release), ("new", new_release)):
            if release is None:
                continue
            folder = Path(work, label)
            folder.mkdir()
            root, notes = unpack_release(release, folder, fetch)
            sides.append(scan_side(f"{name}@{release.version}" if ecosystem == "npm" else
                                   f"{name} {release.version}", root, release, notes,
                                   package=True))
        report = compare(f"{ecosystem}:{name}", sides[0], sides[1], now)
        if source or record is not None:
            # Compare the artifact laid out like the repository: the npm tarball, or the
            # sdist. A wheel is laid out for installation and would differ everywhere.
            tree: Path | None = root
            if ecosystem == "pypi" and root.name != "sdist":
                tree = root / "sdist" if (root / "sdist").is_dir() else None
            prefix = "" if tree is None or tree == root else f"{tree.name}/"
            entries = sides[1].report.entry_points
            reached = {p.removeprefix(prefix) for p in
                       {e.path for e in entries} | {t for e in entries for t in e.targets}
                       if p.startswith(prefix)}
            report.source = compare_to_source(new_release, tree, reached, fetch, record, now,
                                              prefix)
            report.signals += report.source.signals
        return report


def diff_paths(old: Path, new: Path) -> DiffReport:
    """Compare two local folders or archives."""
    with tempfile.TemporaryDirectory(prefix="bombsquad-",
                                     ignore_cleanup_errors=True) as work:
        sides = []
        for label, path in (("old", old), ("new", new)):
            notes: list[str] = []
            package = path.is_file()
            if path.is_file() and path.name.lower().endswith(ARCHIVE_SUFFIXES):
                target = Path(work, label)
                target.mkdir()
                root, notes = unpack(path.read_bytes(), path.name, target)
            elif path.is_dir():
                root = path
            else:
                raise FileNotFoundError(f"not a folder or package archive: {path}")
            sides.append(scan_side(path.name, root, None, notes, package=package))
        return compare("", sides[0], sides[1])
