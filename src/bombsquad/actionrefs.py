"""The actions and reusable workflows a repository's workflows and actions use, and what a
changed reference newly brings.

`uses:` values are read from the YAML node graph and never resolved by running anything.
An action whose reference changed is fetched from GitHub's archive host at both
references, unpacked with the same rules as a package, and compared as `bombsquad diff`
compares two folders. Actions that the action itself uses are not followed.
"""

from __future__ import annotations

import os
import re
import tempfile
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

import yaml

from bombsquad import __version__
from bombsquad.archive import unpack
from bombsquad.diff import DiffReport, Side, compare, scan_side
from bombsquad.lockfiles import Change
from bombsquad.model import Level, ScanReport, Signal
from bombsquad.registry import MAX_ARTIFACT_BYTES, Fetch
from bombsquad.repo import yamltree as y
from bombsquad.source import CODELOAD
from bombsquad.sources import MAX_FILE_BYTES, SKIPPED_DIRS

ECOSYSTEM = "github-actions"
_USES = re.compile(r"^([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)((?:/[^@\s]+)?)@([^\s@]+)$")
_SHA = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True)
class ActionRef:
    path: str  # the workflow or action file, relative to the tree
    action: str  # owner/repo, or owner/repo/path
    ref: str


def _uses_values(root: yaml.Node) -> list[str]:
    out = []
    for _, _, job in y.pairs(y.get(root, "jobs")):
        out.append(y.text(y.get(job, "uses")))
        out += [y.text(y.get(step, "uses")) for step in y.items(y.get(job, "steps"))]
    out += [y.text(y.get(step, "uses")) for step in y.items(y.get(y.get(root, "runs"),
                                                                   "steps"))]
    return [v.strip() for v in out if v]


def read_refs(root: Path) -> tuple[list[ActionRef], list[str]]:
    """Every remote `uses:` reference in the tree's workflows and actions, and notes on
    files that could not be read."""
    refs: list[ActionRef] = []
    notes: list[str] = []
    for folder, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIPPED_DIRS)
        here = Path(folder)
        in_workflows = here.name == "workflows" and here.parent.name == ".github" and (
            here.parent.parent == root)
        for name in sorted(names):
            if not ((in_workflows and name.endswith((".yml", ".yaml")))
                    or name in ("action.yml", "action.yaml")):
                continue
            path = here / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink() or path.stat().st_size > MAX_FILE_BYTES:
                continue
            try:
                node = y.compose(path.read_text(encoding="utf-8-sig"))
            except (OSError, UnicodeDecodeError, y.YamlError) as exc:
                notes.append(f"{relative}: not read for action references ({exc})")
                continue
            if not isinstance(node, yaml.MappingNode):
                continue
            for value in _uses_values(node):
                match = _USES.match(value)
                if match and "${{" not in value:
                    owner, repo, sub, ref = match.groups()
                    refs.append(ActionRef(relative, f"{owner}/{repo}{sub}", ref))
    return refs, notes


def action_changes(base: list[ActionRef], head: list[ActionRef]) -> list[Change]:
    """References the head uses that the base did not, each paired with the reference
    to the same action that it replaces."""
    def index(refs: list[ActionRef]) -> dict[str, dict[str, set[str]]]:
        out: dict[str, dict[str, set[str]]] = {}
        for r in refs:
            out.setdefault(r.action.lower(), {}).setdefault(r.ref, set()).add(r.path)
        return out

    before, after = index(base), index(head)
    names = {r.action.lower(): r.action for r in head}
    found = []
    for key, refs in sorted(after.items()):
        old_refs = before.get(key, {})
        removed = sorted(r for r in old_refs if r not in refs)
        for ref in sorted(r for r in refs if r not in old_refs):
            old = removed[0] if removed else (sorted(old_refs)[0] if old_refs else None)
            found.append(Change(ECOSYSTEM, names[key], old, ref, tuple(sorted(refs[ref])),
                                True))
    return found


def short(ref: str) -> str:
    return ref[:12] if _SHA.match(ref) else ref


def _keep_used(report: DiffReport, sub: str) -> None:
    """Keep what runs for the repository that uses the action: its `action.yml`, or the
    reusable workflow, and the files their entry points reach. The action repository's
    own workflows and tooling never run there."""
    if sub.endswith((".yml", ".yaml")):
        wanted = {sub}
    else:
        prefix = f"{sub}/" if sub else ""
        wanted = {f"{prefix}action.yml", f"{prefix}action.yaml"}
    entries = [e for e in report.new.report.entry_points if e.path in wanted]
    if not entries:
        report.new.notes.append(f"No action or workflow was found at {sorted(wanted)[0]}.")
    reached = wanted | {t for e in entries for t in e.targets}
    report.added_entries = [e for e in report.added_entries if e.path in wanted]
    report.removed_entries = [e for e in report.removed_entries if e.path in wanted]
    report.changed_entries = [(o, n) for o, n in report.changed_entries if n.path in wanted]
    report.added_findings = [f for f in report.added_findings if f.path in reached]
    report.removed_findings = [f for f in report.removed_findings if f.path in reached]
    report.grew = [(path, detail) for path, detail in report.grew if path in reached]


def review_action(change: Change, fetch: Fetch) -> DiffReport:
    """Compare the action's repository at both references. The whole repository is
    scanned, because an action in a subfolder often runs code from elsewhere in it
    (`../lib`); only what the used action reaches is reported."""
    owner, repo, *rest = change.name.split("/")
    sub = "/".join(rest)
    with tempfile.TemporaryDirectory(prefix="bombsquad-action-",
                                     ignore_cleanup_errors=True) as work:
        sides = []
        if change.old is None:
            sides.append(Side("(not used before)", ScanReport(__version__, [], []), {}))
        for label, ref in (("old", change.old), ("new", change.new)):
            if ref is None:
                continue
            url = f"{CODELOAD}/{owner}/{repo}/tar.gz/{urllib.parse.quote(ref, safe='')}"
            data = fetch(url, MAX_ARTIFACT_BYTES)
            folder = Path(work, label)
            folder.mkdir()
            root, notes = unpack(data, f"{repo}.tar.gz", folder)
            sides.append(scan_side(f"{owner}/{repo}@{short(ref)}", root, None,
                                   [f"archive: {n}" for n in notes[:5]]))
    report = compare(f"{ECOSYSTEM}:{change.name}", sides[0], sides[1])
    _keep_used(report, sub)
    if change.old is not None:
        report.signals.append(Signal(
            "action-updated", Level.INFO,
            f"{change.name} moved from {short(change.old)} to {short(change.new)}; the code "
            f"between them: https://github.com/{owner}/{repo}/compare/{change.old}..."
            f"{change.new}"))
    else:
        report.signals.append(Signal(
            "action-added", Level.INFO, f"{change.name} is newly used, at {short(change.new)}"))
    return report
