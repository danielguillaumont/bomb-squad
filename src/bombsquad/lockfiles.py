"""Pinned dependency versions from lockfiles, so a pull request's dependency updates can be
reviewed one by one.

Lockfiles are parsed as JSON, TOML or text. Nothing in them is resolved, installed or run.
Only packages that come from the npm registry or PyPI are listed; git, path and other
sources are counted in the notes.
"""

from __future__ import annotations

import json
import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from bombsquad.sources import MAX_FILE_BYTES, SKIPPED_DIRS

NPM_LOCKS = ("package-lock.json", "npm-shrinkwrap.json")
PYTHON_LOCKS = ("uv.lock", "poetry.lock")
NOT_READ = ("yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb", "Pipfile.lock",
            "pdm.lock")
_REQUIREMENTS = re.compile(r"^requirements[\w.-]*\.txt$", re.IGNORECASE)
_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([^\s;#,]+)\s*"
                  r"(?:[;#].*)?$")
NPM_REGISTRY = "https://registry.npmjs.org/"
PYPI_INDEXES = ("https://pypi.org/simple", "https://pypi.org/simple/")


@dataclass(frozen=True)
class Pin:
    ecosystem: str  # npm | pypi
    name: str
    version: str
    lockfile: str  # path relative to the tree
    direct: bool = False


@dataclass
class Pins:
    pins: list[Pin] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def normalise(ecosystem: str, name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower() if ecosystem == "pypi" else name


def read_tree(root: Path) -> Pins:
    out = Pins()
    for folder, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIPPED_DIRS)
        for name in sorted(names):
            path = Path(folder, name)
            if path.is_symlink() or not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            reader = _reader(name)
            if reader is None:
                if name in NOT_READ:
                    out.notes.append(f"{relative}: this lockfile format is not read yet")
                continue
            if path.stat().st_size > MAX_FILE_BYTES * 10:
                out.notes.append(f"{relative}: larger than {MAX_FILE_BYTES * 10 // 2**20} MB, "
                                 "not read")
                continue
            try:
                text = path.read_text(encoding="utf-8-sig")
            except (OSError, UnicodeDecodeError) as exc:
                out.notes.append(f"{relative}: not read ({exc.__class__.__name__})")
                continue
            try:
                reader(text, relative, out)
            except (ValueError, tomllib.TOMLDecodeError, TypeError, AttributeError) as exc:
                out.notes.append(f"{relative}: not read ({exc})")
    return out


def _reader(name: str):
    if name in NPM_LOCKS:
        return _npm
    if name == "uv.lock":
        return _uv
    if name == "poetry.lock":
        return _poetry
    if _REQUIREMENTS.match(name):
        return _requirements
    return None


def _npm(text: str, relative: str, out: Pins) -> None:
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("not a JSON object")
    skipped = 0
    packages = data.get("packages")
    if isinstance(packages, dict):  # lockfileVersion 2 and 3
        root = packages.get("") if isinstance(packages.get(""), dict) else {}
        direct = set()
        for key in ("dependencies", "devDependencies", "optionalDependencies",
                    "peerDependencies"):
            if isinstance(root.get(key), dict):
                direct.update(root[key])
        for key, entry in packages.items():
            if "node_modules/" not in key or not isinstance(entry, dict):
                continue
            name = entry.get("name") or key.rsplit("node_modules/", 1)[-1]
            version = entry.get("version")
            resolved = entry.get("resolved")
            if entry.get("link") or not isinstance(version, str) or not isinstance(name, str):
                skipped += 1
                continue
            if isinstance(resolved, str) and not resolved.startswith(NPM_REGISTRY):
                skipped += 1
                continue
            out.pins.append(Pin("npm", name, version, relative,
                                key == f"node_modules/{name}" and name in direct))
    elif isinstance(data.get("dependencies"), dict):  # lockfileVersion 1
        stack = [(data["dependencies"], True)]
        while stack:
            deps, top = stack.pop()
            for name, entry in deps.items():
                if not isinstance(entry, dict):
                    continue
                version, resolved = entry.get("version"), entry.get("resolved")
                if not isinstance(version, str) or (
                        isinstance(resolved, str) and not resolved.startswith(NPM_REGISTRY)):
                    skipped += 1
                elif re.match(r"^\d", version):
                    out.pins.append(Pin("npm", name, version, relative,
                                        top and not entry.get("dev", False)))
                else:
                    skipped += 1  # a git URL or path in place of a version
                if isinstance(entry.get("dependencies"), dict):
                    stack.append((entry["dependencies"], False))
    if skipped:
        out.notes.append(f"{relative}: {skipped} entries not from the npm registry (git, "
                         "path, link or other) were not reviewed")


def _uv(text: str, relative: str, out: Pins) -> None:
    data = tomllib.loads(text)
    packages = [p for p in data.get("package", []) if isinstance(p, dict)]
    direct = set()
    for p in packages:
        source = p.get("source") if isinstance(p.get("source"), dict) else {}
        if "editable" in source or "virtual" in source:
            lists = [p.get("dependencies", [])]
            for key in ("dev-dependencies", "optional-dependencies"):
                if isinstance(p.get(key), dict):
                    lists += p[key].values()
            for deps in lists:
                direct.update(normalise("pypi", d["name"]) for d in deps
                              if isinstance(d, dict) and isinstance(d.get("name"), str))
    skipped = 0
    for p in packages:
        source = p.get("source") if isinstance(p.get("source"), dict) else {}
        name, version = p.get("name"), p.get("version")
        if "editable" in source or "virtual" in source:
            continue
        if source.get("registry") not in PYPI_INDEXES or not isinstance(name, str) or (
                not isinstance(version, str)):
            skipped += 1
            continue
        key = normalise("pypi", name)
        out.pins.append(Pin("pypi", key, version, relative, key in direct))
    if skipped:
        out.notes.append(f"{relative}: {skipped} packages not from PyPI were not reviewed")


def _poetry(text: str, relative: str, out: Pins) -> None:
    data = tomllib.loads(text)
    skipped = 0
    for p in data.get("package", []):
        if not isinstance(p, dict):
            continue
        name, version = p.get("name"), p.get("version")
        source = p.get("source")
        if source or not isinstance(name, str) or not isinstance(version, str):
            skipped += 1  # git, path, url and private-index packages carry a source
            continue
        out.pins.append(Pin("pypi", normalise("pypi", name), version, relative))
    if skipped:
        out.notes.append(f"{relative}: {skipped} packages not from PyPI were not reviewed")


def _requirements(text: str, relative: str, out: Pins) -> None:
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].strip().rstrip("\\").strip()
        if not line or line.startswith(("#", "-")):
            continue
        match = _PIN.match(line)
        if match:
            out.pins.append(Pin("pypi", normalise("pypi", match.group(1)), match.group(2),
                                relative, True))


# Changes ------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Change:
    ecosystem: str
    name: str
    old: str | None  # None for a package the base did not have
    new: str
    lockfiles: tuple[str, ...]
    direct: bool

    @property
    def spec(self) -> str:
        return f"{self.ecosystem}:{self.name}@{self.old}..{self.new}"


def version_key(version: str) -> tuple:
    return tuple((0, int(part), "") if part.isdigit() else (1, 0, part)
                 for part in re.split(r"[.+\-_]", version.lower()) if part)


def changes(base: Pins, head: Pins) -> list[Change]:
    """Versions the head pins that the base did not, each paired with the base version it
    most likely replaces. Direct dependencies come first."""
    def index(pins: Pins) -> dict[tuple[str, str], dict[str, set[str]]]:
        out: dict[tuple[str, str], dict[str, set[str]]] = {}
        for p in pins.pins:
            out.setdefault((p.ecosystem, p.name), {}).setdefault(p.version, set()).add(
                p.lockfile)
        return out

    before, after = index(base), index(head)
    direct = {(p.ecosystem, p.name) for p in head.pins if p.direct}
    found = []
    for key, versions in after.items():
        old_versions = before.get(key, {})
        added = sorted((v for v in versions if v not in old_versions), key=version_key)
        removed = sorted((v for v in old_versions if v not in versions), key=version_key)
        for version in added:
            pool = removed or sorted(old_versions, key=version_key)
            lower = [v for v in pool if version_key(v) <= version_key(version)]
            old = (lower or pool)[-1] if pool else None
            found.append(Change(key[0], key[1], old, version, tuple(sorted(versions[version])),
                                key in direct))
    found.sort(key=lambda c: (not c.direct, c.ecosystem, c.name, version_key(c.new)))
    return found
