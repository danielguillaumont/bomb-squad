"""Find what runs without anyone choosing to run it: npm and Python entry points."""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from bombsquad.code.common import CodeHit, Snippet
from bombsquad.code.shell import split_command
from bombsquad.model import EntryPoint, Region
from bombsquad.textpos import Positions

LANGUAGE_BY_SUFFIX = {
    ".js": "javascript", ".cjs": "javascript", ".mjs": "javascript", ".jsx": "javascript",
    ".ts": "javascript", ".mts": "javascript", ".cts": "javascript", ".tsx": "javascript",
    ".py": "python", ".sh": "shell", ".bash": "shell",
    ".ps1": "powershell", ".psm1": "powershell",
}

NPM_INSTALL = "npm install, including when installed as a dependency"
NPM_PREPARE = "npm install in this repository, or as a git dependency"
NPM_HOOKS = {
    "preinstall": NPM_INSTALL, "install": NPM_INSTALL, "postinstall": NPM_INSTALL,
    "preprepare": NPM_PREPARE, "prepare": NPM_PREPARE, "postprepare": NPM_PREPARE,
}
PYTHON_START = "every Python start, once installed"


@dataclass
class Target:
    path: Path
    language: str
    entry: EntryPoint


@dataclass
class Discovery:
    entry_points: list[EntryPoint] = field(default_factory=list)
    targets: list[Target] = field(default_factory=list)
    snippets: list[tuple[str, Snippet, EntryPoint]] = field(default_factory=list)
    hits: list[tuple[str, CodeHit, EntryPoint]] = field(default_factory=list)
    notes: list[tuple[str, str]] = field(default_factory=list)


def _key_region(text: str, positions: Positions, key: str) -> Region:
    match = re.search(rf'"{re.escape(key)}"\s*:', text)
    if not match:
        return positions.line_region(1)
    return positions.region(match.start(), match.end())


def _target(base: Path, word: str) -> Path | None:
    """A file named on a command line, if it exists inside the package directory."""
    word = word.strip("'\"")
    if not word or word.startswith("-") or "://" in word:
        return None
    candidate = (base / word).resolve()
    try:
        candidate.relative_to(base.resolve())
    except ValueError:
        return None  # outside the package
    if candidate.is_file() and candidate.suffix.lower() in LANGUAGE_BY_SUFFIX:
        return candidate
    return None


_RUN_SCRIPT = re.compile(
    r"\b(?:npm|pnpm|yarn|bun)(?:\s+--?[\w-]+)*\s+(?:run(?:-script)?\s+)?([\w:.@/-]+)")


def _called_scripts(command: str, scripts: dict) -> list[str]:
    """Names of package.json scripts a command runs, such as `npm run build`."""
    return [m.group(1) for m in _RUN_SCRIPT.finditer(command)
            if isinstance(scripts.get(m.group(1)), str)]


def npm_package(path: Path, shown: str, text: str, found: Discovery,
                display) -> None:
    try:
        data = json.loads(text)
    except ValueError:
        found.notes.append((shown, "package.json is not valid JSON; its scripts were not read."))
        return
    if not isinstance(data, dict):
        return
    scripts = data.get("scripts") if isinstance(data.get("scripts"), dict) else {}
    positions = Positions(text)
    base = path.parent
    for hook, trigger in NPM_HOOKS.items():
        command = scripts.get(hook)
        if not isinstance(command, str) or not command.strip():
            continue
        region = _key_region(text, positions, hook)
        entry = EntryPoint("npm", f"{hook} script", trigger, shown, region, command)
        found.entry_points.append(entry)
        queue = [(hook, command, region, f"package.json {hook} script")]
        seen = {hook}
        while queue:
            name, script, script_region, origin = queue.pop(0)
            found.snippets.append((shown, Snippet("shell", script, script_region, origin), entry))
            for word in split_command(script):
                target = _target(base, word)
                if target is not None:
                    entry.targets.append(display(target))
                    found.targets.append(Target(
                        target, LANGUAGE_BY_SUFFIX[target.suffix.lower()], entry))
            # `npm run setup` in a hook runs the setup script too.
            for called in _called_scripts(script, scripts):
                if called not in seen and len(seen) < 10:
                    seen.add(called)
                    queue.append((called, scripts[called], _key_region(text, positions, called),
                                  f"package.json {called} script, run by {name}"))
    gyp = base / "binding.gyp"
    if gyp.is_file() and not any(isinstance(scripts.get(h), str) and scripts.get(h).strip()
                                 for h in ("install", "preinstall")):
        gyp_text = gyp.read_text(encoding="utf-8", errors="replace")
        gyp_positions = Positions(gyp_text)
        entry = EntryPoint("npm", "binding.gyp (npm runs node-gyp rebuild)", NPM_INSTALL,
                           display(gyp), gyp_positions.line_region(1), "node-gyp rebuild")
        found.entry_points.append(entry)
        # gyp runs the commands in <!(...) and <!@(...) while it reads the file.
        for match in re.finditer(r"<!@?\((.*?)\)['\"]", gyp_text):
            found.snippets.append((display(gyp), Snippet(
                "shell", match.group(1), gyp_positions.region(match.start(), match.end()),
                "command expansion in binding.gyp"), entry))


def python_file(path: Path, shown: str, text: str, found: Discovery) -> None:
    name = path.name.lower()
    positions = Positions(text)
    first = positions.line_region(1)
    if name == "setup.py":
        entry = EntryPoint("python", "setup.py", "pip install from source, or python setup.py",
                           shown, first, "setup.py")
        found.entry_points.append(entry)
        entry.targets.append(shown)
        found.targets.append(Target(path, "python", entry))
    elif name in ("sitecustomize.py", "usercustomize.py"):
        entry = EntryPoint("python", name, PYTHON_START, shown, first, name)
        found.entry_points.append(entry)
        entry.targets.append(shown)
        found.targets.append(Target(path, "python", entry))
        found.hits.append((shown, CodeHit("BS-EP-001", first, name,
                                          [f"{name} is imported at interpreter start"]), entry))
    elif name == "conftest.py":
        entry = EntryPoint("python", "conftest.py", "running pytest in or below this directory",
                           shown, first, "conftest.py")
        found.entry_points.append(entry)
        entry.targets.append(shown)
        found.targets.append(Target(path, "python", entry))
    elif path.suffix.lower() == ".pth":
        for line_no in range(1, len(positions.line_starts) + 1):
            line = positions.line_text(line_no)
            if re.match(r"import[ \t]", line):
                region = positions.line_region(line_no)
                entry = EntryPoint("python", ".pth import line", PYTHON_START, shown, region,
                                   line.strip())
                found.entry_points.append(entry)
                found.hits.append((shown, CodeHit(
                    "BS-EP-001", region, line.strip()[:300],
                    ["Python executes .pth lines that start with import"]), entry))
                found.snippets.append((shown, Snippet("python", line, region,
                                                      f".pth line {line_no}"), entry))
    elif name == "pyproject.toml":
        _build_backend(path, shown, text, positions, found)


def _build_backend(path: Path, shown: str, text: str, positions: Positions,
                   found: Discovery) -> None:
    """An in-tree build backend runs while the package is built from source."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return
    system = data.get("build-system") if isinstance(data.get("build-system"), dict) else {}
    backend = system.get("build-backend")
    backend_paths = system.get("backend-path")
    if not isinstance(backend, str) or not isinstance(backend_paths, list):
        return
    match = re.search(r"^\s*backend-path\s*=", text, re.MULTILINE)
    region = positions.region(match.start(), match.end()) if match else positions.line_region(1)
    entry = EntryPoint("python", "in-tree build backend", "pip install or build from source",
                       shown, region, backend)
    found.entry_points.append(entry)
    module = backend.split(":")[0].replace(".", "/")
    base = path.parent.resolve()
    for folder in backend_paths:
        if not isinstance(folder, str):
            continue
        for candidate in (base / folder / f"{module}.py", base / folder / module / "__init__.py"):
            try:
                candidate.resolve().relative_to(base)
            except ValueError:
                continue
            if candidate.is_file():
                found.targets.append(Target(candidate.resolve(), "python", entry))


DETECTED_NAMES = frozenset({"package.json", "setup.py", "sitecustomize.py", "usercustomize.py",
                            "conftest.py", "pyproject.toml"})


def is_detected(path: Path) -> bool:
    return path.name.lower() in DETECTED_NAMES or path.suffix.lower() == ".pth"


def discover(path: Path, shown: str, text: str, found: Discovery, display) -> None:
    if path.name.lower() == "package.json":
        npm_package(path, shown, text, found, display)
    else:
        python_file(path, shown, text, found)
