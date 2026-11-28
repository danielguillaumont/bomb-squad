"""A detonated package's dependencies, fetched outside the sandbox.

The sandbox reaches only the sink, so it cannot download what the package needs. Before
it starts, a separate container from the same image, which has a network but holds neither
the package nor the fake credentials, fetches the dependencies the package declares:

- npm: `npm install --ignore-scripts`, so no install script of any dependency runs.
- PyPI: `pip download --only-binary=:all:`, so only wheels are fetched and nothing is built.

What comes back is read as a tar stream, and only regular files with plain relative names
are kept, up to the limits below. The package itself is never in that container.
"""

from __future__ import annotations

import ast
import io
import json
import re
import tarfile
import tomllib
from dataclasses import dataclass, field
from email.parser import HeaderParser
from pathlib import Path, PurePosixPath

MAX_DECLARED = 100  # dependencies read from the package
MAX_BYTES = 300 * 1024 * 1024  # what the fetch container may send back
MAX_FILES = 100_000
FETCH_SECONDS = 180

NPM_NAME = re.compile(r"^(?:@[a-z0-9][\w.~-]*/)?[a-z0-9][\w.~-]*$", re.I)
NPM_RANGE = re.compile(r"^[\w.*^~<>=|\s-]{1,100}$")
REQUIREMENT = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]*"  # name
    r"(?:\s*\[[A-Za-z0-9._,\s-]*\])?"  # extras
    r"(?:\s*\(?[\s<>=!~,.\w*+-]*\)?)?"  # versions
    r"(?:\s*;[\s\w.'\"<>=!~(),*-]*)?$")  # environment marker
WHEEL = re.compile(r"^[A-Za-z0-9][\w.+-]*\.whl$")

# The fetch scripts get the dependencies as arguments, never inside the script text. Each
# is first tried all together; if that fails, one at a time, keeping what works.
NPM_SCRIPT = """\
mkdir -p /tmp/deps && cd /tmp/deps && echo '{}' > package.json
flags='--ignore-scripts --no-audit --no-fund --no-save --omit=dev --loglevel=error'
npm install $flags "$@" >&2 || for spec in "$@"; do npm install $flags "$spec" >&2; done
[ -d node_modules ] && tar -cf - node_modules | head -c %d
exit 0
"""
PIP_SCRIPT = """\
mkdir -p /tmp/out
download() {
  python -m pip download --only-binary=:all: --dest /tmp/out --no-cache-dir \\
    --disable-pip-version-check --quiet "$@" >&2
}
download "$@" || for req in "$@"; do download "$req"; done
cd /tmp && tar -cf - out | head -c %d
exit 0
"""


@dataclass
class Fetched:
    """What the fetch container sent back: (path, data) pairs, relative to node_modules for
    npm and file names of wheels for PyPI."""
    files: list[tuple[str, bytes]] = field(default_factory=list)
    names: list[str] = field(default_factory=list)  # the packages fetched
    notes: list[str] = field(default_factory=list)


def npm_dependencies(root: Path) -> list[str]:
    """`name@range` for the dependencies and optional dependencies in package.json that
    come from the registry. Git, URL, file and alias specifiers are left out."""
    try:
        manifest = json.loads((root / "package.json").read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return []
    if not isinstance(manifest, dict):
        return []
    specs: dict[str, str] = {}
    for key in ("dependencies", "optionalDependencies"):
        section = manifest.get(key)
        if isinstance(section, dict):
            for name, spec in section.items():
                if (isinstance(name, str) and isinstance(spec, str) and NPM_NAME.match(name)
                        and NPM_RANGE.match(spec.strip() or "*")):
                    specs[name] = spec.strip() or "*"
    return [f"{name}@{spec}" for name, spec in list(specs.items())[:MAX_DECLARED]]


def _metadata_requirements(text: str) -> list[str]:
    return HeaderParser().parsestr(text).get_all("Requires-Dist") or []


def _requires_txt(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("["):
            break  # sections hold extras and conditional requirements
        if line and not line.startswith("#"):
            out.append(line)
    return out


def _pyproject(text: str) -> list[str]:
    try:
        project = tomllib.loads(text).get("project") or {}
    except tomllib.TOMLDecodeError:
        return []
    deps = project.get("dependencies") if isinstance(project, dict) else None
    return [d for d in deps if isinstance(d, str)] if isinstance(deps, list) else []


def _setup_py(text: str) -> list[str]:
    """A literal install_requires list in a setup() call. Read, never run."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for keyword in node.keywords:
                if keyword.arg == "install_requires":
                    try:
                        value = ast.literal_eval(keyword.value)
                    except (ValueError, SyntaxError, TypeError, RecursionError):
                        return []
                    if isinstance(value, (list, tuple)):
                        return [v for v in value if isinstance(v, str)]
    return []


def _shallow(root: Path, pattern: str, depth: int = 3) -> list[Path]:
    found = [p for p in root.rglob(pattern)
             if p.is_file() and len(p.relative_to(root).parts) <= depth]
    return sorted(found, key=lambda p: (len(p.parts), str(p)))


def pypi_requirements(root: Path) -> list[str]:
    """The requirements the release declares, from the first source that has any: wheel
    METADATA or sdist PKG-INFO, egg-info requires.txt, pyproject.toml [project], or a
    literal install_requires in setup.py. Direct URL references are left out."""
    sources = [
        *[(p, _metadata_requirements) for p in _shallow(root, "METADATA")
          if p.parent.name.endswith(".dist-info")],
        *[(p, _metadata_requirements) for p in _shallow(root, "PKG-INFO")],
        *[(p, _requires_txt) for p in _shallow(root, "requires.txt")
          if p.parent.name.endswith(".egg-info")],
        *[(p, _pyproject) for p in _shallow(root, "pyproject.toml", 2)],
        *[(p, _setup_py) for p in _shallow(root, "setup.py", 2)],
    ]
    for path, read in sources:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        found = [r.strip() for r in read(text)]
        valid = [r for r in found if REQUIREMENT.match(r) and "@" not in r and len(r) <= 300]
        if valid:
            return list(dict.fromkeys(valid))[:MAX_DECLARED]
    return []


def declared(ecosystem: str, root: Path) -> list[str]:
    return npm_dependencies(root) if ecosystem == "npm" else pypi_requirements(root)


def fetch_command(ecosystem: str, image: str, name: str, specs: list[str]) -> list[str]:
    """The docker command for the fetch container: the detonation image with its own entry
    point replaced, the image's unprivileged user, no capabilities, Docker's default
    network, and no files from the host."""
    script = (NPM_SCRIPT if ecosystem == "npm" else PIP_SCRIPT) % MAX_BYTES
    return ["docker", "run", "--rm", "--name", name, "--entrypoint", "sh", "--user",
            "1001:1001", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--memory", "1g", "--cpus", "1", "--pids-limit", "256", "--env",
            "HOME=/home/detonate", image, "-c", script, "sh", *specs]


def _clean(name: str, prefix: str) -> str | None:
    if "\\" in name or name.startswith("/"):
        return None
    path = PurePosixPath(name)
    parts = path.parts
    if len(parts) < 2 or parts[0] != prefix or any(p in ("", ".", "..") for p in parts):
        return None
    return "/".join(parts[1:])


def read_fetched(ecosystem: str, data: bytes) -> Fetched:
    """The regular files under node_modules/ (npm) or the wheels under out/ (PyPI) in the
    fetch container's tar stream. A stream cut at MAX_BYTES keeps what came before."""
    prefix = "node_modules" if ecosystem == "npm" else "out"
    fetched = Fetched()
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r|") as tar:
            for member in tar:
                if len(fetched.files) >= MAX_FILES:
                    fetched.notes.append(f"Only the first {MAX_FILES} dependency files "
                                         "were kept.")
                    break
                if not member.isreg():
                    continue
                relative = _clean(member.name, prefix)
                if relative is None or (ecosystem == "pypi" and not WHEEL.match(relative)):
                    continue
                stream = tar.extractfile(member)
                content = stream.read() if stream else b""
                total += len(content)
                fetched.files.append((relative, content))
    except (tarfile.TarError, EOFError, OSError):
        if data:
            fetched.notes.append("The dependencies were cut short; what came before is "
                                 "installed.")
    if total >= MAX_BYTES:
        fetched.notes.append(f"The dependencies were cut at {MAX_BYTES // (1024 * 1024)} MB.")
    if ecosystem == "npm":
        names = set()
        for relative, _ in fetched.files:
            parts = relative.split("/")
            if parts[-1] == "package.json" and (len(parts) == 2 or (
                    len(parts) == 3 and parts[0].startswith("@"))):
                names.add("/".join(parts[:-1]))
        fetched.names = sorted(names)
    else:
        fetched.names = sorted(relative for relative, _ in fetched.files)
    return fetched
