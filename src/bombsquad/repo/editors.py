"""Editors and dev containers: VS Code tasks that run when a folder opens, and dev
container lifecycle commands, of which `initializeCommand` runs on the host."""

from __future__ import annotations

import json
import re
from pathlib import Path

from bombsquad.code.common import CodeHit, Snippet
from bombsquad.discovery import Discovery, find_targets, quote_word
from bombsquad.model import EntryPoint, Region
from bombsquad.repo import jsonc
from bombsquad.sources import InputError, read_source
from bombsquad.textpos import Positions

FOLDER_OPEN = "opening the folder in a VS Code-based editor, once it is trusted"
LIFECYCLE = {
    "initializeCommand": "the host machine, whenever the dev container is created or started",
    "onCreateCommand": "creation of the dev container",
    "updateContentCommand": "creation of the dev container, and content updates",
    "postCreateCommand": "creation of the dev container",
    "postStartCommand": "every start of the dev container",
    "postAttachCommand": "every attach to the dev container",
}
MAX_DEPENDS = 20
WORKSPACE = re.compile(r"\$\{(?:workspaceFolder|workspaceRoot|localWorkspaceFolder|"
                       r"containerWorkspaceFolder)\}")


def _read(shown: str, text: str, found: Discovery, what: str) -> jsonc.Node | None:
    try:
        node = jsonc.parse(text)
    except jsonc.JsoncError as exc:
        line = Positions(text).region(exc.index, exc.index).line
        found.notes.append((shown, f"Not read as {what}: {exc} at line {line}."))
        return None
    return node if isinstance(node.value, dict) else None


def _piece(node: jsonc.Node | None) -> str | None:
    """A task command or argument: a string, or {"value": ..., "quoting": ...}."""
    if node is None:
        return None
    if node.text() is not None:
        return node.text()
    value = node.get("value")
    if value is not None and value.text() is not None:
        return value.text()
    if isinstance(value, jsonc.Node) and value.items():
        return " ".join(p for p in (_piece(v) for v in value.items()) if p)
    return None


def _command_line(command: jsonc.Node | None, args: jsonc.Node | None) -> str | None:
    if command is None:
        return None
    if command.items():
        words = [p for p in (_piece(n) for n in command.items()) if p is not None]
        head = " ".join(quote_word(w) for w in words)
    else:
        head = _piece(command)
    if head is None:
        return None
    tail = [p for p in (_piece(n) for n in (args.items() if args else [])) if p is not None]
    return " ".join([head, *(quote_word(t) for t in tail)])


class _Editor:
    def __init__(self, path: Path, shown: str, text: str, found: Discovery, display,
                 root: Path) -> None:
        self.path, self.shown, self.text, self.found, self.display, self.root = (
            path, shown, text, found, display, root)
        self.positions = Positions(text)

    def region(self, start: int, end: int) -> Region:
        return self.positions.region(start, end)

    def line(self, node: jsonc.Node) -> Region:
        return self.positions.line_region(self.positions.region(node.start, node.start).line)

    def queue(self, entry: EntryPoint, language: str | None, command: str, node: jsonc.Node,
              origin: str) -> None:
        if language is None:
            self.found.notes.append((self.shown, f"The cmd command in {origin} is not "
                                                 "analysed."))
            return
        self.found.snippets.append((self.shown, Snippet(language, command, self.line(node),
                                                        origin), entry))
        find_targets(self.found, entry, WORKSPACE.sub(".", command), self.root, self.display)


# VS Code tasks ---------------------------------------------------------------------------

def _text_at(node: jsonc.Node | None, *keys: str) -> str | None:
    for key in keys:
        node = node.get(key) if node is not None else None
    return node.text() if node is not None else None


def _shell_language(scope: jsonc.Node, task: jsonc.Node, windows: bool) -> str | None:
    """Shell tasks run in the default terminal shell, which is PowerShell on Windows."""
    executable = (_text_at(scope, "options", "shell", "executable")
                  or _text_at(task, "options", "shell", "executable") or "").lower()
    program = executable.replace("\\", "/").rsplit("/", 1)[-1].removesuffix(".exe")
    if program == "cmd":
        return None
    if program in ("pwsh", "powershell"):
        return "powershell"
    if program:
        return "shell"
    kind = _text_at(scope, "type") or _text_at(task, "type") or "shell"
    return "powershell" if windows and kind == "shell" else "shell"


def tasks_file(path: Path, shown: str, text: str, found: Discovery, display) -> None:
    root = _read(shown, text, found, "VS Code tasks")
    if root is None:
        return
    item = _Editor(path, shown, text, found, display, path.parent.parent)
    tasks = [t for t in (root.get("tasks").items() if root.get("tasks") else [])
             if isinstance(t.value, dict)]
    by_label: dict[str, jsonc.Node] = {}
    for task in tasks:
        label = task.get("label") or task.get("taskName")
        if label is not None and label.text():
            by_label.setdefault(label.text(), task)
    for task in tasks:
        options = task.get("runOptions")
        run_on = options.get("runOn") if options else None
        if run_on is None or run_on.text() != "folderOpen":
            continue
        label = _label(task)
        start, _ = options.key_span("runOn")
        region = item.region(start, run_on.end)
        entry = EntryPoint("editor", f"VS Code task '{label}' (runOn: folderOpen)", FOLDER_OPEN,
                           shown, region, _summary(task) or label)
        found.entry_points.append(entry)
        found.hits.append((shown, CodeHit(
            "BS-EP-002", region, item.positions.line_text(region.line).strip(),
            [f"task '{label}' runs when the folder opens"]), entry))
        # Tasks it depends on run first.
        seen = {id(task)}
        queue = [(task, f"task '{label}'")]
        while queue:
            current, origin = queue.pop(0)
            _task_commands(item, entry, current, origin)
            for name in _depends(current):
                other = by_label.get(name)
                if other is not None and id(other) not in seen and len(seen) < MAX_DEPENDS:
                    seen.add(id(other))
                    queue.append((other, f"task '{name}', which task '{label}' depends on"))


def _label(task: jsonc.Node) -> str:
    label = task.get("label") or task.get("taskName")
    return (label.text() if label else None) or "unnamed"


def _summary(task: jsonc.Node) -> str | None:
    return _command_line(task.get("command"), task.get("args")) or (
        f"npm run {task.get('script').text()}" if task.get("script") and
        task.get("script").text() else None)


def _depends(task: jsonc.Node) -> list[str]:
    node = task.get("dependsOn")
    if node is None:
        return []
    if node.text() is not None:
        return [node.text()]
    return [n.text() for n in node.items() if n.text() is not None]


def _task_commands(item: _Editor, entry: EntryPoint, task: jsonc.Node, origin: str) -> None:
    for platform in (None, "linux", "osx", "windows"):
        scope = task if platform is None else task.get(platform)
        if scope is None or not isinstance(scope.value, dict):
            continue
        command_node = scope.get("command")
        if platform is not None and command_node is None and scope.get("args") is None:
            continue  # only options differ
        command_node = command_node or task.get("command")
        line = _command_line(command_node, scope.get("args") or task.get("args"))
        where = origin if platform is None else f"{origin} on {platform}"
        if line is None:
            if platform is None:
                _npm_task(item, entry, task, where)
            continue
        language = _shell_language(scope, task, platform == "windows")
        item.queue(entry, language, line, command_node or task, f"VS Code {where}")


def _npm_task(item: _Editor, entry: EntryPoint, task: jsonc.Node, origin: str) -> None:
    """`"type": "npm", "script": "x"` runs that package.json script."""
    kind, script = task.get("type"), task.get("script")
    if not kind or kind.text() != "npm" or not script or not script.text():
        return
    folder = task.get("path")
    package = item.root / (folder.text() if folder and folder.text() else "") / "package.json"
    try:
        package.resolve().relative_to(item.root.resolve())
        data = json.loads(read_source(package)[0])
    except (ValueError, OSError, InputError):
        return
    scripts = data.get("scripts") if isinstance(data, dict) else None
    command = scripts.get(script.text()) if isinstance(scripts, dict) else None
    if isinstance(command, str):
        item.queue(entry, "shell", command, script,
                   f"package.json {script.text()} script, run by VS Code {origin}")


# Dev containers --------------------------------------------------------------------------

def devcontainer_root(path: Path) -> Path:
    if path.name.lower() == ".devcontainer.json":
        return path.parent
    if path.parent.name.lower() == ".devcontainer":
        return path.parent.parent
    return path.parent.parent.parent


def devcontainer_file(path: Path, shown: str, text: str, found: Discovery, display) -> None:
    root = _read(shown, text, found, "a dev container configuration")
    if root is None:
        return
    item = _Editor(path, shown, text, found, display, devcontainer_root(path))
    for key, trigger in LIFECYCLE.items():
        node = root.get(key)
        if node is None:
            continue
        commands = _lifecycle_commands(node)
        if not commands:
            continue
        start, end = root.key_span(key)
        region = item.region(start, end)
        where = "on the host" if key == "initializeCommand" else "inside the container"
        entry = EntryPoint("editor", f"devcontainer {key}", trigger, shown, region,
                           "; ".join(c for _, c, _ in commands))
        found.entry_points.append(entry)
        if key == "initializeCommand":
            found.hits.append((shown, CodeHit(
                "BS-EP-003", region, item.positions.line_text(region.line).strip(),
                ["initializeCommand runs on the host, not in the container"]), entry))
        for name, command, at in commands:
            origin = f"devcontainer {key}{f' {name!r}' if name else ''}, run {where}"
            item.queue(entry, "shell", command, at, origin)


def _lifecycle_commands(node: jsonc.Node) -> list[tuple[str | None, str, jsonc.Node]]:
    """A string runs in a shell; an array runs one program with arguments; an object runs
    several commands in parallel."""
    def one(value: jsonc.Node) -> str | None:
        if value.text() is not None:
            return value.text()
        words = [n.text() for n in value.items() if n.text() is not None]
        return " ".join(quote_word(w) for w in words) if words else None

    if isinstance(node.value, dict):
        out = []
        for name, value in node.value.items():
            command = one(value)
            if command:
                out.append((name, command, value))
        return out
    command = one(node)
    return [(None, command, node)] if command else []
