"""Git hooks that a clone installs for itself: husky, lefthook and pre-commit.

Git never runs hooks from a fresh clone, but these tools install them: husky from an npm
`prepare` script, lefthook from `lefthook install` (often in `postinstall`), pre-commit
from `pre-commit install`. After that, each commit or push runs them.
"""

from __future__ import annotations

import shlex
from pathlib import Path

import yaml

from bombsquad.code.common import CodeHit, Snippet
from bombsquad.discovery import LANGUAGE_BY_SUFFIX, Discovery, Target, find_targets
from bombsquad.model import EntryPoint
from bombsquad.repo import yamltree as y
from bombsquad.repo.workflows import FULL_SHA
from bombsquad.textpos import Positions

HOOK_ACTIONS = {
    "pre-commit": "git commit", "prepare-commit-msg": "git commit", "commit-msg": "git commit",
    "post-commit": "git commit", "pre-merge-commit": "git merge",
    "post-merge": "git merge and git pull", "pre-push": "git push", "pre-rebase": "git rebase",
    "post-rewrite": "git commit --amend and git rebase",
    "post-checkout": "git checkout and git switch", "applypatch-msg": "git am",
    "pre-applypatch": "git am", "post-applypatch": "git am", "pre-auto-gc": "git gc --auto",
    "reference-transaction": "every ref update", "push-to-checkout": "a push to this clone",
    "sendemail-validate": "git send-email", "post-index-change": "index updates",
    "fsmonitor-watchman": "git status and other index reads",
}
GIT_HOOKS = frozenset(HOOK_ACTIONS)
RUNNERS = {"bash": "shell", "sh": "shell", "zsh": "shell", "dash": "shell", "node": "javascript",
           "python": "python", "python3": "python", "pwsh": "powershell",
           "powershell": "powershell"}
LEFTHOOK_NAMES = frozenset(f"{dot}lefthook{local}.{ext}" for dot in ("", ".")
                           for local in ("", "-local") for ext in ("yml", "yaml"))
PRE_COMMIT_NAMES = frozenset({".pre-commit-config.yaml", ".pre-commit-config.yml"})
PRE_COMMIT_TRIGGER = ("git commit, and any other stage it is installed for, once "
                      "`pre-commit install` has run in the clone")
# Local pre-commit hook languages whose entry is not a command line.
NOT_COMMANDS = frozenset({"pygrep", "fail"})
IN_CONTAINER = frozenset({"docker", "docker_image"})
MAX_GROUP_DEPTH = 5


def _runner_language(runner: str | None, path: Path) -> str | None:
    if runner:
        word = runner.split()[0].lower().rsplit("/", 1)[-1]
        if word in RUNNERS:
            return RUNNERS[word]
    return LANGUAGE_BY_SUFFIX.get(path.suffix.lower())


def _read(shown: str, text: str, found: Discovery, what: str) -> yaml.Node | None:
    try:
        node = y.compose(text)
    except y.YamlError as exc:
        found.notes.append((shown, f"Not read as {what}: {exc}."))
        return None
    return node if isinstance(node, yaml.MappingNode) else None


def _queue(found: Discovery, shown: str, positions: Positions, entry: EntryPoint,
           node: yaml.Node, key: yaml.Node | None, origin: str, base: Path, display,
           suffix: str = "") -> None:
    """Analyse a YAML scalar as a shell command, and follow the files it names."""
    command = node.value + suffix
    scalar = y.ScalarMap.build(positions, node)
    found.snippets.append((shown, Snippet("shell", command, y.first_line(positions, key or node),
                                          origin, None if suffix else scalar.offset()), entry))
    find_targets(found, entry, command, base, display)


# husky -----------------------------------------------------------------------------------

def husky(path: Path, shown: str, text: str, found: Discovery) -> None:
    name = path.name
    entry = EntryPoint("git-hooks", f"husky {name} hook",
                       f"{HOOK_ACTIONS[name]}, once husky is installed (its npm prepare script "
                       "does this on npm install)", shown, Positions(text).line_region(1), shown)
    entry.targets.append(shown)
    found.entry_points.append(entry)
    found.targets.append(Target(path, "shell", entry))


# lefthook --------------------------------------------------------------------------------

class _Lefthook:
    def __init__(self, path: Path, shown: str, text: str, found: Discovery, display,
                 root: yaml.Node) -> None:
        self.shown, self.found, self.display = shown, found, display
        self.positions = Positions(text)
        self.base = path.parent
        self.sources = [y.text(y.get(root, "source_dir")) or ".lefthook/",
                        y.text(y.get(root, "source_dir_local")) or ".lefthook-local/"]

    def hook(self, hook: str, key: yaml.Node, node: yaml.Node) -> None:
        entry = EntryPoint("git-hooks", f"lefthook {hook} hook",
                           f"{HOOK_ACTIONS[hook]}, once `lefthook install` has run (often from "
                           "an npm postinstall or prepare script)", self.shown,
                           y.first_line(self.positions, key), "")
        self.found.entry_points.append(entry)
        names: list[str] = []
        for name, _, command in y.pairs(y.get(node, "commands")):
            if y.text(y.get(command, "run")):
                names.append(name)
                self.run(entry, command, f"lefthook {hook} command '{name}'")
        for name, _, script in y.pairs(y.get(node, "scripts")):
            names.append(name)
            self.script(entry, hook, name, y.text(y.get(script, "runner")))
        self.jobs(entry, hook, y.get(node, "jobs"), names, 0)
        entry.runs = ", ".join(names) or "nothing"

    def run(self, entry: EntryPoint, node: yaml.Node, origin: str) -> None:
        _queue(self.found, self.shown, self.positions, entry, y.get(node, "run"),
               y.key_node(node, "run"), origin, self.base, self.display)

    def script(self, entry: EntryPoint, hook: str, name: str, runner: str | None) -> None:
        """Scripts live in <source_dir>/<hook>/<name>."""
        for source in self.sources:
            candidate = (self.base / source / hook / name).resolve()
            try:
                candidate.relative_to(self.base.resolve())
            except ValueError:
                continue
            language = _runner_language(runner, candidate)
            if candidate.is_file() and language:
                entry.targets.append(self.display(candidate))
                self.found.targets.append(Target(candidate, language, entry))

    def jobs(self, entry: EntryPoint, hook: str, jobs: yaml.Node | None, names: list[str],
             depth: int) -> None:
        if depth > MAX_GROUP_DEPTH:
            return
        for job in y.items(jobs):
            name = y.text(y.get(job, "name")) or "unnamed job"
            if y.text(y.get(job, "run")):
                names.append(name)
                self.run(entry, job, f"lefthook {hook} job '{name}'")
            script = y.text(y.get(job, "script"))
            if script:
                names.append(script)
                self.script(entry, hook, script, y.text(y.get(job, "runner")))
            self.jobs(entry, hook, y.get(y.get(job, "group"), "jobs"), names, depth + 1)

    def remotes(self, root: yaml.Node) -> None:
        for remote in y.items(y.get(root, "remotes")):
            url = y.get(remote, "git_url")
            ref = y.text(y.get(remote, "ref"))
            if not y.text(url) or (ref and FULL_SHA.fullmatch(ref)):
                continue
            self.found.hits.append((self.shown, CodeHit(
                "BS-PIN-001", y.region(self.positions, url),
                f"git_url: {y.text(url)}" + (f" ref: {ref}" if ref else ""),
                ["lefthook remote configuration",
                 f"fetched by {ref}, which can be moved" if ref else
                 "fetched from the default branch"],
                ["The remote configuration is not fetched or analysed."]), None))


def lefthook(path: Path, shown: str, text: str, found: Discovery, display) -> None:
    root = _read(shown, text, found, "a lefthook configuration")
    if root is None:
        return
    config = _Lefthook(path, shown, text, found, display, root)
    for hook, key, node in y.pairs(root):
        if hook in GIT_HOOKS and isinstance(node, yaml.MappingNode):
            config.hook(hook, key, node)
    config.remotes(root)


# pre-commit ------------------------------------------------------------------------------

def pre_commit(path: Path, shown: str, text: str, found: Discovery, display) -> None:
    root = _read(shown, text, found, "a pre-commit configuration")
    if root is None:
        return
    positions = Positions(text)
    base = path.parent
    for repo in y.items(y.get(root, "repos")):
        url_node = y.get(repo, "repo")
        url = y.text(url_node)
        hooks = y.items(y.get(repo, "hooks"))
        if url == "local":
            for hook in hooks:
                _local_hook(found, shown, positions, hook, base, display)
        elif url and url != "meta":
            rev_node = y.get(repo, "rev")
            rev = y.text(rev_node)
            ids = [y.text(y.get(h, "id")) or "?" for h in hooks]
            entry = EntryPoint("git-hooks", f"pre-commit hooks from {url}", PRE_COMMIT_TRIGGER,
                               shown, y.first_line(positions, url_node),
                               f"{', '.join(ids)} at {rev or 'no rev'}")
            found.entry_points.append(entry)
            if not (rev and FULL_SHA.fullmatch(rev)):
                where = rev_node if rev_node is not None else url_node
                found.hits.append((shown, CodeHit(
                    "BS-PIN-001", y.region(positions, where), f"{url} rev: {rev}",
                    [f"pre-commit hooks from {url}",
                     f"{url} is referenced by {rev}, which can be moved" if rev else
                     "no rev is given"],
                    ["The hooks' code is fetched by pre-commit and not analysed."]), entry))


def _local_hook(found: Discovery, shown: str, positions: Positions, hook: yaml.Node,
                base: Path, display) -> None:
    hook_id = y.text(y.get(hook, "id")) or "unnamed"
    language = (y.text(y.get(hook, "language")) or "system").strip().lower()
    command = y.get(hook, "entry")
    if not y.text(command) or language in NOT_COMMANDS:
        return
    args = y.strings(y.get(hook, "args"))
    suffix = "".join(" " + shlex.quote(a) for a in args)
    entry = EntryPoint("git-hooks", f"pre-commit local hook '{hook_id}' ({language})",
                       PRE_COMMIT_TRIGGER, shown, y.first_line(positions, command),
                       command.value + suffix)
    found.entry_points.append(entry)
    if language in IN_CONTAINER:
        found.notes.append((shown, f"pre-commit hook '{hook_id}' runs in a container image, "
                                   "which is not analysed."))
        return
    _queue(found, shown, positions, entry, command, y.key_node(hook, "entry"),
           f"pre-commit local hook '{hook_id}'", base, display, suffix)
    if language in ("script", "unsupported_script"):
        # The entry's first word is a script in the repository, whatever its name.
        first = (command.value.split() or [""])[0]
        candidate = (base / first).resolve()
        try:
            candidate.relative_to(base.resolve())
        except ValueError:
            return
        shown_target = display(candidate)
        if candidate.is_file() and shown_target not in entry.targets:
            entry.targets.append(shown_target)
            found.targets.append(Target(candidate, LANGUAGE_BY_SUFFIX.get(
                candidate.suffix.lower(), "shell"), entry))
