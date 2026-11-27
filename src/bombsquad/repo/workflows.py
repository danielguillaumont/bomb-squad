"""GitHub Actions: workflow jobs and their steps, and actions defined in action.yml.

Each workflow job is an entry point that runs on the workflow's events. Its `run:` steps
are analysed in the language of their shell, and the files they name are followed. The
workflow rules are narrow on purpose (see `bombsquad.repo.rules`).

`${{ }}` expressions are replaced with placeholders of the same length before a script is
parsed: GitHub substitutes them before the shell starts, so their text is not shell
syntax. Evidence shows the original expression.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from bombsquad.code.common import CodeHit, Snippet, clip
from bombsquad.code.shell import NetworkCommand, analyze_shell, network_commands
from bombsquad.discovery import Discovery, Target, find_targets, target_path
from bombsquad.model import EntryPoint, Level, Region
from bombsquad.repo import yamltree as y
from bombsquad.textpos import Positions

EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
CONTEXT = re.compile(r"(?<![\w.])(?:github\.(?:event|head_ref)|secrets|inputs)"
                     r"(?:\.[A-Za-z_*][\w*-]*|\[[^\]]*\])*")

# Runs with the base repository's secrets and a token that can write, whoever triggered it.
PRIVILEGED_EVENTS = ("pull_request_target", "workflow_run", "issue_comment")

# Fields anyone who can open an issue or pull request, comment, or push a branch to a fork
# can set. Based on GitHub's documentation on script injections, plus discussions and the
# workflow_run fields that carry a pull request's branch and commit.
ATTACKER_CONTROLLED = tuple(p.split(".") for p in (
    "github.event.issue.title", "github.event.issue.body",
    "github.event.pull_request.title", "github.event.pull_request.body",
    "github.event.discussion.title", "github.event.discussion.body",
    "github.event.comment.body", "github.event.review.body", "github.event.review_comment.body",
    "github.event.pages.*.page_name",
    "github.event.commits.*.message", "github.event.head_commit.message",
    "github.event.commits.*.author.email", "github.event.commits.*.author.name",
    "github.event.head_commit.author.email", "github.event.head_commit.author.name",
    "github.event.pull_request.head.ref", "github.event.pull_request.head.label",
    "github.event.pull_request.head.repo.default_branch",
    "github.head_ref",
    "github.event.workflow_run.head_branch", "github.event.workflow_run.display_title",
    "github.event.workflow_run.head_commit.message",
    "github.event.workflow_run.head_commit.author.email",
    "github.event.workflow_run.head_commit.author.name",
    "github.event.workflow_run.pull_requests.*.head.ref",
))
# Event fields that cannot carry shell syntax: numbers, hashes, states, logins, URLs.
SAFE_FIELDS = frozenset({
    "number", "id", "node_id", "sha", "head_sha", "base_sha", "merge_commit_sha", "before",
    "after", "merged", "draft", "state", "action", "run_id", "run_number", "run_attempt",
    "conclusion", "status", "login", "full_name", "created_at", "updated_at", "closed_at",
    "merged_at", "pushed_at", "private", "fork", "forced", "created", "deleted", "html_url",
    "url", "size",
})
PR_HEAD = re.compile(
    r"github\.event\.pull_request\.(?:head\.(?:sha|ref|repo\.full_name)|merge_commit_sha)"
    r"|github\.head_ref"
    r"|github\.event\.workflow_run\.(?:head_sha|head_branch|head_repository\.full_name)"
    r"|refs/pull/")
GIT_FETCH = re.compile(r"\bgit\s+(?:-\S+\s+)*(?:fetch|checkout|switch|pull|clone|worktree)\b")
GH_CHECKOUT = re.compile(r"\bgh\s+pr\s+checkout\b")

FIRST_PARTY_OWNERS = frozenset({"actions", "github"})
FULL_SHA = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")

DATA_FLAGS = frozenset({"-d", "--data", "--data-ascii", "--data-binary", "--data-raw",
                        "--data-urlencode", "-F", "--form", "--form-string", "-T",
                        "--upload-file", "--json", "--post-data", "--body-data", "--post-file",
                        "--body-file"})
HEADER_FLAGS = frozenset({"-H", "--header", "-u", "--user", "--oauth2-bearer", "-b",
                          "--cookie", "--proxy-user", "--http-user", "--http-password"})


def _normalise(ref: str) -> str:
    ref = re.sub(r"\[\s*['\"]([^'\"\]]+)['\"]\s*\]", r".\1", ref)
    return re.sub(r"\[[^\]]*\]", ".*", ref)


def _controlled(ref: str) -> bool:
    parts = ref.split(".")
    for pattern in ATTACKER_CONTROLLED:
        if all(a == b or "*" in (a, b) for a, b in zip(parts, pattern, strict=False)):
            return True
    return False


def _classify(ref: str) -> Level | None:
    """HIGH for attacker-controlled fields, REVIEW for other event fields, else None."""
    ref = _normalise(ref)
    if ref.startswith(("inputs.", "github.event.inputs", "secrets")) or ref == "inputs":
        return None
    if _controlled(ref):
        return Level.HIGH
    if not ref.startswith("github.event.") or ref.startswith("github.event.repository."):
        return None
    if ref.rsplit(".", 1)[-1] in SAFE_FIELDS:
        return None
    return Level.REVIEW


def _secret_refs(expression: str) -> tuple[set[str], bool]:
    """Secret names an expression reads, and whether it reads every secret."""
    names: set[str] = set()
    every = False
    for match in CONTEXT.finditer(expression):
        ref = _normalise(match.group())
        if ref == "secrets" or ref == "secrets.*":
            every = True
        elif ref.startswith("secrets."):
            names.add(ref.split(".")[1])
    if re.search(r"\bgithub\.token\b", expression):
        names.add("GITHUB_TOKEN")
    return names, every


def _language(shell: str | None) -> str | None:
    if not shell:
        return "shell"
    word = shell.split()[0].lower().replace("\\", "/").rsplit("/", 1)[-1].removesuffix(".exe")
    return {"bash": "shell", "sh": "shell", "pwsh": "powershell", "powershell": "powershell",
            "python": "python", "python3": "python", "node": "javascript"}.get(word)


def _pin_problem(uses: str) -> str | None:
    uses = uses.strip()
    if uses.startswith(("./", "../")) or "${{" in uses:
        return None
    if uses.startswith("docker://"):
        if "@sha256:" in uses:
            return None
        return f"container image {uses[len('docker://'):]} is not pinned by digest"
    if "@" not in uses:
        return f"{uses} has no version"
    name, ref = uses.rsplit("@", 1)
    if FULL_SHA.fullmatch(ref) or name.split("/")[0].lower() in FIRST_PARTY_OWNERS:
        return None
    return f"{name} is referenced by {ref}, which can be moved"


@dataclass
class _Job:
    entry: EntryPoint | None
    label: str
    env: dict[str, str] = field(default_factory=dict)  # variable -> secret ("*" for all)
    shell: str | None = None
    base: Path | None = None


class _File:
    def __init__(self, path: Path, shown: str, text: str, found: Discovery, display,
                 root: Path) -> None:
        self.path, self.shown, self.text, self.found, self.display = (
            path, shown, text, found, display)
        self.positions = Positions(text)
        self.root = root  # where run steps start, for resolving the files they name
        self.events: list[str] = []
        self.action_dir: Path | None = None

    # Helpers ----------------------------------------------------------------------------

    def hit(self, rule_id: str, region: Region, evidence: str, entry: EntryPoint | None,
            via: list[str], level: Level | None = None) -> None:
        self.found.hits.append((self.shown, CodeHit(rule_id, region, clip(evidence), via,
                                                    level=level), entry))

    def span(self, a: yaml.Node, b: yaml.Node | None = None) -> Region:
        return self.positions.region(a.start_mark.index, (b or a).end_mark.index)

    def line_of(self, value: str, index: int) -> str:
        start = value.rfind("\n", 0, index) + 1
        end = value.find("\n", index)
        return value[start:] if end < 0 else value[start:end]

    def substitute(self, value: str) -> tuple[str, dict[str, str]]:
        """The text with each expression replaced by a placeholder, and the placeholders."""
        tokens: dict[str, str] = {}

        def swap(match: re.Match) -> str:
            token = self.found.placeholder(match.group())
            tokens[token] = match.group()
            return token

        return EXPRESSION.sub(swap, value), tokens

    @property
    def privileged(self) -> list[str]:
        return [e for e in self.events if e in PRIVILEGED_EVENTS]

    def env_secrets(self, node: yaml.Node | None, into: dict[str, str]) -> dict[str, str]:
        out = dict(into)
        for name, _, value in y.pairs(node):
            names, every = _secret_refs(y.text(value) or "")
            if every:
                out[name] = "*"
            elif names:
                out[name] = sorted(names)[0]
        return out

    # Rules ------------------------------------------------------------------------------

    def injections(self, value: str, scalar: y.ScalarMap, job: _Job, what: str) -> None:
        for match in EXPRESSION.finditer(value):
            refs = [(m.group(), _classify(m.group())) for m in CONTEXT.finditer(match.group(1))]
            flagged = [(ref, level) for ref, level in refs if level is not None]
            if not flagged:
                continue
            worst = Level.HIGH if any(level is Level.HIGH for _, level in flagged) else (
                Level.REVIEW)
            ref = next(r for r, level in flagged if level is worst)
            why = (f"{ref} can be set by people outside the repository" if worst is Level.HIGH
                   else f"{ref} comes from the event and may be set by its author")
            self.hit("BS-GHA-002", scalar.region(match.start(), match.end()),
                     self.line_of(value, match.start()), job.entry, [what, why],
                     None if worst is Level.HIGH else Level.REVIEW)

    def permissions(self, key: yaml.Node | None, node: yaml.Node | None, entry, where: str
                    ) -> None:
        if node is None or key is None:
            return
        if (y.text(node) or "").strip().lower() == "write-all":
            self.hit("BS-GHA-003", self.span(key, node), "permissions: write-all", entry,
                     [f"{where} grants every permission"])
        for name, k, v in y.pairs(node):
            if name == "id-token" and (y.text(v) or "").strip().lower() == "write":
                self.hit("BS-GHA-004", self.span(k, v), "id-token: write", entry, [where])

    def pin(self, node: yaml.Node | None, entry, where: str) -> None:
        uses = y.text(node)
        problem = _pin_problem(uses) if uses else None
        if problem:
            self.hit("BS-PIN-001", y.region(self.positions, node), f"uses: {uses}", entry,
                     [where, problem])

    def checkout(self, step: yaml.Node, uses: str, job: _Job, label: str) -> None:
        if not self.privileged or uses.split("@")[0].lower() != "actions/checkout":
            return
        for name, k, v in y.pairs(y.get(step, "with")):
            value = y.text(v) or ""
            if name in ("ref", "repository") and PR_HEAD.search(value):
                self.hit("BS-GHA-001", self.span(k, v), f"{name}: {value}", job.entry,
                         [label, f"runs on {', '.join(self.privileged)} and checks out "
                                 "the pull request's code"])

    def run_checkout(self, value: str, scalar: y.ScalarMap, job: _Job, label: str) -> None:
        if not self.privileged:
            return
        match = GH_CHECKOUT.search(value)
        if match is None and PR_HEAD.search(value):
            match = GIT_FETCH.search(value)
        if match:
            self.hit("BS-GHA-001", scalar.region(match.start(), match.end()),
                     self.line_of(value, match.start()), job.entry,
                     [label, f"runs on {', '.join(self.privileged)} and fetches the pull "
                             "request's code"])

    def sends_secrets(self, script: str, tokens: dict[str, str], scalar: y.ScalarMap,
                      env: dict[str, str], job: _Job, label: str) -> None:
        """BS-GHA-006: a bash or sh step that uses secrets and talks to the network."""
        names: set[str] = set()
        every = False
        markers: list[str] = []
        for token, original in tokens.items():
            n, e = _secret_refs(original)
            if n or e:
                markers.append(token)
                names |= n
                every |= e
        used_env = {var: secret for var, secret in env.items()
                    if re.search(rf"\$\{{?{re.escape(var)}\b", script)}
        names |= {s for s in used_env.values() if s != "*"}
        every |= "*" in used_env.values()
        if not names and not every:
            return
        env_pattern = (re.compile(r"\$\{?(?:" + "|".join(map(re.escape, used_env)) + r")\b")
                       if used_env else None)

        def carries(word: str) -> bool:
            return any(m in word for m in markers) or bool(env_pattern and
                                                          env_pattern.search(word))

        commands = network_commands(script)
        whole_env = any(h.rule_id == "BS-ENV-001" for h in analyze_shell(script).hits)
        if not commands:
            return
        sent: list[tuple[NetworkCommand, str]] = []
        for command in commands:
            how = _how_sent(command, carries)
            if how:
                sent.append((command, how))
        if every:
            reason, level = "uses every secret (toJSON(secrets))", None
        elif whole_env:
            reason, level = "collects the whole environment, which holds the secrets", None
        elif sent:
            reason, level = f"puts {', '.join(sorted(names))} in {sent[0][1]}", None
        else:
            reason, level = (f"uses {', '.join(sorted(names))} in the same step as "
                             f"{commands[0].name}", Level.REVIEW)
        command = sent[0][0] if sent else commands[0]
        offset = scalar.offset()
        region = (Region(command.region.line + offset[0], command.region.column + offset[1],
                         command.region.end_line + offset[0],
                         command.region.end_column + offset[1])
                  if offset else y.first_line(self.positions, scalar.node))
        self.hit("BS-GHA-006", region, command.text, job.entry, [label, reason], level)

    # Structure --------------------------------------------------------------------------

    def step(self, step: yaml.Node, number: int, job: _Job, origin: str) -> None:
        name = y.text(y.get(step, "name")) or y.text(y.get(step, "id"))
        uses_node = y.get(step, "uses")
        uses = y.text(uses_node)
        label = (f"step '{name}' in {origin}" if name else
                 f"step {number}{f' ({uses})' if uses else ''} in {origin}")
        if uses:
            self.pin(uses_node, job.entry, label)
            self.checkout(step, uses, job, label)
            if uses.split("@")[0].lower() == "actions/github-script":
                script = y.get(y.get(step, "with"), "script")
                if y.text(script):
                    self.embedded(script, y.key_node(y.get(step, "with"), "script"),
                                  "javascript", job, f"github-script in {label}")
        run = y.get(step, "run")
        if not isinstance(run, yaml.ScalarNode):
            return
        shell = y.text(y.get(step, "shell")) or job.shell
        language = _language(shell)
        env = self.env_secrets(y.get(step, "env"), job.env)
        scalar, script, tokens = self.embedded(run, y.key_node(step, "run"), language, job,
                                               f"run: {label}")
        if language is None:
            self.found.notes.append((self.shown, f"The {shell} script in {label} is not "
                                                 "analysed."))
        self.run_checkout(run.value, scalar, job, label)
        if language == "shell":
            self.sends_secrets(script, tokens, scalar, env, job, label)
        if job.entry is not None and language is not None:
            base = job.base or self.root
            directory = y.text(y.get(step, "working-directory"))
            if directory and "${{" not in directory:
                base = base / directory
            command = EXPRESSION.sub("_BS_", self.paths_resolved(run.value))
            find_targets(self.found, job.entry, command, base, self.display)

    def paths_resolved(self, value: str) -> str:
        """Expressions and variables that name the workspace or the action's directory,
        replaced so that `find_targets` can see the files a step runs."""
        here = "."
        action = str(self.action_dir) if self.action_dir else here
        value = re.sub(r"\$\{\{\s*github\.workspace\s*\}\}|\$\{?GITHUB_WORKSPACE\}?", here, value)
        return re.sub(r"\$\{\{\s*github\.action_path\s*\}\}|\$\{?GITHUB_ACTION_PATH\}?",
                      action.replace("\\", "/"), value)

    def embedded(self, node: yaml.Node, key: yaml.Node | None, language: str | None,
                 job: _Job, origin: str) -> tuple[y.ScalarMap, str, dict[str, str]]:
        """Queue embedded code for analysis, and return where its characters sit and the
        text as parsed, with placeholders for its expressions."""
        scalar = y.ScalarMap.build(self.positions, node)
        self.injections(node.value, scalar, job, origin)
        script, tokens = self.substitute(node.value)
        if language is not None and job.entry is not None:
            self.found.snippets.append((self.shown, Snippet(
                language, script, y.first_line(self.positions, key or node), origin,
                scalar.offset()), job.entry))
        return scalar, script, tokens


def _how_sent(command: NetworkCommand, carries) -> str | None:
    """Where a secret goes in a network command: the body, the URL query or standard input.
    A header, a credential option or a URL that is itself the secret (a webhook) is not
    counted."""
    previous = ""
    for arg in command.args:
        flag = previous
        previous = arg
        if flag in DATA_FLAGS and carries(arg):
            return "a request body"
        if flag in HEADER_FLAGS:
            continue
        for option in DATA_FLAGS:
            if option.startswith("--") and arg.startswith(option + "=") and carries(arg):
                return "a request body"
        if arg.startswith("-d") and len(arg) > 2 and carries(arg):
            return "a request body"
        if "://" in arg and "?" in arg and carries(arg.split("?", 1)[1]):
            return "a URL query"
    if carries(command.stdin):
        return "the data piped into it"
    return None


def _events(node: yaml.Node | None) -> list[str]:
    if isinstance(node, yaml.MappingNode):
        return [name for name, _, _ in y.pairs(node)]
    return y.strings(node)


def _trigger(events: list[str]) -> str:
    if not events:
        return "GitHub Actions (no trigger found)"
    shown = ", ".join(events[:6])
    return f"GitHub Actions {shown}{f' and {len(events) - 6} more' if len(events) > 6 else ''}"


def _windows(runs_on: list[str]) -> bool:
    return any("windows" in label.lower() and "${{" not in label for label in runs_on)


def workflow(path: Path, shown: str, text: str, found: Discovery, display) -> None:
    root_node = _read(shown, text, found, "workflow")
    if root_node is None:
        return
    item = _File(path, shown, text, found, display, path.parent.parent.parent)
    item.events = _events(y.get(root_node, "on"))
    trigger = _trigger(item.events)
    item.permissions(y.key_node(root_node, "permissions"), y.get(root_node, "permissions"),
                     None, "the workflow")
    top_env = item.env_secrets(y.get(root_node, "env"), {})
    top_shell = y.text(y.get(y.get(y.get(root_node, "defaults"), "run"), "shell"))
    missing: list[str] = []
    jobs = y.get(root_node, "jobs")
    for job_id, key, job in y.pairs(jobs):
        runs_on = y.strings(y.get(job, "runs-on")) or y.strings(
            y.get(y.get(job, "runs-on"), "labels"))
        steps = y.items(y.get(job, "steps"))
        uses = y.text(y.get(job, "uses"))
        runs = (f"uses {uses}" if uses else
                f"{len(steps)} step{'s' if len(steps) != 1 else ''} on "
                f"{', '.join(runs_on) or 'an unknown runner'}")
        entry = EntryPoint("github-actions", f"workflow job {job_id}", trigger, shown,
                           y.first_line(item.positions, key), runs)
        found.entry_points.append(entry)
        where = f"job {job_id}"
        if y.get(job, "permissions") is None and y.get(root_node, "permissions") is None:
            missing.append(job_id)
        item.permissions(y.key_node(job, "permissions"), y.get(job, "permissions"), entry,
                         where)
        if any(label.strip().lower() == "self-hosted" for label in runs_on):
            node = y.get(job, "runs-on")
            item.hit("BS-GHA-005", y.region(item.positions, node), f"runs-on: "
                     f"{', '.join(runs_on)}", entry,
                     [where, f"triggered by {', '.join(item.events) or 'unknown events'}"])
        if uses:
            item.pin(y.get(job, "uses"), entry, where)
        shell = (y.text(y.get(y.get(y.get(job, "defaults"), "run"), "shell")) or top_shell
                 or ("pwsh" if _windows(runs_on) else None))
        context = _Job(entry, where, item.env_secrets(y.get(job, "env"), top_env), shell)
        for number, step in enumerate(steps, 1):
            item.step(step, number, context, where)
    if missing and item.events != ["workflow_call"] and jobs is not None:
        item.hit("BS-GHA-003", y.first_line(item.positions, y.key_node(root_node, "jobs")),
                 f"no permissions block for {', '.join(missing)}", None,
                 ["the token gets the repository's default permissions"], Level.INFO)


def action(path: Path, shown: str, text: str, found: Discovery, display) -> None:
    root_node = _read(shown, text, found, "action")
    if root_node is None:
        return
    runs = y.get(root_node, "runs")
    using = (y.text(y.get(runs, "using")) or "").strip().lower()
    if not using:
        return  # not an action definition
    item = _File(path, shown, text, found, display, path.parent)
    item.action_dir = path.parent
    trigger = "any workflow step that uses this action"
    region = y.first_line(item.positions, y.key_node(root_node, "runs"))
    name = y.text(y.get(root_node, "name")) or path.parent.name
    if using == "composite":
        steps = y.items(y.get(runs, "steps"))
        entry = EntryPoint("github-actions", "composite action", trigger, shown, region,
                           f"{name}: {len(steps)} step{'s' if len(steps) != 1 else ''}")
        found.entry_points.append(entry)
        context = _Job(entry, "the action", base=path.parent)
        for number, step in enumerate(steps, 1):
            item.step(step, number, context, "the action")
    elif using.startswith("node"):
        scripts = [(key, y.text(y.get(runs, key))) for key in ("pre", "main", "post")]
        entry = EntryPoint("github-actions", f"JavaScript action ({using})", trigger, shown,
                           region, ", ".join(f"{k}: {v}" for k, v in scripts if v))
        found.entry_points.append(entry)
        # The runner downloads the whole repository, and actions in a subfolder often
        # run code from elsewhere in it (`main: ../lib/index.js`).
        boundary = found.root_of(path) or path.parent
        for _, script in scripts:
            target = target_path(path.parent, script, boundary) if script else None
            if target is not None:
                entry.targets.append(display(target))
                found.targets.append(Target(target, "javascript", entry))
    elif using == "docker":
        image = y.text(y.get(runs, "image")) or ""
        entry = EntryPoint("github-actions", "Docker action", trigger, shown, region, image)
        found.entry_points.append(entry)
        if image.startswith("docker://"):
            item.pin(y.get(runs, "image"), entry, "the action's image")
        found.notes.append((shown, "The action's container image is not analysed."))


def _read(shown: str, text: str, found: Discovery, what: str) -> yaml.Node | None:
    try:
        node = y.compose(text)
    except y.YamlError as exc:
        found.notes.append((shown, f"Not read as a {what}: {exc}. GitHub may still run it."))
        return None
    if not isinstance(node, yaml.MappingNode):
        return None
    return node
